#!/usr/bin/env python3
"""Builds one load-run.sh run's load.json from the raw readings that script's own bash
already took (cgroup cpu.stat/memory.peak at four checkpoints - before_start, window_start,
window_end, process_exit - in KLR_* environment variables) plus the files it wrote to the
run directory (operations.jsonl, web_timing.jsonl, and, for config=events, events.jsonl and
the collector's own observation record).

This script is not meant to be run on its own or imported: it is the glue load-run.sh's
final step invokes, reading its inputs entirely from the KLR_* environment variables that
step exports. The functions doing the actual field-by-field measured/not_measured decisions
(percentiles, cgroup deltas, window classification, event-state classification) live in
load.py, unit-tested there against synthetic inputs; this file only wires load-run.sh's own
environment and on-disk files to them.

Every count and rate here is scoped to the window this run ACTUALLY observed
(KLR_WINDOW_START..KLR_WINDOW_END, the instant the window was really closed): events.jsonl
carries every event the tracer's whole lifetime produced, not just the window's own portion
(the converter's own -window-start/-window-end flags classify boundary remnants; they do
not filter the event stream), so this script filters events by each one's own "ts" field
against the window itself before counting or rating anything.

measurement_complete, which decides whether this run may be compared against another at
all, therefore covers three separate things and not just the cgroup accounting: the
supervision (atomic placement, confirmed termination, removed cgroups), the collector's own
outcome (exit status, whether it attempted every sample the window called for, and whether
any of those attempts actually observed anything), and, for a configuration that runs one,
whether the tracer's attachment was confirmed and whether it was still running at the
window's planned end. A run that fails any of these still reports its load figures - what it
cost is a real measurement - with the reason those figures do not answer the question the
comparison asks.

The window's PLANNED end (KLR_WINDOW_END_PLANNED) and the tracer's own exit time
(KLR_TRACER_EXITED_AT) are kept as their own fields beside it, never folded into one
"window end": a run that stopped early observed a shorter span than it planned to, and both
halves of that fact - what it measured, and what it set out to measure - have to survive
into load.json for the aggregation to be able to tell a comparable run from one that is not.

Usage (as load-run.sh's own last step; not meant to be invoked otherwise):
  python3 experiments/runtime-discovery/tools/load_run_assemble.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import load


def env(name, default=''):
    return os.environ.get(name, default)


def env_bool(name):
    return env(name) == '1'


def read_json_lines_counting_malformed(path):
    """(records, malformed_count) for a JSONL file: every line that fails to parse is
    counted rather than silently skipped, since a converted event log this script cannot
    fully read is not the same thing as a clean, empty one."""
    if not os.path.exists(path):
        return [], 0
    out, malformed = [], 0
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                malformed += 1
    return out, malformed


def read_json_lines(path):
    records, _ = read_json_lines_counting_malformed(path)
    return records


def window_seconds():
    ws, we = load.parse_iso(env('KLR_WINDOW_START')), load.parse_iso(env('KLR_WINDOW_END'))
    if ws is None or we is None or we <= ws:
        return None
    return we - ws


def dir_size_bytes(path):
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def file_size_or_not_measured(path, reason_if_absent):
    if not path or not os.path.exists(path):
        return load.not_measured(reason_if_absent)
    return os.path.getsize(path)


def read_id_file(path):
    if not os.path.exists(path):
        return ''
    return open(path, encoding='utf-8').read().strip()


def read_json_or_none(path):
    if not path or not os.path.exists(path):
        return None
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def planned_sample_count(window_seconds, interval_seconds):
    """How many samples a window of this length at this interval calls for - the same
    integer division the collector itself schedules by, with the same floor of one."""
    try:
        n = int(window_seconds) // int(interval_seconds)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return max(1, n)


def observation_completeness(obs, interval_env, window_env):
    """(reasons, notes, first_sample_delay_s) for the collector's own observation record.

    A run is only a usable measurement if the collector actually did the sampling the window
    called for. Two different things are checked, and kept apart, because they fail for
    different reasons and mean different things:

      - how many of the planned samples were attempted. The collector schedules
        window/interval samples and its LAST one starts one interval before the window
        closes, so a collector that exits shortly before the window's end having taken all
        of them is behaving exactly as designed - that is not an early exit and is not
        reported as one. Fewer samples than planned is: the record says which.
      - how late the FIRST sample actually started against its own scheduled start (which is
        the window's own opening instant). The runner can only measure its own wait; a
        collector still initializing when the window opens produces a late first sample
        against a phase base already in the past, and that is visible only here.
    """
    reasons, notes = [], []
    if obs is None:
        return ['the collector wrote no observation record, so nothing about its sampling can be established'], notes, None
    run_key = obs.get('run_key') or {}
    window_block = obs.get('window') or {}
    samples = window_block.get('samples')
    if not isinstance(samples, list):
        return ['the collector\'s observation record carries no sample timing at all'], notes, None
    planned = planned_sample_count(run_key.get('window_seconds', window_env),
                                   run_key.get('interval_seconds', interval_env))
    attempted = len(samples)
    if planned is None:
        reasons.append('the planned sample count could not be computed from the observation record')
    elif attempted < planned:
        reasons.append(f'the collector attempted {attempted} of the {planned} samples this window '
                       f'called for; it stopped before the last one')
    else:
        notes.append(f'the collector attempted all {planned} planned samples and then exited, '
                     f'which is how a completed window ends')
    if obs.get('inspect_error'):
        reasons.append(f'the collector could not inspect its target: {obs["inspect_error"]}')
    # A sample is recorded whether or not it actually observed anything: a sample that could
    # not list the container's processes is still entered in window.samples, with its own
    # collection_results entry marked invalid. Counting samples therefore says how many
    # times the collector TRIED, not how many times it saw something - and a run in which
    # every attempt failed measured the cost of failing, not the cost of observing.
    results = obs.get('collection_results')
    if not isinstance(results, list) or not results:
        reasons.append('the collector recorded no collection results at all, so no sample is '
                       'known to have observed anything')
    else:
        valid = sum(1 for cr in results if cr.get('valid'))
        notes.append(f'{valid} of {len(results)} collection results are valid')
        if valid == 0:
            failed_kinds = sorted({str(cr.get('proc_observe')) for cr in results if not cr.get('valid')})
            reasons.append('not one of the collector\'s ' + str(len(results)) + ' samples produced a '
                           'valid observation (' + ', '.join(failed_kinds) + '); the load figures below '
                           'are the cost of those failed attempts, not of observing this workload')
    first_delay_s = None
    if samples:
        delay_ms = samples[0].get('delay_ms')
        if isinstance(delay_ms, (int, float)):
            first_delay_s = delay_ms / 1000.0
    return reasons, notes, first_delay_s


def read_int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_int_file_or_none(path):
    if not path or not os.path.exists(path):
        return None
    try:
        return int(open(path).read().strip())
    except (OSError, ValueError):
        return None


def main():
    r = env('KLR_R')
    run_collector = env_bool('KLR_RUN_COLLECTOR')
    run_tracer = env_bool('KLR_RUN_TRACER')
    attached = env_bool('KLR_ATTACHED_OK')
    stopped_early = env_bool('KLR_STOPPED_EARLY')

    out = {
        'run_id': env('KLR_RUN_ID'),
        'case': env('KLR_CASE'),
        'config': env('KLR_CONFIG'),
        'interval': int(env('KLR_INTERVAL')),
        'window': int(env('KLR_WINDOW')),
        'replicate': int(env('KLR_REPLICATE')),
        'sync': 'attach_running',
        'health_url': env('KLR_HEALTH_URL'),
        'container_id': read_id_file(env('KLR_CONTAINER_ID_FILE')),
        'image_id': read_id_file(env('KLR_IMAGE_ID_FILE')),
        'fired_at': env('KLR_FIRED_AT'),
        'window_start_wall': env('KLR_WINDOW_START'),
        'window_end_wall': env('KLR_WINDOW_END'),
        'window_end_planned_wall': env('KLR_WINDOW_END_PLANNED'),
        'tracer_exited_at_wall': env('KLR_TRACER_EXITED_AT') or load.not_measured(
            'the tracer recorded no exit time (no tracer, or its termination was never confirmed)'),
        'window_established': env('KLR_WINDOW_ESTABLISHED') != '0',
        'window_start_drift_s': read_int_or_none(env('KLR_WINDOW_START_DRIFT_S')),
        'stopped_early': stopped_early,
        'stop_reason': env('KLR_STOP_REASON') or ('window_elapsed' if not stopped_early else 'unknown'),
        'dump_logs_ok': env_bool('KLR_DUMP_LOGS_OK'),
    }
    window_s = window_seconds()
    # Reasons this run's own cgroup accounting is incomplete, and notes about facts a
    # reader needs to interpret it - both accumulated as the sections below run, and both
    # carried into load.json rather than only into the run log.
    incomplete_reasons = []
    notes = []
    window_end_epoch = load.parse_iso(out['window_end_wall'])

    # --- collector / tracer cgroup accounting: four checkpoints each - before_start and
    # process_exit come from supervise's own record (the process supervise itself started
    # and stopped), window_start and window_end from load-run.sh's own `cgroup-stat` reads
    # of the same cgroup at the moments the common window opened and closed. All four are
    # the Go-side {"measured","value","reason"} shape (see load.from_measured_json). ---
    def segment_readings(name, supervise_record_path, wstart_path, wend_path, not_running_reason):
        """The four cgroup CPU segments and the memory peak for one supervised target, plus
        whatever this target contributes to the run's own completeness: a fallback (non-
        atomic) cgroup placement leaves the child's startup outside these counters, and an
        unconfirmed termination leaves a process that may still be adding to them - neither
        is a usable load measurement, so both are recorded as an explicit incompleteness
        rather than silently averaged in with proper ones."""
        sup = read_json_or_none(supervise_record_path)
        wstart = read_json_or_none(wstart_path)
        wend = read_json_or_none(wend_path)
        if sup is None:
            missing = not_running_reason or f'supervise record {supervise_record_path} not found'
            incomplete_reasons.append(f'{name}: {missing}')
            n = load.not_measured(missing)
            return n, n, n, n, load.not_measured(missing)
        placement = sup.get('placement_atomic') or {}
        if placement.get('measured') and not placement.get('value'):
            incomplete_reasons.append(
                f'{name} was placed in its cgroup only after exec (cgroup_method='
                f'{sup.get("cgroup_method")}): its own startup CPU and initial memory are '
                f'outside these counters')
        elif not placement.get('measured'):
            incomplete_reasons.append(
                f'{name}: whether it was placed in its cgroup atomically is not recorded '
                f'({placement.get("reason") or "no placement_atomic field"})')
        termination = sup.get('termination_confirmed') or {}
        if not termination.get('measured') or not termination.get('value'):
            incomplete_reasons.append(
                f'{name}: termination was not confirmed ({termination.get("reason") or "no termination_confirmed field"})')
        exited = load.parse_iso(sup.get('exited_at_wall'))
        if exited is not None and window_end_epoch is not None and exited < window_end_epoch:
            notes.append(
                f'{name} exited at {sup.get("exited_at_wall")}, before the window closed at '
                f'{out["window_end_wall"]}; its cgroup was kept until the window-end reading '
                f'was taken, so that reading is its own final counter rather than a substitute')
        before = load.from_measured_json(sup.get('baseline_cpu_usage_usec'), 'supervise record missing baseline_cpu_usage_usec')
        after = load.from_measured_json(sup.get('final_cpu_usage_usec'), 'supervise record missing final_cpu_usage_usec')
        ws = load.from_measured_json((wstart or {}).get('cpu_usage_usec'), f'{wstart_path} not found or unreadable')
        we = load.from_measured_json((wend or {}).get('cpu_usage_usec'), f'{wend_path} not found or unreadable')
        prep = load.delta_measured(before, ws)
        window = load.delta_measured(ws, we)
        drain = load.delta_measured(we, after)
        total = load.delta_measured(before, after)
        mem = load.from_measured_json(sup.get('final_memory_peak_bytes'), 'supervise record missing final_memory_peak_bytes')
        out[f'{name}_cgroup_method'] = sup.get('cgroup_method')
        out[f'{name}_placement_atomic'] = load.from_measured_json(placement or None, 'no placement_atomic field in the supervise record')
        out[f'{name}_termination_confirmed'] = load.from_measured_json(termination or None, 'no termination_confirmed field in the supervise record')
        out[f'{name}_exited_at_wall'] = sup.get('exited_at_wall') or load.not_measured('no exit time was recorded')
        out[f'{name}_status'] = sup.get('status')
        code = sup.get('exit_code')
        out[f'{name}_exit_code'] = code if isinstance(code, int) else load.not_measured(
            'no exit code was recorded for this child')
        return prep, window, drain, total, mem

    if run_collector:
        out['collector_cgroup_path'] = env('KLR_COLLECTOR_CGROUP')
        prep, window, drain, total, mem = segment_readings(
            'collector', env('KLR_COLLECTOR_RECORD'), env('KLR_CGROUP_COLLECTOR_WSTART'), env('KLR_CGROUP_COLLECTOR_WEND'), None)
        out['collector_cpu_usage_delta_prep_us'] = prep
        out['collector_cpu_usage_delta_window_us'] = window
        out['collector_cpu_usage_delta_drain_us'] = drain
        out['collector_cpu_usage_delta_total_us'] = total
        out['collector_memory_peak_bytes'] = mem
    else:
        reason = 'config=none starts no collector'
        out['collector_cgroup_path'] = None
        for f in ('prep', 'window', 'drain', 'total'):
            out[f'collector_cpu_usage_delta_{f}_us'] = load.not_measured(reason)
        out['collector_memory_peak_bytes'] = load.not_measured(reason)

    if run_tracer:
        out['tracer_cgroup_path'] = env('KLR_TRACER_CGROUP')
        prep, window, drain, total, mem = segment_readings(
            'tracer', env('KLR_TRACER_RECORD'), env('KLR_CGROUP_TRACER_WSTART'), env('KLR_CGROUP_TRACER_WEND'), None)
        out['tracer_cpu_usage_delta_prep_us'] = prep
        out['tracer_cpu_usage_delta_window_us'] = window
        out['tracer_cpu_usage_delta_drain_us'] = drain
        out['tracer_cpu_usage_delta_total_us'] = total
        out['tracer_memory_peak_bytes'] = mem
    else:
        reason = 'this config starts no tracer'
        out['tracer_cgroup_path'] = None
        for f in ('prep', 'window', 'drain', 'total'):
            out[f'tracer_cpu_usage_delta_{f}_us'] = load.not_measured(reason)
        out['tracer_memory_peak_bytes'] = load.not_measured(reason)

    # --- docker daemon cgroup: always read directly by load-run.sh itself via `cgroup-stat`,
    # at the same window_start/window_end checkpoints every other window-scoped metric uses -
    # never sourced from the collector's own report, so config=none, procfs and events all
    # read this the same way and stay comparable. ---
    docker_wstart = read_json_or_none(env('KLR_CGROUP_DOCKER_WSTART'))
    docker_wend = read_json_or_none(env('KLR_CGROUP_DOCKER_WEND'))
    docker_ws = load.from_measured_json((docker_wstart or {}).get('cpu_usage_usec'), 'docker daemon cgroup-stat (window start) not found or unreadable')
    docker_we = load.from_measured_json((docker_wend or {}).get('cpu_usage_usec'), 'docker daemon cgroup-stat (window end) not found or unreadable')
    out['docker_daemon_cpu_usage_delta_window_us'] = load.delta_measured(docker_ws, docker_we)

    # --- events, drops, event_state: header/trailer validated, malformed lines counted,
    # and every count/rate scoped to the common window by each event's own "ts". ---
    events_path = env('KLR_EVENTS_JSONL')
    if run_tracer and events_path and os.path.exists(events_path):
        events, malformed = read_json_lines_counting_malformed(events_path)
        header = events[0] if events and events[0].get('record') == 'events_header' else None
        trailer = events[-1] if events and events[-1].get('record') == 'events_trailer' else None
        # A missing trailer means conversion never finished (crashed, was killed, or the
        # input was truncated): every drop/partial/unmeasured figure that would otherwise
        # come from it is unknown, not zero - reporting 0 here would be an unearned claim
        # that nothing was lost, exactly the mistake REFERENCE.md's own "an unmeasured
        # category is not a measured zero" rule exists to rule out.
        trailer_reason = 'events.jsonl has no events_trailer record; conversion did not complete'
        drops_raw = trailer.get('drops', {}) if trailer else None
        cid = out['container_id']

        window_start_iso, window_end_iso = out['window_start_wall'], out['window_end_wall']

        def in_window(rec):
            # Each event is a single instant, not an interval; passing its own "ts" as
            # both ends of classify_window's [start,end] reduces its "fully inside the
            # window" rule to exactly the point-in-window test this needs, including its
            # unparseable-timestamp handling (an event whose own "ts" this cannot parse is
            # never silently counted as in-window).
            return load.classify_window(rec.get('ts'), rec.get('ts'), window_start_iso, window_end_iso) == 'within'

        all_events = [e for e in events if e.get('record') == 'event']
        windowed_events = [e for e in all_events if in_window(e)]
        attributed = [e for e in windowed_events if e.get('container_id') == cid]

        out['events_total'] = len(windowed_events)
        out['events_total_per_second'] = load.rate(len(windowed_events), window_s) if window_s else load.not_measured(
            'window duration could not be computed')
        out['events_attributed'] = len(attributed)
        out['events_attributed_per_second'] = load.rate(len(attributed), window_s) if window_s else load.not_measured(
            'window duration could not be computed')
        out['events_outside_window'] = len(all_events) - len(windowed_events)
        out['malformed_lines'] = malformed
        if drops_raw is None:
            out['drops'] = {f: load.not_measured(trailer_reason) for f in load.DROP_FIELDS}
            # Malformed lines are still a real, counted fact about this conversion even
            # without a trailer to fold them into; convert_failures itself is separately
            # not_measured (the trailer that would have carried it is missing), so a
            # malformed-line count is kept here as its own field rather than silently lost.
            out['drops']['convert_failures'] = malformed if malformed else load.not_measured(trailer_reason)
            out['partial_events'] = load.not_measured(trailer_reason)
            out['unmeasured'] = [trailer_reason]
        else:
            # Malformed lines in the CONVERTED output are, like any other conversion
            # failure the trailer's own convert_failures already counts, added to that same
            # total rather than kept as a disjoint figure a reader would have to remember to
            # also check - matching how existing readers of this format already treat a
            # convert_failures count as the single place conversion problems accumulate.
            merged_convert_failures = drops_raw.get('convert_failures', 0) + malformed
            drops = dict(drops_raw)
            drops['convert_failures'] = merged_convert_failures
            out['drops'] = {f: drops.get(f, 0) for f in load.DROP_FIELDS}
            out['partial_events'] = load.partial_events_from_drops(drops)
            out['unmeasured'] = drops.get('unmeasured', [])
        drops_for_state = drops_raw if drops_raw is not None else {}
        out['event_state'] = load.event_state_from_conversion(
            run_tracer, header, trailer, malformed, drops_for_state, runner_stopped_early=stopped_early)
    else:
        reason = 'this config starts no tracer' if not run_tracer else 'events.jsonl is missing (conversion did not run or failed)'
        for f in ('events_total', 'events_total_per_second', 'events_attributed', 'events_attributed_per_second',
                  'events_outside_window', 'malformed_lines', 'partial_events'):
            out[f] = load.not_measured(reason)
        out['drops'] = {f: load.not_measured(reason) for f in load.DROP_FIELDS}
        out['unmeasured'] = [reason]
        out['event_state'] = load.event_state_from_conversion(
            run_tracer, None, None, 0, {}, runner_stopped_early=stopped_early)

    # --- trace output size (whole-lifetime totals) and rate (window-scoped, from the byte
    # counts load-run.sh itself took at the window's own start and end - never the whole
    # file's size divided by the window's own duration, which also carries the file's
    # pre-window prep and post-window drain output and would overstate the rate more the
    # shorter an early-stopped window was). ---
    if run_tracer:
        stdout_bytes = file_size_or_not_measured(f'{r}/trace.txt', 'trace.txt is missing')
        stderr_bytes = file_size_or_not_measured(f'{r}/trace.err', 'trace.err is missing')
        out['trace_stdout_bytes'] = stdout_bytes
        out['trace_stderr_bytes'] = stderr_bytes

        def window_rate(wstart_path, wend_path, whole_reason):
            ws = read_int_file_or_none(wstart_path)
            we = read_int_file_or_none(wend_path)
            if ws is None or we is None:
                return load.not_measured(f'{whole_reason}: byte count at window start/end was not recorded')
            delta = load.delta_measured(ws, we)
            return load.rate(delta, window_s) if window_s else load.not_measured('window duration could not be computed')

        out['trace_stdout_bytes_per_second'] = window_rate(env('KLR_TRACE_STDOUT_WSTART'), env('KLR_TRACE_STDOUT_WEND'), 'stdout')
        out['trace_stderr_bytes_per_second'] = window_rate(env('KLR_TRACE_STDERR_WSTART'), env('KLR_TRACE_STDERR_WEND'), 'stderr')
        # Whole-lifetime rate kept as its own, separately-labeled field: useful context, but
        # never confused with the window-scoped rate above by sharing its name.
        whole_lifetime_s = None
        sup = read_json_or_none(env('KLR_TRACER_RECORD'))
        if sup is not None and isinstance(sup.get('exited_at_monotonic_s'), (int, float)):
            whole_lifetime_s = sup['exited_at_monotonic_s']
        out['trace_stdout_bytes_per_second_whole_lifetime'] = (
            load.rate(stdout_bytes, whole_lifetime_s) if whole_lifetime_s and not load.is_not_measured(stdout_bytes)
            else load.not_measured('tracer whole-lifetime duration could not be computed'))
        out['trace_stderr_bytes_per_second_whole_lifetime'] = (
            load.rate(stderr_bytes, whole_lifetime_s) if whole_lifetime_s and not load.is_not_measured(stderr_bytes)
            else load.not_measured('tracer whole-lifetime duration could not be computed'))
    else:
        reason = 'this config starts no tracer'
        out['trace_stdout_bytes'] = load.not_measured(reason)
        out['trace_stderr_bytes'] = load.not_measured(reason)
        out['trace_stdout_bytes_per_second'] = load.not_measured(reason)
        out['trace_stderr_bytes_per_second'] = load.not_measured(reason)
        out['trace_stdout_bytes_per_second_whole_lifetime'] = load.not_measured(reason)
        out['trace_stderr_bytes_per_second_whole_lifetime'] = load.not_measured(reason)
    out['run_dir_growth_bytes'] = dir_size_bytes(r)  # the run directory started empty (rm -rf + mkdir -p)

    # --- workload timing: the operational loop's own curl/git/openssl instances (scoped to
    # the common window; see load.workload_stats_from_operations), and the host-side web
    # request loop (already window-scoped by its own fixed schedule). ---
    operations = read_json_lines(f'{r}/gtb-raw/operations.jsonl')
    workload = load.workload_stats_from_operations(operations, out['window_start_wall'], out['window_end_wall'])
    workload['web'] = load.web_stats_from_timing(read_json_lines(f'{r}/web_timing.jsonl'))
    out['workload'] = workload

    # --- watch-run.sh's own summary (it always runs, for every config, from before the
    # tracer/collector exist) ---
    watch_samples = read_json_lines(f'{r}/watch.jsonl')
    out['watch_samples'] = len(watch_samples)
    out['watch_stop_reason'] = env('KLR_STOP_REASON') or None

    # --- cgroup removal: each child cgroup and then their parent, as the runner's own
    # cgroup-remove calls recorded them. A cgroup that could not be removed is a stated
    # fact with its own reason here, not an unexplained leftover under /sys/fs/cgroup. ---
    cleanup = {}
    for label in ('tracer', 'collector', 'parent'):
        rec = read_json_or_none(f'{r}/cgroup-remove-{label}.json')
        if rec is None:
            continue
        cleanup[label] = {'path': rec.get('path'),
                          'removed': load.from_measured_json(rec.get('removed'), 'no removed field'),
                          'populated': load.from_measured_json(rec.get('populated'), 'no populated field')}
        removed = cleanup[label]['removed']
        if load.is_not_measured(removed) or removed is not True:
            incomplete_reasons.append(
                f'the {label} cgroup at {rec.get("path")} was not removed: '
                f'{(rec.get("removed") or {}).get("reason") or "no reason recorded"}')
    out['cgroup_cleanup'] = cleanup

    # --- stop failures the runner could not resolve through its own bounded stop path ---
    stop_failures = []
    sf_path = env('KLR_STOP_FAILURES_FILE')
    if sf_path and os.path.exists(sf_path):
        stop_failures = [line.strip() for line in open(sf_path, encoding='utf-8') if line.strip()]
    out['stop_failures'] = stop_failures
    incomplete_reasons.extend(stop_failures)

    # --- did this run actually OBSERVE what it set out to? Atomic cgroup placement and a
    # confirmed termination say the load figures are trustworthy; they say nothing about
    # whether the collector did its job. A collector that exited non-zero before the window
    # even opened leaves a cgroup reading that is perfectly well measured and completely
    # uninformative, and a config=events run whose tracer never attached collected no events
    # at all - neither is a measurement another run can be compared against. ---
    if run_collector:
        collector_exit = out.get('collector_exit_code')
        if load.is_not_measured(collector_exit):
            incomplete_reasons.append(f'collector: {load.not_measured_reason(collector_exit)}')
        elif collector_exit != 0:
            incomplete_reasons.append(f'the collector exited {collector_exit}, so its own sampling did not complete')
        obs = read_json_or_none(env('KLR_OBS'))
        obs_reasons, obs_notes, first_delay_s = observation_completeness(
            obs, out['interval'], out['window'])
        incomplete_reasons.extend(obs_reasons)
        notes.extend(obs_notes)
        out['collector_first_sample_delay_s'] = (
            first_delay_s if first_delay_s is not None
            else load.not_measured('the collector recorded no first-sample timing'))
        results = ((obs or {}).get('collection_results') or []) if obs is not None else []
        if obs is None or not isinstance(results, list) or not results:
            out['collector_valid_samples'] = load.not_measured(
                'the collector recorded no collection results')
            out['collector_invalid_samples'] = load.not_measured(
                'the collector recorded no collection results')
        else:
            out['collector_valid_samples'] = sum(1 for cr in results if cr.get('valid'))
            out['collector_invalid_samples'] = sum(1 for cr in results if not cr.get('valid'))
        # The runner can only time its own wait for the window to open. Whether the
        # COLLECTOR was ready by then is a separate fact, and this is where it is measured:
        # its first sample's own delay against the scheduled start that is the window's own
        # opening instant.
        tolerance = read_int_or_none(env('KLR_WINDOW_START_TOLERANCE_S'))
        if tolerance is not None and first_delay_s is not None and first_delay_s > tolerance:
            out['window_established'] = False
            notes.append(f'the collector took its first sample {first_delay_s:.3f}s after the window '
                         f'opened (tolerance {tolerance}s): its sampling started against a phase base '
                         f'already in the past, so this run is excluded from comparisons')
    else:
        out['collector_first_sample_delay_s'] = load.not_measured('config=none starts no collector')

    if run_tracer:
        if not attached:
            incomplete_reasons.append(
                'the tracer\'s attachment was never confirmed, so this configuration was not established')
        elif out['event_state'] == 'failed':
            incomplete_reasons.append(
                f'event collection is in state {out["event_state"]}, so this configuration collected no usable events')
        # Whether the tracer was RUNNING for the whole window is a different question from
        # how much it lost while it ran. A tracer that died ten seconds into a five-minute
        # window loses no events for the remaining 290 seconds - it simply was not there -
        # and every per-second figure computed over the window would read as if it had been.
        # This is recorded under its own name so it is never confused with the degradation a
        # drop counter causes.
        tracer_exit = load.parse_iso(env('KLR_TRACER_EXITED_AT'))
        planned_end = load.parse_iso(out['window_end_planned_wall'])
        if tracer_exit is None:
            incomplete_reasons.append(
                'tracer_exit_time_unknown: the tracer recorded no exit time, so whether it was '
                'running for the whole window cannot be established')
        elif planned_end is not None and tracer_exit < planned_end:
            incomplete_reasons.append(
                f'tracer_exited_before_window_end: the tracer exited at {env("KLR_TRACER_EXITED_AT")}, '
                f'{planned_end - tracer_exit:.1f}s before the planned end of the window '
                f'({out["window_end_planned_wall"]}), so it was not observing for all of it')

    if not out['window_established']:
        drift = out['window_start_drift_s']
        notes.append(f'the window opened {drift}s after it was planned to '
                     f'(tolerance exceeded); this run is excluded from comparisons')
    out['measurement_complete'] = not incomplete_reasons
    out['measurement_incomplete_reasons'] = incomplete_reasons
    out['notes'] = notes

    json.dump(out, open(f'{r}/load.json', 'w'), indent=1, sort_keys=True)
    print(f'{r}/load.json written: config={out["config"]} stopped_early={out["stopped_early"]} '
          f'window_established={out["window_established"]} measurement_complete={out["measurement_complete"]} '
          f'event_state={out["event_state"]} events_total={out["events_total"]} watch_samples={out["watch_samples"]}')


if __name__ == '__main__':
    main()
