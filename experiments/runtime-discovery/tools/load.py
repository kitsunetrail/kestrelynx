#!/usr/bin/env python3
"""Pure helpers for building and aggregating load-run.sh's own load.json, plus the
aggregator itself.

load_run_assemble.py (invoked by load-run.sh once a run finishes) imports the functions
below to turn that one run's raw cgroup/event/workload readings into load.json. This file's
own __main__ instead aggregates every already-written load.json under an output directory
into AGGREGATE-load.md/.csv - one row per run, plus each run's own difference against the
matching config=none run of the same case/interval/window/replicate block, since a load
number only means something next to a run that measured the same workload with nothing
watching it. That difference is only computed when the two runs really are comparable -
both ran the planned window out from when it was planned to open, over the same image, with
complete cgroup accounting; otherwise it is reported as not_measured naming exactly which
of those did not hold (see comparison_blocker).

Every field that could not be measured is either the exact string "not_measured: <reason>"
(inside load.json - see NOT_MEASURED_PREFIX below) or, once it has passed through here,
"n/a (<reason>)" in the aggregated tables. Neither is ever a bare 0 standing in for
something this run never actually read.

All counts and durations here are scoped to one common observation window (a fixed start
and a fixed end, the same span for every configuration of a given case/interval/window
block) rather than to a container's or a tracer's own full lifetime: an event or operation
that falls partly or fully outside that window is excluded from the totals and reported
separately (see classify_window / operations_in_window), so config=none, config=procfs and
config=events are always compared over exactly the same span of time.

Usage (from the repository root):
  python3 experiments/runtime-discovery/tools/load.py [out dir]   (default: experiments/runtime-discovery/out)
Writes: <out dir>/AGGREGATE-load.md and <out dir>/AGGREGATE-load.csv
Unit tests (from the repository root):
  python3 -m unittest discover -s experiments/runtime-discovery/tools -p 'load_test.py'
  python3 experiments/runtime-discovery/tools/load_test.py
"""
import csv
import glob
import json
import math
import os
import re
import sys
from datetime import datetime

NOT_MEASURED_PREFIX = 'not_measured: '

RUN_DIR_RE = re.compile(r'^(26|27|28)-load-(none|procfs|events)-(\d+)-(\d+)-r(\d+)-attach_running$')

OPERATION_KINDS = ('curl', 'git', 'openssl')

# The EventDropCounts fields this module carries through in full (see REFERENCE.md's own
# "Observation states" and "CSV files" sections for what each one means) - kept as the
# complete set rather than the two or three a caller happens to need today, so a table built
# from load.json can always answer "what kind of loss" without going back to raw events.jsonl.
DROP_FIELDS = (
    'lost_events', 'lost_notifications', 'map_overflow', 'convert_failures',
    'enter_exit_unmatched', 'enter_exit_unmatched_boundary',
    'path_read_failures', 'path_truncations',
    'identity_unavailable', 'unmatched_identity_unavailable',
    'events_before_filter', 'events_after_filter',
)


def not_measured(reason):
    """The exact sentinel load.json uses for a field this run could not read: a string,
    never a number, so it can never be mistaken for a measured zero."""
    return f'{NOT_MEASURED_PREFIX}{reason}'


def is_not_measured(value):
    return isinstance(value, str) and value.startswith(NOT_MEASURED_PREFIX)


def not_measured_reason(value):
    """The reason text of a not_measured(...) value, or None when the value is measured."""
    return value[len(NOT_MEASURED_PREFIX):] if is_not_measured(value) else None


def measured_or(value, ok, reason):
    """value when ok is true, else the not_measured(...) sentinel carrying reason. The one
    place this module decides whether a reading counts as measured, so every caller goes
    through the same rule rather than each inventing its own truthiness check."""
    return value if ok else not_measured(reason)


def cgroup_cpu_delta_us(before, after):
    """The cpu.stat usage_usec delta between two readings taken as strings (as a shell
    variable holds them, empty when the file could not be read at all), or not_measured
    when either side is missing. Never returns a negative delta: a cgroup's own usage_usec
    is monotonically non-decreasing over its lifetime, so a negative result means the two
    readings were not of the same cgroup lifetime, which is reported rather than shown as
    a small negative number no reader would trust anyway.
    """
    if not before or not after:
        return not_measured('cpu.stat usage_usec was not read both before and after')
    delta_us = int(after) - int(before)
    if delta_us < 0:
        return not_measured(f'usage_usec decreased ({before} -> {after}); not the same cgroup lifetime')
    return delta_us


def cgroup_memory_peak_bytes(ok, peak):
    if not ok:
        return not_measured('memory.peak was not read (missing controller, missing file, or kernel too old)')
    return int(peak)


def from_measured_json(d, missing_reason):
    """Converts a Go-side {"measured": bool, "value": ..., "reason": "..."} dict - the JSON
    shape supervise's own record and cgroup-stat's own output both use for every reading
    that can independently succeed or fail (MeasuredInt64/MeasuredBool in supervise.go) -
    into this module's own not_measured(...) sentinel convention. d=None (the file itself
    could not be read or parsed at all, as opposed to one field inside it) uses
    missing_reason instead of a per-field one.
    """
    if d is None:
        return not_measured(missing_reason)
    if not d.get('measured'):
        return not_measured(d.get('reason') or 'not measured')
    return d.get('value')


def delta_measured(before, after):
    """after-before when both are plain numbers, else not_measured naming which side and
    why. The same rule cgroup_cpu_delta_us applies to raw shell-string readings, generalized
    to values already resolved through from_measured_json (a supervise.json/cgroup-stat.json
    reading) rather than empty-string-means-missing shell variables - never a negative
    delta, which would mean the two readings were not of the same measurement lifetime.
    """
    if is_not_measured(before):
        return not_measured(f'before: {not_measured_reason(before)}')
    if is_not_measured(after):
        return not_measured(f'after: {not_measured_reason(after)}')
    if before is None or after is None:
        return not_measured('one or both readings are missing')
    d = after - before
    if d < 0:
        return not_measured(f'value decreased ({before} -> {after}); not the same measurement lifetime')
    return d


def percentile(sorted_values, p):
    """The nearest-rank percentile of an already-sorted, non-empty sequence. p=0.5 is the
    median, p=0.95 the p95. Never interpolates between two values: a distribution built
    from a handful of curl/git/openssl instances per run does not have enough samples for
    interpolation to mean anything more than nearest-rank already does."""
    n = len(sorted_values)
    k = max(0, min(n - 1, math.ceil(p * n) - 1))
    return sorted_values[k]


def duration_stats(durations_ms, failures, no_data_reason):
    """{"n", "median_ms", "p95_ms", "max_ms", "failures"} from a list of successful
    instances' own duration_ms plus a separate failure count, or a single not_measured
    field when there were no instances of this kind at all (never a stats block with zero
    n standing in for "this run recorded none of these")."""
    n = len(durations_ms) + failures
    if n == 0:
        return {'n': 0, 'state': not_measured(no_data_reason)}
    if not durations_ms:
        return {'n': n, 'median_ms': not_measured('every instance failed; no successful duration to summarize'),
                'p95_ms': not_measured('every instance failed; no successful duration to summarize'),
                'max_ms': not_measured('every instance failed; no successful duration to summarize'),
                'failures': failures}
    s = sorted(durations_ms)
    return {'n': n, 'median_ms': percentile(s, 0.5), 'p95_ms': percentile(s, 0.95), 'max_ms': s[-1], 'failures': failures}


def parse_iso(s):
    """Parses this harness's own timestamp shape (RFC3339 UTC, "Z"-suffixed, a fractional
    second of any length) into an aware-enough, purely relative form: returns a float epoch
    seconds, or None for an empty/unparseable value, so a caller can compare instants
    without ever raising on a field this run left unset.
    """
    if not s:
        return None
    s = s.strip()
    if not s.endswith('Z'):
        return None
    body = s[:-1]
    if '.' in body:
        head, frac = body.split('.', 1)
        body = f'{head}.{frac[:6]:0<6}'
    try:
        return datetime.fromisoformat(body + '+00:00').timestamp()
    except ValueError:
        return None


def classify_window(start_iso, end_iso, window_start_iso, window_end_iso):
    """"within" when [start,end] both parse and fall entirely inside [window_start,
    window_end]; "boundary_crossing" when they parse but only partly overlap it (or spill
    past either edge); "unknown" when start/end or the window bounds themselves could not
    be parsed at all - never silently folded into "within", which would let an operation
    load-run.sh does not actually know the timing of masquerade as in-window evidence.
    """
    ws, we = parse_iso(window_start_iso), parse_iso(window_end_iso)
    s, e = parse_iso(start_iso), parse_iso(end_iso)
    if ws is None or we is None or s is None or e is None:
        return 'unknown'
    if s >= ws and e <= we:
        return 'within'
    if e < ws or s > we:
        return 'outside'
    return 'boundary_crossing'


def workload_stats_from_operations(records, window_start_iso=None, window_end_iso=None):
    """{"curl": {...}, "git": {...}, "openssl": {...}} from operations.jsonl's own parsed
    records (each a dict with at least "op"; "ts"/"end_ts"/"duration_ms"/"exit_code" when
    load-run.sh's own os-ops.sh fixture wrote them).

    When window_start_iso/window_end_iso are given, only instances classified "within" that
    window (see classify_window, using each record's own "ts" as start and "end_ts" as end)
    contribute to n/median/p95/max/failures; "boundary_crossing" and "unknown" instances are
    counted separately per kind and never merged into the main statistics, since an
    operation that only partly overlaps the window is not evidence of what happened inside
    it. Without window bounds (the default), every matching instance is used - the shape
    older callers and tests relied on before window scoping existed.

    An older operations.jsonl with no duration_ms/exit_code at all (predating that
    addition) reports every kind as not_measured rather than as zero instances, since the
    operations plainly did happen - this run's own log simply does not carry their timing.
    """
    out = {}
    saw_any_timing = any('duration_ms' in r for r in records)
    windowed = window_start_iso is not None and window_end_iso is not None
    for kind in OPERATION_KINDS:
        prefix = f'osops_{kind}'
        matching = [r for r in records if r.get('op') == prefix]
        if not matching:
            out[kind] = {'n': 0, 'state': not_measured(f'no {prefix} operations recorded in operations.jsonl'),
                         'boundary_crossing': 0, 'outside_window': 0}
            continue
        if not saw_any_timing:
            out[kind] = {'n': len(matching), 'state': not_measured(
                'operations.jsonl predates per-instance duration_ms/exit_code'),
                'boundary_crossing': 0, 'outside_window': 0}
            continue
        boundary = 0
        outside = 0
        in_window = matching
        if windowed:
            in_window = []
            for r in matching:
                cls = classify_window(r.get('ts'), r.get('end_ts'), window_start_iso, window_end_iso)
                if cls == 'within':
                    in_window.append(r)
                elif cls == 'boundary_crossing':
                    boundary += 1
                elif cls == 'outside':
                    outside += 1
                else:
                    boundary += 1  # "unknown" (unparseable): not claimed as in-window evidence either
        durations, failures = [], 0
        for r in in_window:
            ok = bool(r.get('ok', True)) and r.get('exit_code', 0) == 0
            if ok and isinstance(r.get('duration_ms'), (int, float)):
                durations.append(float(r['duration_ms']))
            else:
                failures += 1
        stats = duration_stats(durations, failures, f'no {prefix} instances recorded inside the observation window')
        stats['boundary_crossing'] = boundary
        stats['outside_window'] = outside
        out[kind] = stats
    return out


def web_stats_from_timing(records):
    """The same {"n", "median_ms", ...} shape as workload_stats_from_operations, plus
    "failure_breakdown" splitting every non-"ok" response into "timeout" (web_timing.jsonl's
    own "timeout_type" not "none") and "failure" (a real curl exit without a timeout, e.g. a
    connection reset or a non-2xx/3xx HTTP status) - never merged into one undifferentiated
    "failures" count, which cannot tell a service that is refusing connections from one that
    is simply too slow to answer inside curl's own timeout. Built from web_timing.jsonl's
    own parsed records (each a dict with "ok" and, on success, "latency_ms"; "timeout_type"
    when load-run.sh's own fixed schedule wrote it). Every probe load-run.sh's own web loop
    issues is already scoped to the common observation window by construction (its planned
    schedule never runs past the window's own end), so no separate window filter is applied
    here. A request the loop's own curl could not even complete (connection refused,
    timeout) has "latency_ms": null and counts as a failure or timeout, never as a
    zero-length success."""
    if not records:
        return {'n': 0, 'state': not_measured('no web_timing.jsonl records for this run')}
    durations, failures = [], 0
    timeouts, real_failures = 0, 0
    for r in records:
        if r.get('ok') and isinstance(r.get('latency_ms'), (int, float)):
            durations.append(float(r['latency_ms']))
            continue
        failures += 1
        # Only "operation_timeout" (curl's own --max-time/--connect-timeout expiring) is a
        # timeout; "connection_failed", "resolve_failed", "empty_reply" and any other curl
        # exit are a real (non-timeout) failure - a service refusing connections outright is
        # a materially different fact from one that is merely too slow to answer.
        if r.get('timeout_type') == 'operation_timeout':
            timeouts += 1
        else:
            real_failures += 1
    stats = duration_stats(durations, failures, 'no web requests recorded')
    stats['success_count'] = len(durations)
    stats['timeout_count'] = timeouts
    stats['failure_count'] = real_failures
    return stats


def partial_events_from_drops(drops):
    """REFERENCE.md's own partial_events total: path_read_failures + path_truncations +
    enter_exit_unmatched_boundary + identity_unavailable. These do not change the
    collection's own event_state (see event_state_from_conversion) but are never omitted
    from load.json either - a caller building the load/overhead results table needs them
    to tell a run with real, if incomplete, evidence from one with none at all.
    """
    return (drops.get('path_read_failures', 0) + drops.get('path_truncations', 0)
            + drops.get('enter_exit_unmatched_boundary', 0) + drops.get('identity_unavailable', 0))


def event_state_from_conversion(run_tracer, header, trailer, malformed_lines, drops, runner_stopped_early=False):
    """Replicates this experiment's own public event-state rule (not_attempted / failed /
    observed / degraded), now from the converted log's own header/trailer rather than from
    drop counters alone: not_attempted when no tracer was even configured; failed when no
    header could be read at all, or the header itself says the tracer never started or its
    attachment was never confirmed; degraded when the header/attachment are fine but the
    trailer is missing entirely (conversion did not complete), or when malformed lines were
    found, or when the trailer's own drops report loss, unmatched halves, conversion
    failures, an early stop, or any unmeasured category; observed only once a trailer is
    actually present and none of that degraded it.

    header/trailer are the parsed events_header/events_trailer records (or None when
    missing or unparseable) - reading them directly, rather than trusting a bash-side
    "did attach-check succeed" flag alone, is what lets this catch a tracer that this run's
    own attach-check believed was attached but the converted log itself never confirms.

    runner_stopped_early is the RUNNER's own fact: the observation window was closed before
    its planned end (a watchdog threshold, an operator stop). It degrades the state on its
    own, without waiting for the converter to agree: the converter only sees a short window
    when the tracer's own exit time reached it, and a run whose window was cut short did not
    collect what it set out to collect either way.
    """
    if not run_tracer:
        return 'not_attempted'
    if header is None or not header.get('started') or not header.get('attached'):
        return 'failed'
    if trailer is None:
        return 'degraded'
    if malformed_lines:
        return 'degraded'
    if runner_stopped_early:
        return 'degraded'
    degraded = (
        drops.get('lost_events', 0) > 0
        or drops.get('lost_notifications', 0) > 0
        or drops.get('convert_failures', 0) > 0
        or drops.get('map_overflow', 0) > 0
        or drops.get('enter_exit_unmatched', 0) > 0
        or bool(drops.get('stopped_early'))
        or bool(drops.get('unmeasured'))
    )
    return 'degraded' if degraded else 'observed'


# ---- aggregation ------------------------------------------------------------------------

def run_fields(run_dir):
    m = RUN_DIR_RE.match(os.path.basename(run_dir))
    if not m:
        return None
    case, config, interval, window, replicate = m.groups()
    return {'run': os.path.basename(run_dir), 'case': case, 'config': config,
            'interval': int(interval), 'window': int(window), 'replicate': int(replicate)}


def block_key(fields):
    """Runs are only comparable against a config=none run that measured the same workload
    under the same timing plan: same case, same interval/window block, same replicate."""
    return (fields['case'], fields['interval'], fields['window'], fields['replicate'])


def human(value):
    """Render one load.json field for the aggregated tables: "n/a (<reason>)" for a
    not_measured(...) sentinel or an altogether-missing value, the value itself otherwise.
    Never renders a missing or unmeasured field as 0."""
    if value is None:
        return 'n/a (not recorded)'
    if is_not_measured(value):
        return f'n/a ({not_measured_reason(value)})'
    return value


def op_field(load_json, kind, field):
    op = (load_json.get('workload') or {}).get(kind) or {}
    if field in op:
        return op[field]
    if 'state' in op:
        return op['state']
    return not_measured(f'no {kind} data in this run\'s load.json')


NO_BASE_REASON = 'no matching config=none run in this case/interval/window/replicate block'


def comparison_blocker(this_lj, base_lj):
    """Why this run's difference against the matching config=none run must not be computed
    at all, or None when the two really are comparable.

    Matching on case/interval/planned window/replicate (see block_key) only says the two
    runs were PLANNED the same way. A difference between them means something only if both
    actually carried that plan out: each ran its own window from the instant it was planned
    to, to the end it was planned to reach, over the same workload image, with complete
    cgroup accounting and an observation that actually happened. Each of those has to be
    recorded as having held - an absent field is not evidence that it did. A run that stopped early measured a shorter span; a run whose window
    started late measured a shifted one; a run whose supervised process was placed in its
    cgroup only after exec is missing that process's own startup from its counters; and two
    runs of different images are not two measurements of the same workload at all. In each
    of those cases the difference is reported as not_measured with this reason rather than
    computed from two things that are not comparable.
    """
    if base_lj is None:
        return NO_BASE_REASON
    for label, lj in (('this run', this_lj), ('the matching config=none run', base_lj)):
        if lj.get('stopped_early'):
            return (f'{label} stopped early ({lj.get("stop_reason") or "reason not recorded"}), '
                    'so it did not measure the planned window')
        # Both of these must be recorded as True, not merely "not False". A load.json that
        # does not carry them at all was written before either was established, and there is
        # no evidence in it either way - which is a reason not to compare, not a licence to.
        established = lj.get('window_established')
        if established is not True:
            if established is False:
                drift = lj.get('window_start_drift_s')
                return (f'{label} did not open its window when it was planned to'
                        + (f' (off by {drift}s)' if drift is not None else '')
                        + ', so the two windows are not the same span')
            return (f'{label} does not record whether its window was established '
                    f'(window_established={established!r}), so it cannot be confirmed to have '
                    'measured the same span')
        complete = lj.get('measurement_complete')
        if complete is not True:
            if complete is False:
                reasons = lj.get('measurement_incomplete_reasons') or ['reason not recorded']
                return f'{label} is an incomplete measurement: {"; ".join(reasons)}'
            return (f'{label} does not record whether its measurement was complete '
                    f'(measurement_complete={complete!r}), so it cannot be confirmed to have '
                    'measured what this comparison assumes')
    if this_lj.get('window') != base_lj.get('window'):
        return (f'the two runs planned different windows ({this_lj.get("window")}s vs '
                f'{base_lj.get("window")}s)')
    this_image, base_image = this_lj.get('image_id'), base_lj.get('image_id')
    if not this_image or not base_image:
        return ('the image id of at least one of the two runs was not recorded, so they '
                'cannot be confirmed to have measured the same workload')
    if this_image != base_image:
        return f'the two runs measured different images ({this_image} vs {base_image})'
    return None


def delta(this_value, base_value, blocked_reason=None):
    """this_value - base_value when both are plain numbers and the two runs are comparable
    at all (blocked_reason None; see comparison_blocker), else n/a with why not: this is the
    "difference vs the matching none run" load.py reports alongside each run's own absolute
    numbers, never computed by subtracting through an unmeasured, missing or incomparable
    side."""
    if is_not_measured(this_value) or this_value is None:
        return not_measured('this run\'s own value is not measured')
    if blocked_reason:
        return not_measured(blocked_reason)
    if base_value is None:
        return not_measured(NO_BASE_REASON)
    if is_not_measured(base_value):
        return not_measured('the matching config=none run did not measure this value either')
    return this_value - base_value


def rate(count, seconds):
    """count/seconds as a rounded rate, or not_measured when count is unmeasured or the
    window duration is not a usable positive number - never a division that could produce
    a spurious rate from a zero or negative denominator."""
    if is_not_measured(count) or count is None:
        return not_measured('count is not measured')
    if not isinstance(seconds, (int, float)) or seconds <= 0:
        return not_measured('window duration could not be computed')
    return round(count / seconds, 3)


ROW_COLUMNS = [
    'run', 'case', 'config', 'interval', 'window', 'replicate', 'stopped_early', 'stop_reason',
    'window_established', 'measurement_complete', 'comparable_to_none', 'not_comparable_because',
    'collector_cpu_prep_s', 'collector_cpu_window_s', 'collector_cpu_drain_s', 'collector_cpu_total_s',
    'collector_memory_peak_bytes',
    'tracer_cpu_prep_s', 'tracer_cpu_window_s', 'tracer_cpu_drain_s', 'tracer_cpu_total_s',
    'tracer_memory_peak_bytes',
    'dockerd_cpu_window_s',
    'events_total', 'events_total_per_second', 'events_attributed', 'events_attributed_per_second',
    'event_state', 'partial_events', 'malformed_lines',
    'lost_events', 'lost_notifications', 'map_overflow', 'convert_failures', 'enter_exit_unmatched',
    'trace_stdout_bytes', 'trace_stdout_bytes_per_second', 'trace_stderr_bytes', 'trace_stderr_bytes_per_second',
    'run_dir_growth_bytes',
    'curl_n', 'curl_median_ms', 'curl_p95_ms', 'curl_max_ms', 'curl_failures', 'curl_median_delta_ms',
    'git_n', 'git_median_ms', 'git_p95_ms', 'git_max_ms', 'git_failures', 'git_median_delta_ms',
    'openssl_n', 'openssl_median_ms', 'openssl_p95_ms', 'openssl_max_ms', 'openssl_failures', 'openssl_median_delta_ms',
    'web_n', 'web_median_ms', 'web_p95_ms', 'web_max_ms', 'web_failures', 'web_median_delta_ms',
    'web_success_count', 'web_timeout_count', 'web_failure_count',
]


def rows_for_out_dir(out_dir):
    """[{column: rendered value}, ...] for every run directory under out_dir whose name
    load-run.sh produced and which has a load.json. Pure over the filesystem it is pointed
    at, so a test can build a small synthetic out_dir and get exactly the rows a real
    aggregation run would from the same contents."""
    run_dirs = sorted(d for d in glob.glob(os.path.join(out_dir, '*-load-*'))
                       if os.path.isdir(d) and run_fields(d))
    loaded = {}
    for d in run_dirs:
        path = os.path.join(d, 'load.json')
        if not os.path.exists(path):
            continue
        loaded[d] = (run_fields(d), json.load(open(path)))

    none_by_block = {}
    for d, (fields, lj) in loaded.items():
        if fields['config'] == 'none':
            none_by_block[block_key(fields)] = lj

    rows = []
    for d, (fields, lj) in loaded.items():
        base = none_by_block.get(block_key(fields))
        # A config=none run is its own baseline: the difference against itself is not a
        # comparison and is never blocked by the preconditions below.
        blocked = None if fields['config'] == 'none' else comparison_blocker(lj, base)

        def base_op(kind, field):
            return op_field(base, kind, field) if base is not None else None

        row = dict(fields)
        row['stopped_early'] = lj.get('stopped_early', 'n/a (not recorded)')
        row['stop_reason'] = lj.get('stop_reason', '')
        row['window_established'] = lj.get('window_established', 'n/a (not recorded)')
        row['measurement_complete'] = lj.get('measurement_complete', 'n/a (not recorded)')
        row['comparable_to_none'] = blocked is None
        row['not_comparable_because'] = blocked or ''
        row['collector_cpu_prep_s'] = human(_cpu_seconds(lj.get('collector_cpu_usage_delta_prep_us')))
        row['collector_cpu_window_s'] = human(_cpu_seconds(lj.get('collector_cpu_usage_delta_window_us')))
        row['collector_cpu_drain_s'] = human(_cpu_seconds(lj.get('collector_cpu_usage_delta_drain_us')))
        row['collector_cpu_total_s'] = human(_cpu_seconds(lj.get('collector_cpu_usage_delta_total_us')))
        row['collector_memory_peak_bytes'] = human(lj.get('collector_memory_peak_bytes'))
        row['tracer_cpu_prep_s'] = human(_cpu_seconds(lj.get('tracer_cpu_usage_delta_prep_us')))
        row['tracer_cpu_window_s'] = human(_cpu_seconds(lj.get('tracer_cpu_usage_delta_window_us')))
        row['tracer_cpu_drain_s'] = human(_cpu_seconds(lj.get('tracer_cpu_usage_delta_drain_us')))
        row['tracer_cpu_total_s'] = human(_cpu_seconds(lj.get('tracer_cpu_usage_delta_total_us')))
        row['tracer_memory_peak_bytes'] = human(lj.get('tracer_memory_peak_bytes'))
        row['dockerd_cpu_window_s'] = human(_cpu_seconds(lj.get('docker_daemon_cpu_usage_delta_window_us')))
        row['events_total'] = human(lj.get('events_total'))
        row['events_total_per_second'] = human(lj.get('events_total_per_second'))
        row['events_attributed'] = human(lj.get('events_attributed'))
        row['events_attributed_per_second'] = human(lj.get('events_attributed_per_second'))
        row['event_state'] = lj.get('event_state', 'not_measured')
        row['partial_events'] = human(lj.get('partial_events'))
        row['malformed_lines'] = human(lj.get('malformed_lines'))
        drops = lj.get('drops') or {}
        for f in ('lost_events', 'lost_notifications', 'map_overflow', 'convert_failures', 'enter_exit_unmatched'):
            row[f] = human(drops.get(f, lj.get(f)))  # drops.<f> when present; lj.<f> kept as a fallback for older load.json
        row['trace_stdout_bytes'] = human(lj.get('trace_stdout_bytes'))
        row['trace_stdout_bytes_per_second'] = human(lj.get('trace_stdout_bytes_per_second'))
        row['trace_stderr_bytes'] = human(lj.get('trace_stderr_bytes'))
        row['trace_stderr_bytes_per_second'] = human(lj.get('trace_stderr_bytes_per_second'))
        row['run_dir_growth_bytes'] = human(lj.get('run_dir_growth_bytes'))
        for kind in ('curl', 'git', 'openssl'):
            row[f'{kind}_n'] = human(op_field(lj, kind, 'n'))
            row[f'{kind}_median_ms'] = human(op_field(lj, kind, 'median_ms'))
            row[f'{kind}_p95_ms'] = human(op_field(lj, kind, 'p95_ms'))
            row[f'{kind}_max_ms'] = human(op_field(lj, kind, 'max_ms'))
            row[f'{kind}_failures'] = human(op_field(lj, kind, 'failures'))
            row[f'{kind}_median_delta_ms'] = human(delta(op_field(lj, kind, 'median_ms'), base_op(kind, 'median_ms'), blocked))
        row['web_n'] = human(op_field(lj, 'web', 'n'))
        row['web_median_ms'] = human(op_field(lj, 'web', 'median_ms'))
        row['web_p95_ms'] = human(op_field(lj, 'web', 'p95_ms'))
        row['web_max_ms'] = human(op_field(lj, 'web', 'max_ms'))
        row['web_failures'] = human(op_field(lj, 'web', 'failures'))
        row['web_median_delta_ms'] = human(delta(op_field(lj, 'web', 'median_ms'), base_op('web', 'median_ms'), blocked))
        row['web_success_count'] = human(op_field(lj, 'web', 'success_count'))
        row['web_timeout_count'] = human(op_field(lj, 'web', 'timeout_count'))
        row['web_failure_count'] = human(op_field(lj, 'web', 'failure_count'))
        rows.append(row)

    rows.sort(key=lambda r: (r['case'], r['interval'], r['window'], r['replicate'], r['config']))
    return rows


def _cpu_seconds(usec_value):
    """usec_value (an int microsecond delta, or a not_measured(...) string) as seconds,
    rounded to 3 decimal places; passes a not_measured sentinel (or None) through
    unchanged."""
    if is_not_measured(usec_value) or usec_value is None:
        return usec_value
    return round(usec_value / 1_000_000, 3)


def write_aggregate(out_dir):
    rows = rows_for_out_dir(out_dir)
    with open(os.path.join(out_dir, 'AGGREGATE-load.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=ROW_COLUMNS, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(os.path.join(out_dir, 'AGGREGATE-load.md'), 'w') as f:
        f.write('# Load and overhead measurement: all runs\n\n')
        f.write('| ' + ' | '.join(ROW_COLUMNS) + ' |\n|' + ' --- |' * len(ROW_COLUMNS) + '\n')
        for r in rows:
            f.write('| ' + ' | '.join(str(r.get(c, '')) for c in ROW_COLUMNS) + ' |\n')
    return rows


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else 'experiments/runtime-discovery/out'
    rows = write_aggregate(out_dir)
    print(f'{len(rows)} rows -> {out_dir}/AGGREGATE-load.md')


if __name__ == '__main__':
    main()
