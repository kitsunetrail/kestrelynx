#!/usr/bin/env python3
"""Cross-references one measurement run's match_hc.json/match_all.json
against a truth.json (from truth.py) and writes coverage.json and
coverage.md: package-level recall, false positives, and miss causes, by
evidence series (S0/S1/S2) and by acceptance category (resident OS,
short-lived OS, and the case's own language ecosystem).

Usage: coverage.py <run dir> <truth.json>
Reads:  <run dir>/match_hc.json, <run dir>/match_all.json,
        <run dir>/collect/*.json (window bounds), <run dir>/fired_at.txt,
        <run dir>/events.jsonl (raw event capture, for the mapping-gap
        and short-lived-subject checks), <run dir>/operations.jsonl (or
        gtb-raw/operations.jsonl, or <case>.operations.jsonl — whichever
        this run actually carries, alongside the matching occurrences/
        usage logs), <truth.json>
Writes: <run dir>/coverage.json, <run dir>/coverage.md

Every key here is the three-part (ecosystem, name, version) truth.json
itself uses, matched against match's own PackageVerdict.installed_version
rather than name alone: a confirmed package whose reported version
matches no version this run's own inventory walk found for that name is
neither a plain true positive nor a plain false positive by construction
of that exact-triple comparison, which is what gives the design's
misattribution rule for free — a package confirmed at the wrong version
counts as a false positive for that (wrong) version when the wrong
version is itself a known-unused one, as a true positive when the wrong
version turns out to also be genuinely used (two different bundled
versions of the same name, both used), and independently leaves the
correct version's own miss to surface as an ordinary false negative
whenever nothing else confirms it — all without extra branching, because
each of the three outcomes is just a different (ecosystem, name, version)
key landing in a different one of the exact sets.

The main tp/fn/fp/tn/recall/fpr figures below are scored against U/N,
where U is "used at startup" (which already includes any use before the
measurement window opens — the design's own primary evaluation including
pre-start use) unioned with "used during an operation THIS measurement
run's own operations.jsonl actually recorded", whether or not that
operation's own instance fell inside this run's own observation window,
up to this run's own stop (see main_membership). This is deliberately
not truth's own whole-truth-run used/unused set: the truth run (strace,
900 seconds) can run longer than, or simply differently from, any one
measurement run, and scoring against everything the truth run ever did
would count a package this particular measurement run never had the
opportunity to use — because it never ran the operation that uses it at
all — as a miss of this run's own collection, which it is not. A package
used only during an operation this run's own operations.jsonl never
recorded at all is excluded from both U and N (X): this run's own
evidence cannot confirm or deny the equivalent activity ever happened
during it, so it is neither a confirmed use nor a confirmed non-use for
THIS run specifically.

Each category/series result also carries a "window" figure alongside
the main one: the same tp/fn/fp/tn recomputed against U_window/N_window,
the narrower subset of U that this measurement run's own operations.jsonl
can confirm actually completed inside this measurement run's own
observation window specifically (as opposed to merely being recorded at
all, which is all the main figure requires) — an auxiliary figure, per
the design's own treatment of window-scoped recall as supplementary to
the main figure, never a replacement for it. Both "main_scoping" and
"window" report unavailable when this run carries no operations.jsonl of
its own to score against at all (any
case other than the three coverage-validation ones, or a run this tool
was not pointed at).

Run this from the same repository checkout truth.py ran in: it imports
truth.py's own time-parsing and operation-interval helpers rather than
duplicating them.

A bundled package's own scan-report Finding population is a separate
concern from whether it was ever confirmed: with match's -all-packages
flag used at scan time, a package the scan lists but never confirms is an
ordinary false negative, classified "mapping_not_supported" alongside
every other kind of unconfirmed-but-known package, rather than being
dropped from the recall denominator or scored as its own outcome.
"""
import glob
import json
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gtb
import truth as truth_lib

SERIES = ('S0', 'S1', 'S2')
SERIES_FIELD = {'S0': 'verdict', 'S1': 's1_verdict', 'S2': 's2_verdict'}
SERIES_FACTOR_FIELD = {'S0': 'factor', 'S1': 's1_factor', 'S2': 's2_factor'}

# match.go's own ecosystem labels (mapping.go's eco* constants), as they
# appear in a PackageVerdict's "ecosystem" field, mapped to this tool's
# truth.json ecosystem names. "gobinary" is intentionally absent: Go's
# embedded-module evidence stays out of this tool's population entirely.
ECOSYSTEM_MAP = {'os': 'os', 'jar': 'java', 'node-pkg': 'node', 'python-pkg': 'python'}

MAPPING_GAP_FACTORS = ('lang_pkg_unmappable', 'no_file_list', 'db_absent', 'db_error',
                       'mapping_input_missing', 'event_path_unresolved')

# collect.go's own Failure.Step vocabulary for a permission result
# (EACCES/EPERM) and for "the process/path was not there at all"
# (ESRCH/ENOENT) — see collect.go's procReadOutcome. Read from the
# structured "step" field rather than pattern-matching the free-text
# "message" (Go's own err.Error() string, whose exact wording is not this
# tool's to depend on), so a permission result is told apart from a
# not-found one by the same vocabulary the collector itself uses to make
# that distinction, not by guessing at error text.
PERMISSION_FAILURE_STEPS = ('proc_denied', 'rootfs_denied', 'prepare_proc_denied')
NOT_FOUND_FAILURE_STEPS = ('proc_gone',)

# Short-lived operational commands, exactly as truth.py's own
# classify_exec_subject names them — used here to read a measurement
# run's own event-sourced confirmations the same way, never truth's own
# subject labels (see short_lived_subject_from_confirmations).
SHORT_LIVED_COMMAND_BASENAMES = {os.path.basename(p) for p in truth_lib.SHORT_LIVED_COMMANDS}


def load_match(run, variant):
    path = f'{run}/match_{variant}.json'
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def confirmed_key(pv):
    """The (ecosystem, name, version) key a PackageVerdict resolves to in
    this tool's truth vocabulary, or None when its ecosystem is out of
    scope (a Go binary, or an ecosystem label this tool does not
    recognize)."""
    eco = ECOSYSTEM_MAP.get(pv.get('ecosystem'), '')
    if not eco:
        eco = 'os' if pv.get('class') == 'os' else ''
    if not eco:
        return None
    name = pv.get('package', '')
    if eco == 'python':
        name = gtb.normalize_py_name(name)
    return eco, name, pv.get('installed_version') or None


def build_confirmed_sets(match_json):
    """{series: {(ecosystem, name, version): PackageVerdict}}."""
    sets = {s: {} for s in SERIES}
    present = {}
    for pv in match_json.get('packages', []):
        key = confirmed_key(pv)
        if key is None:
            continue
        present[key] = pv
        for series in SERIES:
            field = SERIES_FIELD[series]
            verdict = pv.get(field) or pv.get('verdict')
            if verdict == 'confirmed':
                sets[series][key] = pv
    return sets, present


def truth_used_map(truth):
    """{(ecosystem, name, version): truth-used-entry}."""
    return {(u['ecosystem'], u['name'], u['version']): u for u in truth.get('used', [])}


# --- category assignment --------------------------------------------------

def categories_for_used(entry):
    """Which acceptance categories a used truth entry belongs to. An OS
    package belongs to resident_os and/or short_lived_os according to
    which subjects truth.py recorded for it - both, when both touched it
    - never neither, since an entry only exists in "used" because some
    subject did. A language package belongs to exactly its own
    ecosystem's category."""
    eco = entry['ecosystem']
    if eco != 'os':
        return [eco]
    subjects = entry.get('subjects') or ['resident']
    cats = []
    if 'resident' in subjects:
        cats.append('resident_os')
    if 'short_lived' in subjects:
        cats.append('short_lived_os')
    return cats or ['resident_os']


def categories_for_unused(entry):
    """An unused OS package is a negative example for both OS categories
    at once: nothing observed it under either subject, so both
    categories' false-positive/true-negative counts are equally
    informative about it. A language package again belongs to exactly its
    own ecosystem's category."""
    eco = entry['ecosystem']
    return ['resident_os', 'short_lived_os'] if eco == 'os' else [eco]


def categories_for_unknown(entry):
    """A truth-unknown (X) entry is assigned the same way an unused one
    is: an OS package belongs to both OS categories (use/non-use could
    not be certified under either subject), a language package to its own
    ecosystem."""
    return categories_for_unused(entry)


# --- measurement-run context: window bounds, events, failures -------------

def read_window_bounds(run):
    """(window_start, window_end) as aware UTC datetimes, read from the
    saved observation JSON, or (None, None) when there is none."""
    candidates = [f for f in glob.glob(f'{run}/collect/*.json')
                  if not f.endswith('manifest.json') and not f.endswith('ready.json')]
    if not candidates:
        return None, None
    try:
        obs = json.load(open(candidates[0]))
    except (ValueError, OSError):
        return None, None
    window = obs.get('window', {})
    start, end = window.get('scheduled_start'), window.get('scheduled_end')
    return (truth_lib.parse_iso_utc(start) if start else None,
            truth_lib.parse_iso_utc(end) if end else None)


def read_sample_times(run):
    """Every sample's own actual start time (falling back to its
    scheduled start when the actual one was not recorded), as sorted
    aware UTC datetimes, from the same saved observation JSON
    read_window_bounds reads (window.samples[]) - the real times this
    run's own periodic sampling loop actually fired at, which a
    scheduling delay or a slow sample can disagree with a constant
    interval_seconds by (see read_sampling_interval_seconds). Returns
    [] when there is no observation record, or it carries no samples at
    all."""
    candidates = [f for f in glob.glob(f'{run}/collect/*.json')
                  if not f.endswith('manifest.json') and not f.endswith('ready.json')]
    if not candidates:
        return []
    try:
        obs = json.load(open(candidates[0]))
    except (ValueError, OSError):
        return []
    times = []
    for s in (obs.get('window') or {}).get('samples') or []:
        ts = s.get('actual_start') or s.get('scheduled_start')
        if not ts:
            continue
        try:
            times.append(truth_lib.parse_iso_utc(ts))
        except ValueError:
            continue
    return sorted(times)


def read_sample_process_index(run):
    """{(sample_id, path): set of exe basenames} - every process this
    run's own periodic sample found at each sample instant, keyed by
    every path that process's own memory maps (or its own exe itself)
    named - the only way to resolve WHICH process a sampling-sourced
    confirmation actually came from (a sampling Confirmation never
    carries its own process_generation at all, see series.go's own
    sourceSampling handling), since a shared library's own package name
    says nothing about which of its many possible callers a specific
    confirmation is even about. Returns {} when there is no observation
    record, from the same saved JSON read_window_bounds/
    read_sample_times read.

    Applies the SAME validity condition match.go's own buildReadOutcomes
    does when deciding what a sample's own process rows can be used as
    evidence for: a process record marked invalid (its own generation
    identity could not be confirmed stable across the sample, per
    collect.go's own ProcessRecord.Invalid) is skipped entirely, and a
    process whose own exe or maps read itself failed (exe_error/
    maps_error) never contributes the corresponding half - crediting an
    unreadable or unstable process's own (possibly stale, possibly
    mixed-generation) exe/maps to a path would misattribute it to a
    process that was never actually confirmed to be there."""
    candidates = [f for f in glob.glob(f'{run}/collect/*.json')
                  if not f.endswith('manifest.json') and not f.endswith('ready.json')]
    if not candidates:
        return {}
    try:
        obs = json.load(open(candidates[0]))
    except (ValueError, OSError):
        return {}
    index = {}
    for proc in obs.get('processes') or []:
        if proc.get('invalid'):
            continue
        sample_id = proc.get('sample_id')
        exe = proc.get('exe')
        if not sample_id or not exe or proc.get('exe_error'):
            continue
        basename = os.path.basename(exe)
        index.setdefault((sample_id, exe), set()).add(basename)
        if proc.get('maps_error'):
            continue
        for m in proc.get('maps') or []:
            p = m.get('path')
            if p:
                index.setdefault((sample_id, p), set()).add(basename)
    return index


def read_sampling_interval_seconds(match_json):
    return (match_json or {}).get('run_key', {}).get('interval_seconds')


def read_event_state(match_json):
    """(event_state, has_drops) from one match result: has_drops is True
    when the window is degraded or reports an actual event loss - lost
    events, the notifications that stand for events lost to buffer
    overflow, or a map overflow that dropped an open/exec outright - a
    run-wide signal classify_miss attaches as an auxiliary tag on an
    otherwise-unexplained miss, rather than treating it as a standalone
    cause on its own.

    This deliberately does not sum every numeric field under event_drops:
    fields like path_read_failures describe an event the collection DID
    capture but could not fully describe (an attribute missing, not a
    loss - see EventDropCounts.partialEventCount in events.go), and
    events_before_filter/events_after_filter are plain counts, not a loss
    count at all. Folding those in would mark nearly every run as having
    dropped events regardless of whether anything was actually lost."""
    m = match_json or {}
    state = m.get('event_state')
    drops = m.get('event_drops') or {}
    real_loss = (drops.get('lost_events') or 0) > 0 or (drops.get('lost_notifications') or 0) > 0 \
        or (drops.get('map_overflow') or 0) > 0
    return state, (state == 'degraded' or real_loss)


def read_failures(match_json):
    """Every recorded step failure as {"step": str, "message": str} -
    the structured step name (collect.go's own Failure.Step) kept
    alongside the free-text message, so a caller can tell a permission
    result apart from a not-found one by the collector's own vocabulary
    (see PERMISSION_FAILURE_STEPS/NOT_FOUND_FAILURE_STEPS) rather than by
    guessing at the message's wording."""
    return [{'step': f.get('step', ''), 'message': f.get('message', '')}
            for f in (match_json or {}).get('failures', [])]


def read_event_capture(run, container_id, window_start=None, window_end=None):
    """{path: [event dicts]} for every successful, resolved exec/open
    this run's own events.jsonl attributes to container_id and (when
    window bounds are given) places inside the observation window -
    independent of whether match could turn it into a package. Omitting
    the window bounds keeps this tool's earlier, run-wide behavior for a
    caller that has none to give; classify_miss's own S1/S2 use of this
    always supplies them, so an event from outside this run's own
    observation is never used to explain a miss that happened inside
    it."""
    path = f'{run}/events.jsonl'
    captured = {}
    if not os.path.exists(path):
        return captured
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get('record') != 'event' or not rec.get('ok'):
                continue
            if rec.get('event') not in ('exec', 'open'):
                continue
            if container_id and rec.get('container_id') != container_id:
                continue
            if rec.get('path_resolved') is False:
                continue
            p = rec.get('resolved') or rec.get('path')
            if not p:
                continue
            if window_start is not None or window_end is not None:
                ts_dt = _parse_event_ts(rec.get('ts'))
                if ts_dt is None:
                    continue
                if window_start is not None and ts_dt < window_start:
                    continue
                if window_end is not None and ts_dt > window_end:
                    continue
            captured.setdefault(p, []).append(rec)
    return captured


def _parse_event_ts(ts):
    if not ts:
        return None
    try:
        return truth_lib.parse_iso_utc(ts)
    except ValueError:
        return None


def read_container_id(run):
    path = f'{run}/container_id.txt'
    if os.path.exists(path):
        return open(path).read().strip()
    return None


def find_event_gap(run, container_id, window_start, window_end):
    """The single largest gap between two consecutive successful,
    resolved, in-window exec/open events this run recorded for
    container_id, when that gap is at least 2 seconds long and at least
    5 times the median gap in the same stream - a coarse, run-level
    signal that this run's own event capture has an identifiable hole in
    an otherwise fairly regular stream, never a claim that any specific
    package's own evidence fell into it (classify_miss only promotes this
    to a miss's own primary cause together with a run-wide report of
    lost/dropped events). Returns (gap_start, gap_end), or None when
    there are too few events to compare gaps at all, or none stands out
    this way."""
    path = f'{run}/events.jsonl'
    if not os.path.exists(path):
        return None
    times = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get('record') != 'event' or not rec.get('ok'):
                continue
            if rec.get('event') not in ('exec', 'open'):
                continue
            if container_id and rec.get('container_id') != container_id:
                continue
            if rec.get('path_resolved') is False:
                continue
            ts_dt = _parse_event_ts(rec.get('ts'))
            if ts_dt is None:
                continue
            if window_start is not None and ts_dt < window_start:
                continue
            if window_end is not None and ts_dt > window_end:
                continue
            times.append(ts_dt)
    times.sort()
    if len(times) < 4:
        return None
    gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
    sorted_gaps = sorted(gaps)
    mid = len(sorted_gaps) // 2
    median = sorted_gaps[mid] if len(sorted_gaps) % 2 else (sorted_gaps[mid - 1] + sorted_gaps[mid]) / 2
    best_idx = max(range(len(gaps)), key=lambda i: gaps[i])
    best = gaps[best_idx]
    if best >= 2.0 and (median == 0 or best >= 5 * median):
        return times[best_idx], times[best_idx + 1]
    return None


# --- miss-cause classification ---------------------------------------------

def _could_persist_into_window(used_entry):
    """Whether this package's own truth evidence includes something that
    could plausibly still be resident by the time the measurement window
    opens even though every timed observation of it happened earlier: an
    executed image or a shared library, both held mapped for as long as
    the process that loaded them keeps running, unlike a plain data file
    a program opens once and is done with. Only a package with no such
    evidence at all qualifies for "used before the window" as a miss
    cause in its own right; one that does is left for a more specific
    explanation, since being held mapped is exactly the kind of continued
    use this run's own sampling should have been able to see within the
    window regardless of when it was first opened."""
    if 'exec' in (used_entry.get('evidence_types') or []):
        return True
    return any(p.endswith('.so') or '.so.' in os.path.basename(p)
               for p in (used_entry.get('paths') or []))


def read_events_by_pid_starttime(run, container_id):
    """{(pid, starttime): [event dict, ...]} - every SUCCESSFUL event
    record this run's own events.jsonl attributes to container_id, of
    EVERY kind (exec/open/dlopen/exit/dlclose - not just exec/open the
    way read_event_capture keeps), each carrying its own parsed 'ts_dt'.
    The only way to read a genuine start~end pairing (a process's own
    exec~exit, or a dynamically loaded library's own dlopen~dlclose)
    directly off THIS measurement run's own capture (see
    _measurement_retention_interval) - never borrowed from the separate
    strace-only truth run, which has no bearing on how long anything was
    actually retained on THIS run."""
    path = f'{run}/events.jsonl'
    index = {}
    if not os.path.exists(path):
        return index
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get('record') != 'event' or not rec.get('ok'):
                continue
            if container_id and rec.get('container_id') != container_id:
                continue
            pid, starttime = rec.get('pid'), rec.get('starttime')
            if pid is None or starttime is None:
                continue
            ts_dt = _parse_event_ts(rec.get('ts'))
            if ts_dt is None:
                continue
            entry = dict(rec)
            entry['ts_dt'] = ts_dt
            index.setdefault((pid, starttime), []).append(entry)
    return index


def _measurement_retention_intervals(used_entry, events_by_pid, measurement_intervals_raw):
    """(intervals, has_unconfirmed_use) - EVERY retention interval THIS
    measurement run's own evidence can support for one used package,
    never just the first one found: a package can legitimately be
    retained across more than one such interval (opened by more than
    one process, or during more than one operation instance), and ALL
    of them matter for judging whether a sample could have caught it -
    a single brief interval fitting cleanly between two samples proves
    nothing about a second, much longer one that does not.

    intervals is a list of (start_dt, end_dt) pairs: a genuine
    exec~exit span (for a process subject) or dlopen~dlclose span (for
    a dynamically loaded library) read directly from this run's own
    events.jsonl, for each of the package's own paths this run actually
    captured a paired opening+closing event for, plus (for a
    short_lived PROCESS subject only) every genuinely exec~exit-paired
    osops_ operation instance the package was used during (see
    read_operation_intervals's own "paired" flag - never a fixed
    operation's own "load" span, which times executing an import
    statement, not how long anything it loaded then stayed resident
    for; a resident subject's own operation instance never has this
    kind of span to begin with, hence the 'short_lived' subject
    restriction).

    has_unconfirmed_use is True when this run's own evidence shows a use
    this function could not build a retention interval for at all - an
    events.jsonl opening (exec/open/dlopen) of one of the package's own
    paths with no matching close/exit ever recorded, or an osops_
    operation instance the package was used during that usage.jsonl
    could not pair (paired is False) - a genuine "held, unknown for how
    long" use, never silently dropped just because some OTHER use of
    the same package could be confirmed short.

    Within one (pid, starttime) events group, every opening of the
    package's own paths is paired with the NEXT still-available closing
    event for THAT SAME PATH at or after it, in chronological order -
    never "the earliest open of any of our own paths" matched against
    "the earliest close of anything", which would silently pair a later,
    still-open load with an earlier load's own close and miss that the
    later one was never confirmed closed at all (the same process
    loading, closing, then loading the SAME package again without this
    run ever recording a second close is a real, distinct "held, unknown
    for how long" use of its own), and would just as wrongly pair one
    path's own open against an entirely UNRELATED path's own close
    (dlclose is a per-library event; b.so closing says nothing about
    whether a.so, opened around the same time by the same process, was
    ever closed at all). "exit" is the one exception: a process exiting
    ends every retention interval it was still holding open at once,
    across every path, since the OS itself reclaims everything the
    process held the moment it exits - so an exit event closes all of
    this group's still-pending opens regardless of which path they were
    for, not just one."""
    paths = set(used_entry.get('paths') or [])
    intervals = []
    has_unconfirmed_use = False
    for events in events_by_pid.values():
        timeline = []
        for e in events:
            ev = e.get('event')
            if ev in ('exec', 'open', 'dlopen') and e.get('path') in paths:
                timeline.append((e['ts_dt'], 'open', e.get('path')))
            elif ev == 'dlclose' and e.get('path') in paths:
                timeline.append((e['ts_dt'], 'close', e.get('path')))
            elif ev == 'exit':
                timeline.append((e['ts_dt'], 'exit', None))
        if not timeline:
            continue
        timeline.sort(key=lambda item: item[0])
        pending = {}  # path -> [open_ts, ...], oldest first
        for ts, kind, path in timeline:
            if kind == 'open':
                pending.setdefault(path, []).append(ts)
            elif kind == 'close':
                queue = pending.get(path)
                if queue:
                    intervals.append((queue.pop(0), ts))
            else:  # 'exit': closes every path's own still-pending opens at once
                for queue in pending.values():
                    for open_ts in queue:
                        intervals.append((open_ts, ts))
                pending = {}
        # Anything still pending once this group's own timeline is
        # exhausted never saw its own same-path close, nor a process
        # exit, recorded at all - a genuine "held, unknown for how long"
        # use.
        if any(pending.values()):
            has_unconfirmed_use = True
    if 'short_lived' in (used_entry.get('subjects') or []):
        used_ops = set(used_entry.get('used_during_operations') or [])
        for iv in measurement_intervals_raw:
            if iv.get('op') in used_ops and str(iv.get('op', '')).startswith('osops_'):
                if iv.get('paired') and iv.get('start') is not None and iv.get('end') is not None:
                    intervals.append((iv['start'], iv['end']))
                elif not iv.get('paired'):
                    has_unconfirmed_use = True
    return intervals, has_unconfirmed_use


def _interval_fits_between_samples(start_dt, end_dt, sample_times):
    """Whether [start_dt, end_dt] is sandwiched entirely between two of
    this run's own ADJACENT, actual sample times - not merely "no
    sample happens to fall inside it" (which a retention interval
    entirely before the first sample or after the last one would
    trivially satisfy too, despite never having been genuinely
    bracketed by two samples that could have caught it one way or the
    other)."""
    times = sorted(sample_times)
    for i in range(len(times) - 1):
        if times[i] <= start_dt and end_dt <= times[i + 1]:
            return True
    return False


def classify_miss(key, used_entry, present_pv, series, ctx):
    """One primary miss cause, in a fixed priority order, plus an optional
    auxiliary tag. ctx carries everything about the measurement run this
    needs: window bounds (relative to the measurement run's own firing
    instant), the sampling interval, captured raw events keyed by path
    (S1/S2 only - see below), recorded failures, an identified event-loss
    time range when this run's own capture shows one, and whether the run
    as a whole reported any event loss at all.

    Returns (cause: str, detail: str, tags: list[str]).
    """
    window_start_rel = ctx.get('window_start_rel')
    first_s, last_s = used_entry.get('first_seen_s'), used_entry.get('last_seen_s')

    # 1: every piece of truth's own timed evidence for this package falls
    # entirely before the measurement window even opened, and nothing
    # about it says it could still be resident once the window opens.
    if (window_start_rel is not None and last_s is not None
            and last_s < window_start_rel and not _could_persist_into_window(used_entry)):
        return ('used_before_window',
                f'all evidence at or before {last_s:.1f}s (relative to firing); '
                f'the measurement window opened at {window_start_rel:.1f}s', [])

    # 2 (S0 only): a genuinely short-lived use is confirmed only when
    # EVERY ONE of THIS measurement run's own retention intervals for
    # this package (see _measurement_retention_intervals - a real
    # exec~exit/dlopen~dlclose span from its own events.jsonl for each
    # of the package's own paths that has one, plus, for a short-lived
    # PROCESS subject, each genuine exec~exit-paired osops operation
    # instance) fits entirely between two of this run's own ACTUAL,
    # recorded sample times (from the observation record's own
    # window.samples - not merely a constant interval_seconds a
    # scheduling delay or a slow sample can silently disagree with).
    # This is never decided from the FIRST interval found alone, nor
    # does the order intervals happen to be enumerated in matter: a
    # package can be retained across more than one interval (opened by
    # more than one process, or during more than one operation
    # instance), and a single brief one fitting cleanly between samples
    # proves nothing about a second, much longer one that a sample
    # genuinely could have caught. A use this run's own evidence shows
    # started but never confirms the end of at all (has_unconfirmed_use)
    # counts the same way a spanning interval would: retained for an
    # unknown length, never assumed short.
    #
    # An operation's own span is NEVER used as a stand-in for retention
    # in general (see _measurement_retention_intervals): this run's own
    # event stream carries no exit/dlclose events at all today, and a
    # resident subject's own lazy-loaded library has no retention END
    # this run can observe by any means - it stays mapped for the rest
    # of that process's life. Truth's own retention timing is never
    # transplanted onto this run either: truth's own hold_seconds/
    # exec_hold_seconds_min/held_evidence describe a DIFFERENT run's own
    # clock. When this run's own evidence cannot support any retention
    # interval at all, this stays unconfirmed rather than assumed either
    # way - short_lived_use_candidate is set as an auxiliary tag on
    # cause 7 (unknown) instead of asserting a specific cause this run
    # cannot actually support.
    short_lived_use_unconfirmable = False
    if series == 'S0':
        sample_times = ctx.get('sample_times') or []
        measurement_intervals_raw = ctx.get('measurement_intervals_raw') or []
        events_by_pid = ctx.get('events_by_pid') or {}
        retention_intervals, has_unconfirmed_use = _measurement_retention_intervals(
            used_entry, events_by_pid, measurement_intervals_raw)
        if not retention_intervals or has_unconfirmed_use or len(sample_times) < 2:
            short_lived_use_unconfirmable = True
        elif all(_interval_fits_between_samples(start, end, sample_times) for start, end in retention_intervals):
            return ('short_lived_use',
                    f'every one of this run\'s own {len(retention_intervals)} confirmed retention interval(s) '
                    'fits entirely between two of this run\'s own consecutive sample times', [])
        # else: at least one retention interval WAS confirmed on this
        # run's own evidence but does not fit between two samples - a
        # real (non-)finding, not an unconfirmable one.

    # 3 (S2 only): truth shows in-window use, and the run's own raw event
    # log captured an exec/open of one of this package's own paths, but
    # match still produced no confirmed verdict for it - a resolution
    # gap between raw evidence and a named package, not a missing
    # observation. This is S2-specific: S0 never uses event evidence at
    # all, and S1 (P ∪ A) does not draw on it either - only S2 (P ∪ A ∪
    # E) does, so citing raw event capture to explain an S0 or S1 miss
    # would be scoring a series against a source it never uses.
    if series == 'S2':
        captured_paths = ctx.get('captured_paths', {})
        paths = used_entry.get('paths') or []
        if any(p in captured_paths for p in paths):
            return ('mapping_not_supported',
                    'the run\'s own event log captured an exec/open of this package\'s own path, '
                    'but no package verdict was produced from it', [])
    # A bundled package the scan itself never listed a Finding-less
    # PackageVerdict for at all falls in here too: the evidence, if any,
    # was never going to reach a verdict regardless of what happened at
    # runtime. This applies to every series alike, since it is a scan
    # population gap, not an event-evidence one.
    if present_pv is None:
        return ('mapping_not_supported',
                'the bundled package carries no PackageVerdict in this scan at all '
                '(absent from the scan\'s own package list)', [])
    factor = present_pv.get(SERIES_FACTOR_FIELD[series]) or present_pv.get('factor') or ''
    if factor in MAPPING_GAP_FACTORS:
        return ('mapping_not_supported', f'match reported factor "{factor}" for this package in {series}', [])

    # 4/5: a recorded access failure names one of this package's own
    # paths. The structured step decides which: proc_denied/
    # rootfs_denied is a real permission result; proc_gone (ESRCH/ENOENT)
    # is the path or process simply not being there, never reported as a
    # permission denial; anything else naming the path is a real,
    # identifiable failure that is neither, kept apart as "other" rather
    # than folded into "unknown".
    paths = used_entry.get('paths') or []
    failures = ctx.get('failures', [])
    matching = [f for f in failures if any(p in (f.get('message') or '') for p in paths)]
    if matching:
        permission = [f for f in matching if f.get('step') in PERMISSION_FAILURE_STEPS]
        if permission:
            return ('insufficient_permission',
                    f'a recorded access failure (step "{permission[0].get("step")}") '
                    'names one of this package\'s own paths', [])
        other = [f for f in matching if f.get('step') not in NOT_FOUND_FAILURE_STEPS]
        if other:
            return ('other',
                    f'a recorded access failure (step "{other[0].get("step")}") names one of this '
                    f'package\'s own paths, for a reason other than a permission denial or a not-found '
                    f'result: {other[0].get("message")}', [])
        # every matching failure is proc_gone (ENOENT/ESRCH-equivalent):
        # explicitly not a permission result, and not specific enough on
        # its own to be "other" either - falls through to below.

    # 6 (S2 only): a run-wide report of lost or dropped events, promoted
    # to this miss's own primary cause only when this run's own event
    # stream for this container shows an identifiable gap that actually
    # OVERLAPS this specific package's own operation interval on this
    # measurement run - never merely because a gap exists somewhere in
    # the run, or because event_drops is nonzero somewhere, neither of
    # which says THIS package's own evidence was the evidence lost. S2
    # only: event loss cannot explain an S0/S1 miss, since neither draws
    # on event evidence at all.
    if series == 'S2':
        loss_window = ctx.get('identified_loss_window')
        if ctx.get('has_event_drops') and loss_window is not None:
            op_intervals_by_name = ctx.get('measurement_op_intervals') or {}
            gap_start, gap_end = loss_window
            for op in (used_entry.get('used_during_operations') or []):
                for start, end in op_intervals_by_name.get(op, []):
                    if start is None or end is None:
                        continue
                    if start <= gap_end and gap_start <= end:
                        return ('lost_events',
                                f'this run\'s own event stream for this container shows a gap from '
                                f'{gap_start.isoformat()} to {gap_end.isoformat()}, overlapping this '
                                f'package\'s own "{op}" operation on this run, and this run reported '
                                'dropped/lost events', [])

    # 7: none of the above explains this miss at all.
    tags = []
    if ctx.get('has_event_drops'):
        tags.append('lost_events_candidate')
    if short_lived_use_unconfirmable:
        tags.append('short_lived_use_candidate')
    return ('unknown',
            'present in the scan with a non-confirmed verdict and no window-timing, event-capture, '
            'or failure-message signal to classify from', tags)


# --- window-scoped operation-based scoring (auxiliary to the main,
# whole-run recall figure) --------------------------------------------------

def _measurement_operation_paths(run, case_id):
    """(operations_path, occurrences_path, usage_path) for the
    measurement run's own copy of these logs, trying every naming
    convention this harness's own tooling actually produces: case-run.sh's
    post-rename copy under gtb-raw/ (what a real measurement run leaves
    behind), dump-logs' own <case>.<name>.jsonl naming directly at the
    run's root (this tool's own test fixtures use this form), and a plain
    unprefixed copy at the run's root. Each of the three names is
    resolved independently, so a fixture carrying only one of these files
    for occurrences/usage (or none at all) still finds what it does
    have."""
    def find(name):
        candidates = [
            f'{run}/gtb-raw/{name}.jsonl',
            f'{run}/{case_id}.{name}.jsonl',
            f'{run}/{name}.jsonl',
        ]
        return next((c for c in candidates if os.path.exists(c)), candidates[-1])
    return find('operations'), find('occurrences'), find('usage')


def read_measurement_operation_intervals(run, case_id):
    """The measurement run's own operation instances, timed the same way
    truth.py's own read_operation_intervals times a truth run's, from
    this run's own operations.jsonl/occurrences.jsonl/usage.jsonl - none
    of which this tool duplicates the reading of. Returns [] when this
    run carries no operations.jsonl of its own at all (a case other than
    26-28, or a run this tool was not pointed at)."""
    ops_path, occ_path, usage_path = _measurement_operation_paths(run, case_id)
    if not os.path.exists(ops_path):
        return []
    return truth_lib.read_operation_intervals(ops_path, occ_path, usage_path)


def _interval_overlap(interval, window_start, window_end):
    """"inside" (fully contained in [window_start, window_end]),
    "straddle" (a real, timed interval that partially overlaps the
    window boundary), or "outside" (no overlap at all, or an interval
    this cannot time)."""
    start, end = interval.get('start'), interval.get('end')
    if start is None or end is None or window_start is None or window_end is None:
        return 'outside'
    if start >= window_start and end <= window_end:
        return 'inside'
    if end < window_start or start > window_end:
        return 'outside'
    return 'straddle'


def build_window_operation_sets(measurement_intervals, window_start, window_end):
    """O_window (operation names with at least one instance that
    completed fully inside the measurement window), straddling_only (a
    name with at least one instance overlapping the window boundary and
    none fully inside it), and every operation name this measurement run
    recorded at all (used to tell a genuinely unrecorded operation apart
    from one this run saw only outside the window)."""
    inside, straddle, seen = set(), set(), set()
    for interval in measurement_intervals:
        seen.add(interval['op'])
        overlap = _interval_overlap(interval, window_start, window_end)
        if overlap == 'inside':
            inside.add(interval['op'])
        elif overlap == 'straddle':
            straddle.add(interval['op'])
    return inside, (straddle - inside), seen


def _confirmable_via_completed_ops(used_entry, completed_ops_here, unpaired_osops_ids):
    """Whether at least one of completed_ops_here (the operation NAMES
    this package was used during that this measurement run's own
    operations.jsonl shows finished by window end) is confirmable as a
    genuine main-scope use.

    A non-osops (fixed, one-shot) operation always is: compare_
    operations' own exact-sequence check already requires the two runs
    to match on every fixed operation entirely, so there is no
    "unverified instance" concept for one at all.

    A periodic osops_ operation is confirmable only when at least one of
    the SPECIFIC instances this package's own evidence was tied to (see
    truth.py's own operation_instances) falls OUTSIDE unpaired_osops_ids
    - truth.py's own osops_pairing (from compare_operation_records's own
    positional pairing against a measurement run) names exactly which of
    truth's own instances were actually verified and which were left
    over in whatever range one side's own sequence ran longer than the
    other's. An operation NAME matching completed_ops is not enough on
    its own: the specific instance this package's own evidence came from
    might be one this run's own re-comparison never had the chance to
    verify at all.

    unpaired_osops_ids is None when no such information is available
    (an older truth.json with no operation_instances, or a caller with
    no fresh osops_pairing to give at all) - every completed op is then
    trusted unconditionally, the same as before this check existed. An
    entry with no operation_instances recorded at all falls back the
    same way: there is nothing more specific to check against."""
    non_osops = {op for op in completed_ops_here if not str(op).startswith('osops_')}
    if non_osops:
        return True
    if unpaired_osops_ids is None:
        return True
    instances = set(used_entry.get('operation_instances') or [])
    if not instances:
        return True
    return bool(instances - unpaired_osops_ids)


def _paired_measurement_instance_for(instance_id, osops_pairing, measurement_intervals_raw):
    """The measurement run's own operation-interval dict (from
    measurement_intervals_raw, matched by its own "id") that truth.py's
    own osops_pairing says instance_id (one of TRUTH's own operation
    instance ids) was actually verified against, by POSITION in the two
    runs' own interleaved timelines (paired_truth_osops_ids[i] pairs
    with paired_measurement_osops_ids[i] - see truth.py's own
    osops_pairing_info). Returns None when instance_id has no paired
    counterpart at all (unpaired, or not an osops instance to begin
    with), when osops_pairing itself was not given, or when that
    counterpart's own interval cannot be found in this run's own
    interval list."""
    if not osops_pairing:
        return None
    paired_truth = osops_pairing.get('paired_truth_osops_ids') or []
    paired_measurement = osops_pairing.get('paired_measurement_osops_ids') or []
    try:
        idx = paired_truth.index(instance_id)
    except ValueError:
        return None
    if idx >= len(paired_measurement):
        return None
    measurement_id = paired_measurement[idx]
    for iv in measurement_intervals_raw or []:
        if iv.get('id') == measurement_id:
            return iv
    return None


def main_membership(used_entry, completed_ops, straddling_ops, measurement_op_intervals, window_end,
                     unpaired_osops_ids=None, osops_pairing=None, measurement_intervals_raw=None):
    """Whether one truth-used package belongs to U ("used at startup" —
    which already includes any use before the measurement window opens,
    the design's own "primary evaluation including pre-start use" — or
    during an operation THIS measurement run's own operations.jsonl
    shows finished by the end of its own observation window,
    completed_ops), or, failing that, to X. The scope is deliberately
    "from startup through the end of THIS run's own window", never the
    truth run's own full, possibly-longer life span: a package the truth
    run used only during an operation this measurement run's own window
    had already closed before starting (or that this run's own
    operations.jsonl never recorded starting at all) is not something
    this run had the opportunity to confirm using within its own defined
    primary period, so it is excluded from U rather than counted as a
    miss this run could never have made.

    completed_ops and straddling_ops both come from
    measurement_ops_completed_by/measurement_ops_straddling_only, scoped
    to this run's own window-end cutoff (window_end, an absolute
    datetime - the same one measurement_op_intervals' own [start, end]
    pairs are given in). An operation this run's own window closed IN
    THE MIDDLE of (straddling_ops) is not enough on its own: the
    operation having started before the cutoff says nothing about
    whether THIS package's own use happened in the part of it before the
    cutoff or the part after, and truth's own first_seen_s is a
    DIFFERENT run's own clock entirely - directly comparing it to this
    run's own window_end would be comparing two unrelated clocks as if
    they were the same one.

    What IS portable across the two runs is truth's own
    operation_offsets_s (see attribute_evidence): how far past THAT
    SPECIFIC operation instance's own start this package was first used,
    on the truth run. Mapping that same offset onto THIS run's own
    matching instance gives a time on THIS run's own clock the
    truth-observed use would correspond to; only when that mapped
    instant falls at or before window_end, AND truth's own evidence
    separately shows the package is the kind that gets retained at all
    (an executed image or a shared library, see _could_persist_into_
    window, or an explicit later sighting of it still loaded,
    held_evidence - the offset alone says nothing about whether the use
    PERSISTED long enough to still matter, only where it started), does
    this count toward U. A missing offset, a straddling op with no
    matching measurement instance, or a mapped instant past window_end
    all leave this unconfirmed.

    For a periodic osops_ operation specifically, "THIS run's own
    matching instance" is never just "any instance sharing the same
    operation name" - it is the ONE SPECIFIC instance osops_pairing (see
    truth.py's own osops_pairing_info) says this package's own
    operation_instances id was actually paired with, by position in the
    two runs' own interleaved timelines. The offset is then taken from
    operation_instance_offsets_s (instance-keyed, not name-keyed) and
    applied only to that one paired instance's own start - never onto a
    different instance of the same name this run's own re-comparison
    happened to also record. A fixed (non-osops) operation has no such
    per-instance concept at all (compare_operations' own exact-sequence
    check already requires it to match entirely), so it keeps the
    plain, name-based offset/instance lookup. osops_pairing/
    measurement_intervals_raw being None (no fresh re-comparison
    available at all) falls back to that same name-based lookup for
    osops operations too, rather than refusing to confirm anything.

    unpaired_osops_ids (set of instance ids, or None - see
    _confirmable_via_completed_ops) further restricts even a NAME match
    in completed_ops: a periodic osops_ operation this package was used
    during is only trusted there when at least one of the SPECIFIC
    instances truth.py's own operation_instances ties this package's
    evidence to was actually verified by this run's own fresh
    operation-sequence re-comparison (truth.py's own osops_pairing), not
    merely left in whatever range one side's own sequence ran longer.

    A "used" truth entry is never reclassified into N here, only into X:
    an operation that is simply out of this run's own main-scope (too
    late, never recorded, confirmed only via an unverified osops
    instance, straddling with no persistence evidence, or straddling
    with a mapped instant this run cannot confirm falls at or before its
    own window_end) leaves the true answer unresolved for this specific
    run, not confirmed negative — and neither does an entry whose own
    timed evidence could not be placed at startup or against any
    operation at all (post-stop-only, or otherwise unattributed
    throughout truth.py's own attribution — see attribute_evidence): a
    real usage signal truth.py could not pin to a period is exactly the
    kind of unresolved case X exists for, not a confirmed non-use. N
    stays exactly truth's own confirmed-unused set.

    Returns "u_main" | "x_main".
    """
    if used_entry.get('used_at_startup'):
        return 'u_main'
    entry_ops = set(used_entry.get('used_during_operations') or [])
    non_osops_ops = {op for op in entry_ops if not str(op).startswith('osops_')}
    osops_ops = entry_ops - non_osops_ops

    # Fixed (non-periodic) operations: a single instance per name, so
    # the coarse NAME-level completed_ops set is exact - there is no
    # per-instance ambiguity a finer check could ever resolve
    # differently for one.
    if non_osops_ops & completed_ops:
        return 'u_main'

    osops_result = None
    if osops_ops:
        # NEVER confirmed by operation NAME alone, regardless of
        # whether the name appears in completed_ops or straddling_ops:
        # a periodic operation repeats, and a DIFFERENT instance of the
        # same name finishing cleanly before window_end says nothing
        # about the SPECIFIC instance(s) this package's own evidence is
        # actually tied to - see _osops_instance_membership, which
        # walks those specific instances one at a time.
        osops_result = _osops_instance_membership(used_entry, osops_pairing, measurement_intervals_raw, window_end)
        if osops_result is True:
            return 'u_main'

    # Fall through to the coarse, NAME-level path below only for a
    # fixed operation's own straddling instance (always exact), or for
    # an osops operation when NO fresh per-instance pairing information
    # was available at all (osops_result is None) - never when pairing
    # information existed and already gave every one of the package's
    # own checked instances a definitive negative (osops_result is
    # False): that negative answer is more specific than the coarse
    # name-based fallback could ever be, and must not be second-guessed
    # by it.
    straddling_here = non_osops_ops & straddling_ops
    if osops_ops and osops_result is None:
        straddling_here = straddling_here | (osops_ops & straddling_ops)
        if osops_ops & completed_ops and _confirmable_via_completed_ops(used_entry, osops_ops & completed_ops,
                                                                          unpaired_osops_ids):
            return 'u_main'

    if straddling_here:
        persistence_evidence = _could_persist_into_window(used_entry) or bool(used_entry.get('held_evidence'))
        if persistence_evidence and window_end is not None:
            offsets = used_entry.get('operation_offsets_s') or {}
            for op in straddling_here:
                offset = offsets.get(op)
                if offset is None:
                    continue
                for start, end in measurement_op_intervals.get(op, []):
                    if start is None or start > window_end or (end is not None and end <= window_end):
                        continue  # not the instance this run's own window closed in the middle of
                    if start + timedelta(seconds=offset) <= window_end:
                        return 'u_main'
    return 'x_main'


def _osops_instance_membership(used_entry, osops_pairing, measurement_intervals_raw, window_end):
    """True/False/None: whether at least one of this package's own
    periodic osops_ operation instances (used_entry's own
    operation_instances, truth-side ids) has a PAIRED measurement
    counterpart (via osops_pairing - see truth.py's own
    osops_pairing_info) confirming this package was used at or before
    window_end on THIS measurement run.

    Every one of the package's own checked instances is judged by that
    SPECIFIC instance's own [start, end] - never by whether the
    operation's own NAME appears in some pre-aggregated completed/
    straddling set, which can hide a straddling instance entirely
    behind a DIFFERENT, already-completed instance of the very same
    periodic operation (measurement_ops_completed_by/
    measurement_ops_straddling_only classify a NAME as "completed" the
    moment ANY one of its instances finishes in time, even while
    another instance of that same name is still straddling window_end -
    exactly the ambiguity a per-instance walk exists to resolve). A
    completed instance (fully finished at or before window_end)
    confirms unconditionally; a straddling instance (started at or
    before window_end, not yet finished) only confirms when truth's own
    evidence also shows the package is the kind that gets retained
    (_could_persist_into_window/held_evidence) and that instance's own
    id-specific offset (operation_instance_offsets_s) maps to at or
    before window_end.

    Returns True the moment any instance confirms; False when this
    package HAD operation_instances to check (osops_pairing was given
    and this entry recorded at least one) but none of them - whether
    because they resolved to a paired instance that simply did not
    confirm, or because NONE of them had a paired counterpart at all -
    ever confirmed in-window use; None only when there was nothing to
    check in the first place (no osops_pairing/measurement_intervals_raw
    given at all, or this entry carries no operation_instances of its
    own whatsoever - an older truth.json, say). The caller falls back
    to a coarser, name-based check ONLY in that True absence-of-
    information case - never merely because every one of this entry's
    own instances happened to be unpaired, which is itself a definite,
    checked answer (X), not an invitation to fall back to a less
    precise check that could paper over it with a different instance of
    the same operation NAME this package's own evidence has nothing to
    do with."""
    if not osops_pairing or window_end is None or measurement_intervals_raw is None:
        return None
    instances = used_entry.get('operation_instances') or []
    if not instances:
        return None
    persistence_evidence = _could_persist_into_window(used_entry) or bool(used_entry.get('held_evidence'))
    instance_offsets = used_entry.get('operation_instance_offsets_s') or {}
    for instance_id in instances:
        m_iv = _paired_measurement_instance_for(instance_id, osops_pairing, measurement_intervals_raw)
        if m_iv is None or not str(m_iv.get('op', '')).startswith('osops_'):
            # Not resolvable through this pairing info at all (a fixed
            # operation's own instance id mixed into the same list,
            # unpaired, or otherwise absent from it) - not a match, but
            # osops_pairing itself still stands, so this never falls
            # back to the coarser name-based path over it; it simply
            # does not confirm.
            continue
        start, end = m_iv.get('start'), m_iv.get('end')
        if start is None or start > window_end:
            continue  # this specific instance is out of main-scope entirely
        if end is not None and end <= window_end:
            return True
        if not persistence_evidence:
            continue
        offset = instance_offsets.get(instance_id)
        if offset is None:
            continue
        if start + timedelta(seconds=offset) <= window_end:
            return True
    return False


def measurement_ops_started_by(measurement_intervals, cutoff):
    """Operation names with at least one instance whose own start
    precedes or reaches cutoff (an operation THIS measurement run had
    already begun by then). Used to scope the main U to "from startup
    through the end of this run's own observation window" (see
    main_membership), rather than to every operation this run ever
    happened to reach regardless of how long after the window closed it
    started. Returns an empty set when cutoff is None (no window bound
    to scope against at all)."""
    names = set()
    if cutoff is None:
        return names
    for iv in measurement_intervals:
        if iv.get('start') is not None and iv['start'] <= cutoff:
            names.add(iv['op'])
    return names


def measurement_ops_completed_by(measurement_intervals, cutoff):
    """Operation names with at least one instance whose own start AND
    end both fall at or before cutoff - definitely over by the time
    this run's own observation window closed, with no ambiguity about
    which side of the cutoff any use during it fell on. Returns an
    empty set when cutoff is None."""
    names = set()
    if cutoff is None:
        return names
    for iv in measurement_intervals:
        start, end = iv.get('start'), iv.get('end')
        if start is not None and start <= cutoff and end is not None and end <= cutoff:
            names.add(iv['op'])
    return names


def measurement_ops_straddling_only(measurement_intervals, cutoff):
    """Operation names that started by cutoff (measurement_ops_started_by)
    but have no instance confirmed fully finished by then
    (measurement_ops_completed_by) - this run's own window closed in the
    middle of every instance it saw start in time, never before or after
    all of them. A name with at least one clean, fully-finished-by-cutoff
    instance is excluded here even if it also has other, still-running
    instances: that one clean instance is enough for
    measurement_ops_completed_by on its own."""
    started = measurement_ops_started_by(measurement_intervals, cutoff)
    completed = measurement_ops_completed_by(measurement_intervals, cutoff)
    return started - completed


def window_membership(used_entry, o_window, straddling_only_ops, measurement_seen_ops):
    """Whether one truth-used package belongs to U_window, X_window, or
    N_window.

    Startup use only counts toward U_window when it is the kind that
    could plausibly still be resident by the time the window opens (an
    executed image, still mapped for as long as the process that ran it
    keeps running, or a shared library reached the same way - see
    _could_persist_into_window): startup use is never added
    unconditionally, since a package merely opened once before the
    window and never touched again has no basis for being called
    "used within the window" specifically.

    Failing that, a package used during an operation this run's own
    window-scoped evidence confirms completed inside the window is
    U_window. An operation used during is only ever confirmed CLEAR of
    the window (contributing to a real N_window) when this run's own
    operations.jsonl recorded it unambiguously outside the window's own
    boundary - never straddling it, never simply absent. A package with
    even ONE ambiguous operation among the ones it was used during
    (seen only straddling the boundary, or never recorded by this run's
    own operations.jsonl at all) is left unresolved as a whole: X_window,
    never a confirmed N_window - the ambiguous operation alone could
    still have been the one where in-window use happened, regardless of
    how many of the package's other operations this run confirmed
    cleanly outside the window. N_window requires every operation the
    package was used during to be confirmed clear, with no ambiguity
    left anywhere. The same holds when there is no operation evidence to
    check at all (and startup use, if any, is not the persisting kind).

    Returns "u_window" | "x_window" | "n_window".
    """
    if used_entry.get('used_at_startup') and _could_persist_into_window(used_entry):
        return 'u_window'
    entry_ops = set(used_entry.get('used_during_operations') or [])
    if entry_ops & o_window:
        return 'u_window'
    if entry_ops:
        unrecorded = entry_ops - measurement_seen_ops
        ambiguous = entry_ops & (straddling_only_ops | unrecorded)
        if ambiguous:
            return 'x_window'
        # Every operation this package was used during is recorded by
        # this run and confirmed clear of the window boundary (neither
        # straddling it nor missing) - a genuine, unambiguous "not used
        # within this window" result.
        return 'n_window'
    return 'x_window'


# --- short-lived-subject determination from the measurement run's own
# confirmations (never from truth's own subject labels) --------------------

def _events_by_pid_starttime_path(run, container_id):
    """{(pid, starttime, path): comm-or-path} from this run's own
    events.jsonl, restricted to this container's successful, resolved
    exec/open events - the fallback source short_lived_subject_from_
    confirmations uses only when a specific confirmation carries no
    usable process identity of its own. For an "exec" event the acting
    process's own image IS the observed path; for an "open" event this
    prefers a "comm" field when the event carries one, and falls back to
    the observed path itself otherwise (still useful when the opening
    process's own name happens to match one of the short-lived commands,
    though a plain open's own path is normally the file being read, not
    the reader)."""
    path = f'{run}/events.jsonl'
    index = {}
    if not os.path.exists(path):
        return index
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get('record') != 'event' or not rec.get('ok'):
                continue
            if rec.get('event') not in ('exec', 'open'):
                continue
            if container_id and rec.get('container_id') != container_id:
                continue
            p = rec.get('resolved') or rec.get('path')
            if not p:
                continue
            key = (rec.get('pid'), rec.get('starttime'), p)
            subject_hint = p if rec.get('event') == 'exec' else (rec.get('comm') or p)
            index[key] = subject_hint
    return index


def _confirmation_subject_is_short_lived(c, events_index):
    """Whether one confirmation's own acting process names a short-lived
    command (curl/git/openssl), resolved from the confirmation itself
    (an "exec" confirmation's own path IS the acting process's image)
    or, failing that, this run's own events.jsonl by pid/starttime/path
    - never guessed at when neither resolves a subject at all."""
    if c.get('source') == 'event_exec':
        return os.path.basename(c.get('path') or '') in SHORT_LIVED_COMMAND_BASENAMES
    gen = c.get('process_generation') or {}
    pid = gen.get('pid')
    if not pid:
        return False
    hint = events_index.get((pid, gen.get('starttime'), c.get('path')))
    return bool(hint) and os.path.basename(hint) in SHORT_LIVED_COMMAND_BASENAMES


def _sample_confirmation_subject_is_short_lived(c, sample_process_index):
    """Whether one sampling-sourced (P) confirmation's own subject - the
    specific process THIS run's own periodic sample actually found
    holding the confirmed path open or mapped - names a short-lived
    command (curl/git/openssl). A sampling-sourced Confirmation never
    carries its own process_generation at all (see series.go's own
    sourceSampling handling: only Source/Path/Verb/Grain/SampleID/
    ObservedAt/Ecosystem/ContainerID are ever set for it), so the acting
    process has to be found the only other way available: cross-
    referencing the confirmation's own (sample_id, path) against that
    same sample's own raw process list (sample_process_index). This is
    never guessed at from the confirmed PACKAGE's own name: a shared
    library like libssl3 is mapped by many different processes at once
    (a long-lived server AND a short-lived curl invocation might both
    have it mapped in the very same sample), and the package's own name
    says nothing about which of them this specific confirmation is
    actually about."""
    sample_id = c.get('sample_id')
    path = c.get('path')
    if not sample_id or not path:
        return False
    exes = sample_process_index.get((sample_id, path)) or set()
    return any(exe in SHORT_LIVED_COMMAND_BASENAMES for exe in exes)


def short_lived_subject_from_sampling(pv, sample_process_index):
    """Whether this PackageVerdict carries at least one sampling-sourced
    (P) confirmation whose own subject - resolved via
    sample_process_index, never via the confirmed package's own name -
    is a short-lived command."""
    return any(c.get('source') == 'sampling'
               and _sample_confirmation_subject_is_short_lived(c, sample_process_index)
               for c in pv.get('confirmations') or [])


def short_lived_subject_from_confirmations(pv, events_index):
    """Whether this PackageVerdict carries at least one S2 confirmation
    (source event_exec/event_open) whose own acting process names a
    short-lived command (curl/git/openssl) - determined from THIS
    measurement run's own confirmations and, only when a confirmation's
    own process_generation carries no usable pid, this run's own
    events.jsonl. Never reads truth's own subject labels: those describe
    the separate strace-only truth run, not what this measurement run's
    own evidence independently shows."""
    return any(c.get('source') in ('event_exec', 'event_open')
               and _confirmation_subject_is_short_lived(c, events_index)
               for c in pv.get('confirmations') or [])


def short_lived_subject_for_series(pv, series, events_index, is_s0_confirmed, sample_process_index):
    """The short-lived-subject-confirmed determination, CUMULATIVE
    across series the same way each series' own confirmed set itself
    accumulates evidence: S0 = P, S1 = P ∪ A, S2 = P ∪ A ∪ E. A package
    this run's own S0 (sampling alone) already confirmed as a
    short-lived subject does not stop being P-confirmed once S1/S2 add
    more evidence on top of it - it is never re-derived or reset
    per-series, only ever added to.

    P (S0, sampling alone): resolved from the SUBJECT a sampling
    confirmation actually came from (see short_lived_subject_from_
    sampling/sample_process_index) - never from the confirmed package's
    own name. A short-lived OS package (curl/git/openssl) happens to
    resolve correctly this way too (the confirming sample's own process
    for a "curl" package confirmation IS the curl process itself), but
    a shared library like libssl3 - mapped by many different processes
    at once, some short-lived and some not - could never be told apart
    by name at all: only knowing which specific process a specific
    sampling confirmation actually came from can. is_s0_confirmed
    (whether THIS key is actually in the S0 series' own confirmed set -
    the caller's to know) still gates this: a key never confirmed at S0
    at all must not be credited with P just because pv happens to carry
    a stray sampling confirmation for some other version or context.

    A (S1's own addition on top of P): counted from confirmations whose
    own source is neither "sampling" nor an event source, resolved to a
    short-lived subject by the same pid-based subject resolution S2 uses
    (source A confirmations, e.g. os_package_path_index, carry a real
    process_generation, unlike sampling's own confirmations). A
    confirmation whose own subject cannot be resolved this way
    contributes nothing, per the design's own "主体が分からなければ加え
    ない" rule.

    E (S2's own addition on top of P ∪ A): every event-sourced
    confirmation (see short_lived_subject_from_confirmations).
    """
    if is_s0_confirmed and short_lived_subject_from_sampling(pv, sample_process_index):
        return True
    if series == 'S0':
        return False
    if any(c.get('source') not in ('sampling', 'event_exec', 'event_open')
           and _confirmation_subject_is_short_lived(c, events_index)
           for c in pv.get('confirmations') or []):
        return True
    if series == 'S1':
        return False
    return short_lived_subject_from_confirmations(pv, events_index)


# --- coverage computation --------------------------------------------------

# The two exact reason strings truth.py's own main() ever attaches to
# an X candidate for the operations-comparison gap specifically (see
# truth.py's own completeness_reasons) - matched, never regenerated, so
# _blocked_only_by_operations recognizes exactly these two forms and no
# other completeness gap's own wording.
_OPERATIONS_REASON_MARKERS = (
    'no measurement run was given to compare',
    "does not match the measurement run's",
)


def _blocked_only_by_operations(entry):
    """Whether entry's own 'reasons' (as truth.py itself attached to
    every X candidate when its own completeness gate failed) name
    NOTHING but the operations-comparison gap. A candidate with even one
    OTHER completeness gap listed alongside it (an empty trace file,
    unreconstructed syscalls, an unresolved path, a broken symlink
    chain, ...) is never restored here, no matter how this run's own
    fresh operations re-comparison turns out - only the operations-
    specific blocker is ever lifted, never the others. An entry with no
    'reasons' at all (truth.py's own completeness gate never blocked it
    to begin with) is not "blocked only by operations" either - there is
    nothing to restore."""
    reasons = entry.get('reasons') or []
    if not reasons:
        return False
    return all(any(marker in r for marker in _OPERATIONS_REASON_MARKERS) for r in reasons)


def restore_unused_after_recomparison(truth):
    """truth's own (unused, unknown) lists, adjusted for THIS run's own
    fresh operations re-comparison - already confirmed consistent by the
    time compute() is ever reached at all (see check_operations_
    consistent and main()'s own HOLD gate, which never calls compute()
    otherwise): an 'unknown' (X) candidate truth.py itself could only
    certify as unused pending an operations comparison it never had the
    chance to perform standalone (or once found inconsistent against
    some OTHER measurement run at truth.py's own build time) is promoted
    back to 'unused' (N) here, since THIS run's own fresh comparison has
    since succeeded where truth.json's own saved verdict cannot be
    trusted for this purpose at all (see check_operations_consistent).

    Returns (unused: list, unknown: list) - copies of truth's own lists,
    with every candidate _blocked_only_by_operations moved from the
    second into the first (its own now-resolved 'reasons' dropped)."""
    unused = list(truth.get('unused') or [])
    unknown = []
    for entry in truth.get('unknown') or []:
        if _blocked_only_by_operations(entry):
            restored = dict(entry)
            restored.pop('reasons', None)
            unused.append(restored)
        else:
            unknown.append(entry)
    return unused, unknown


def compute(run, match_json, truth, variant, ops_result=None):
    used_map = truth_used_map(truth)
    restored_unused, restored_unknown = restore_unused_after_recomparison(truth)
    unused_map = {(u['ecosystem'], u['name'], u['version']): u for u in restored_unused}
    unknown_map = {(u['ecosystem'], u['name'], u['version']): u for u in restored_unknown}
    # Which of truth's own osops instances this run's own fresh
    # operation-sequence re-comparison actually left unverified (see
    # truth.py's own osops_pairing/_confirmable_via_completed_ops) -
    # None when ops_result was not given at all (compute() called
    # directly without one), which main_membership reads as "nothing to
    # restrict on", not as "everything is unpaired".
    unpaired_osops_ids = None
    osops_pairing = None
    if ops_result:
        osops_pairing = ops_result.get('osops_pairing')
        unpaired_osops_ids = set((osops_pairing or {}).get('unpaired_truth_osops_ids') or [])
    confirmed_sets, present = build_confirmed_sets(match_json) if match_json else ({s: {} for s in SERIES}, {})

    categories = sorted({c for e in used_map.values() for c in categories_for_used(e)}
                         | {c for e in unused_map.values() for c in categories_for_unused(e)}
                         | {c for e in unknown_map.values() for c in categories_for_unknown(e)})

    # Identification misconfirmations: a confirmed (ecosystem, name,
    # version) outside I = U ∪ N ∪ X entirely - the bundled-inventory
    # ledger truth.py itself built, not just its used/unused halves. A
    # confirmed key that IS in I, just in X (truth could not certify use
    # or non-use for it), is a different outcome: this run confirmed
    # something the ledger cannot yet call used or unused, not something
    # the ledger never heard of at all. That is reported separately as
    # "confirmed_in_x" (the design's own "正解不明への確認数") and never
    # folded into identification misconfirmations, which are reserved
    # for a key I itself has no record of whatsoever.
    #
    # A same-name entry at a different version, when one exists, is
    # noted (likely a version-string formatting difference between Trivy
    # and this run's own extraction) without being folded into ordinary
    # TP/FP/FN: this tool does not have a live scan to confirm the two
    # sides format versions identically, so it surfaces the difference
    # rather than silently equating or discarding it.
    ledger_keys = set(used_map) | set(unused_map) | set(unknown_map)
    known_names = {(e, n) for (e, n, _v) in ledger_keys}
    identification_by_series = {s: [] for s in SERIES}
    confirmed_in_x_by_series = {s: [] for s in SERIES}
    for series in SERIES:
        for key in confirmed_sets[series]:
            if key in unknown_map:
                confirmed_in_x_by_series[series].append(
                    {'ecosystem': key[0], 'name': key[1], 'version': key[2]})
                continue
            if key in ledger_keys:
                continue
            eco, name, version = key
            entry = {'ecosystem': eco, 'name': name, 'version': version}
            if (eco, name) in known_names:
                entry['note'] = 'a different version of this name is in the bundled inventory'
            identification_by_series[series].append(entry)

    window_start, window_end = read_window_bounds(run)
    fired_at = truth_lib.read_instant_file(f'{run}/fired_at.txt')
    window_start_rel = (window_start - fired_at).total_seconds() if window_start and fired_at else None
    window_end_rel = (window_end - fired_at).total_seconds() if window_end and fired_at else None
    container_id = read_container_id(run)
    captured_paths = read_event_capture(run, container_id, window_start, window_end)
    events_index = _events_by_pid_starttime_path(run, container_id)
    sample_process_index = read_sample_process_index(run)
    failures = read_failures(match_json)
    event_state, has_event_drops = read_event_state(match_json)
    interval_seconds = read_sampling_interval_seconds(match_json)
    identified_loss_window = None
    if has_event_drops:
        identified_loss_window = find_event_gap(run, container_id, window_start, window_end)

    case_id = truth.get('case_id')
    measurement_intervals = read_measurement_operation_intervals(run, case_id) if case_id else []
    measurement_op_intervals = {}
    for iv in measurement_intervals:
        if iv.get('start') is not None and iv.get('end') is not None:
            measurement_op_intervals.setdefault(iv['op'], []).append((iv['start'], iv['end']))
    sample_times = read_sample_times(run)
    events_by_pid = read_events_by_pid_starttime(run, container_id)
    base_ctx = {
        'window_start_rel': window_start_rel, 'window_end_rel': window_end_rel,
        'captured_paths': captured_paths, 'failures': failures,
        'has_event_drops': has_event_drops, 'interval_seconds': interval_seconds,
        'identified_loss_window': identified_loss_window,
        'measurement_op_intervals': measurement_op_intervals,
        'measurement_intervals_raw': measurement_intervals,
        'sample_times': sample_times,
        'events_by_pid': events_by_pid,
    }

    o_window, straddling_only_ops, measurement_seen_ops = build_window_operation_sets(
        measurement_intervals, window_start, window_end)
    window_available = bool(measurement_intervals) and window_start is not None and window_end is not None
    # The main scope is "from startup through the end of this run's own
    # observation window" (see main_membership/measurement_ops_started_by),
    # so it needs window_end the same way the window figure needs both
    # bounds - not merely "this run recorded some operations at all".
    main_scoping_available = bool(measurement_intervals) and window_end is not None
    measurement_ops_by_window_end = measurement_ops_started_by(measurement_intervals, window_end)
    measurement_ops_completed_by_window_end = measurement_ops_completed_by(measurement_intervals, window_end)
    measurement_ops_straddling_window_end = measurement_ops_straddling_only(measurement_intervals, window_end)
    all_used_ops = {op for e in used_map.values() for op in (e.get('used_during_operations') or [])}
    excluded_ops = sorted(straddling_only_ops | (all_used_ops - measurement_seen_ops))

    by_category = {}
    for cat in categories:
        # cat_used_all/cat_unused_truth/cat_unknown_truth are truth's own
        # whole-truth-run sets, filtered to this category - the
        # candidate population both the primary (main-scoped) and the
        # auxiliary window figure are carved out of.
        cat_used_all = {k: e for k, e in used_map.items() if cat in categories_for_used(e)}
        cat_unused_truth = {k: e for k, e in unused_map.items() if cat in categories_for_unused(e)}
        cat_unknown_truth = {k: e for k, e in unknown_map.items() if cat in categories_for_unknown(e)}

        # The primary U/X: scored against what THIS measurement run's own
        # operations.jsonl shows already under way by the end of its own
        # window, not the (possibly longer, possibly differently
        # scheduled) truth run's own full life span - see
        # main_membership. N is always exactly truth's own confirmed-
        # unused set: a "used" truth entry excluded from U this way is
        # never turned into a confirmed negative, only into X. Falls
        # back to truth's own raw used set when this measurement run
        # carries no operations.jsonl/window bound to scope against at
        # all (a case other than 26-28, or a fixture with no such log),
        # so a truth.json without the per-operation fields this scoring
        # needs still scores exactly as it always did.
        if main_scoping_available:
            cat_used, cat_x_main = {}, {}
            for k, e in cat_used_all.items():
                if main_membership(e, measurement_ops_completed_by_window_end,
                                    measurement_ops_straddling_window_end,
                                    measurement_op_intervals, window_end,
                                    unpaired_osops_ids, osops_pairing, measurement_intervals) == 'u_main':
                    cat_used[k] = e
                else:
                    cat_x_main[k] = e
            cat_unused = dict(cat_unused_truth)
            cat_unknown_for_main = dict(cat_unknown_truth)
            cat_unknown_for_main.update(cat_x_main)
        else:
            cat_used = cat_used_all
            cat_unused = cat_unused_truth
            cat_unknown_for_main = cat_unknown_truth
        row = {'category': cat, 'used_count': len(cat_used), 'unused_count': len(cat_unused),
               'x_main_count': len(cat_unknown_for_main), 'series': {}}

        window_sets = None
        if window_available:
            u_window, x_window, n_window_extra = set(), set(), set()
            for k, e in cat_used_all.items():
                membership = window_membership(e, o_window, straddling_only_ops, measurement_seen_ops)
                if membership == 'u_window':
                    u_window.add(k)
                elif membership == 'x_window':
                    x_window.add(k)
                else:
                    n_window_extra.add(k)
            x_window |= set(cat_unknown_truth)
            n_window = set(cat_unused_truth) | n_window_extra
            window_sets = {'u_window': u_window, 'x_window': x_window, 'n_window': n_window}

        for series in SERIES:
            c_s = confirmed_sets[series]
            tp_keys = [k for k in cat_used if k in c_s]
            fn_keys = [k for k in cat_used if k not in c_s]
            fp_keys = [k for k in cat_unused if k in c_s]
            tn_keys = [k for k in cat_unused if k not in c_s]
            recall = (len(tp_keys) / len(cat_used)) if cat_used else None
            fpr = (len(fp_keys) / len(cat_unused)) if cat_unused else None
            x_main_confirmed = sum(1 for k in cat_unknown_for_main if k in c_s)
            misses = []
            cause_counts = {}
            for k in fn_keys:
                cause, detail, tags = classify_miss(k, used_map[k], present.get(k), series, base_ctx)
                misses.append({'ecosystem': k[0], 'name': k[1], 'version': k[2],
                                'cause': cause, 'detail': detail, 'tags': tags})
                cause_counts[cause] = cause_counts.get(cause, 0) + 1
            direct_short_lived = None
            if cat == 'short_lived_os':
                # The short-lived-subject-confirmed count is built from
                # THIS measurement run's own confirmations, never from
                # truth's own subject labels, and is CUMULATIVE across
                # series the same way each series' own confirmed set
                # itself accumulates evidence (see
                # short_lived_subject_for_series): S0 = P, S1 = P ∪ A,
                # S2 = P ∪ A ∪ E. It is an auxiliary count restricted to
                # true positives, and never substitutes for the
                # category's own TP above.
                direct_short_lived = sum(
                    1 for k in tp_keys
                    if k in present and short_lived_subject_for_series(
                        present[k], series, events_index, k in confirmed_sets['S0'], sample_process_index)
                )
            series_row = {
                'tp': len(tp_keys), 'fn': len(fn_keys), 'fp': len(fp_keys), 'tn': len(tn_keys),
                'recall': recall, 'fpr': fpr,
                'misses': misses,
                'miss_cause_counts': cause_counts,
                'false_positives': [{'ecosystem': k[0], 'name': k[1], 'version': k[2]} for k in fp_keys],
                'short_lived_direct_confirmations': direct_short_lived,
                'x_main_confirmed': x_main_confirmed,
                'window': None,
            }
            assert sum(cause_counts.values()) == len(fn_keys), \
                f'{cat}/{series}: miss-cause total {sum(cause_counts.values())} != FN {len(fn_keys)}'
            if window_sets is not None:
                u_w, x_w, n_w = window_sets['u_window'], window_sets['x_window'], window_sets['n_window']
                tp_w = [k for k in u_w if k in c_s]
                fn_w = [k for k in u_w if k not in c_s]
                fp_w = [k for k in n_w if k in c_s]
                tn_w = [k for k in n_w if k not in c_s]
                x_w_confirmed = [k for k in x_w if k in c_s]
                series_row['window'] = {
                    'u_window': len(u_w), 'n_window': len(n_w), 'x_window': len(x_w),
                    'tp': len(tp_w), 'fn': len(fn_w), 'fp': len(fp_w), 'tn': len(tn_w),
                    'recall': (len(tp_w) / len(u_w)) if u_w else None,
                    'fpr': (len(fp_w) / len(n_w)) if n_w else None,
                    'confirmed_in_x_window': len(x_w_confirmed),
                }
            row['series'][series] = series_row
        by_category[cat] = row

    return {
        'variant': variant,
        'categories': by_category,
        'identification_misconfirmations': identification_by_series,
        'confirmed_in_x': confirmed_in_x_by_series,
        'inventory_size': truth.get('inventory_size'),
        # THIS run's own FRESH re-comparison result (see
        # check_operations_consistent), never truth.json's own saved
        # operation_consistency - which describes whatever measurement
        # run truth.py itself happened to be pointed at when it was
        # built (often none at all, or a self-comparison performed only
        # to unlock N during verification), not necessarily this one.
        # ops_result is None only when compute() was called directly
        # without one (e.g. a unit test exercising compute() on its
        # own, bypassing main()'s own HOLD gate and re-comparison).
        'operation_consistency': ops_result,
        'window_start_rel_s': window_start_rel,
        'window_end_rel_s': window_end_rel,
        'interval_seconds': interval_seconds,
        'event_state': event_state,
        'main_scoping': {
            'available': main_scoping_available,
            'measurement_operations_seen': sorted(measurement_seen_ops),
            'measurement_operations_by_window_end': sorted(measurement_ops_by_window_end),
        },
        'window_scoped': {
            'available': window_available,
            'operations_in_window': sorted(o_window),
            'operations_excluded': excluded_ops,
        },
    }


def render_markdown(case_id, results):
    lines = [f'# Coverage report: case {case_id}', '']
    op = results['all'].get('operation_consistency') or {}
    if op.get('checked'):
        state = 'consistent' if op.get('consistent') else 'INCONSISTENT'
        lines.append(f'- Operation-sequence check against `{op.get("measurement_run")}`: **{state}** ({op.get("detail")})')
    else:
        lines.append('- Operation-sequence check: not performed (no measurement run given to truth.py)')
    lines.append('')
    for variant in ('all', 'hc'):
        r = results[variant]
        lines.append(f'## {variant.upper()} scan')
        lines.append('')
        def _fmt(v):
            return 'N/A' if v is None else f'{v}s'
        lines.append(f'- window: {_fmt(r["window_start_rel_s"])} to {_fmt(r["window_end_rel_s"])} relative to firing; '
                      f'interval {_fmt(r["interval_seconds"])}; event_state={r["event_state"]}')
        ws = r.get('window_scoped') or {}
        if ws.get('available'):
            lines.append(f'- window-scoped operations O_window: {", ".join(ws["operations_in_window"]) or "(none)"}')
            if ws.get('operations_excluded'):
                lines.append(f'- operations excluded from window scoring (straddling or unrecorded): '
                              f'{", ".join(ws["operations_excluded"])}')
        else:
            lines.append('- window-scoped scoring: not available (no measurement operations.jsonl for this run)')
        lines.append('')
        lines.append('| category | series | used | TP | FN | recall | unused | FP | TN | FPR | window recall | window FPR |')
        lines.append('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
        for cat, row in sorted(r['categories'].items()):
            for series in SERIES:
                s = row['series'][series]
                recall = f'{s["recall"]:.0%}' if s['recall'] is not None else 'N/A'
                fpr = f'{s["fpr"]:.0%}' if s['fpr'] is not None else 'N/A'
                w = s.get('window')
                w_recall = f'{w["recall"]:.0%}' if w and w['recall'] is not None else 'N/A'
                w_fpr = f'{w["fpr"]:.0%}' if w and w['fpr'] is not None else 'N/A'
                lines.append(f'| {cat} | {series} | {row["used_count"]} | {s["tp"]} | {s["fn"]} | {recall} '
                              f'| {row["unused_count"]} | {s["fp"]} | {s["tn"]} | {fpr} | {w_recall} | {w_fpr} |')
        lines.append('')
        idmis = r['identification_misconfirmations']
        total_idmis = sum(len(v) for v in idmis.values())
        if total_idmis:
            lines.append(f'- Identification misconfirmations (confirmed but at no version in the bundled inventory): {total_idmis}')
            for series in SERIES:
                for e in idmis[series]:
                    note = f' ({e["note"]})' if 'note' in e else ''
                    lines.append(f'  - {series}: {e["ecosystem"]}/{e["name"]}@{e["version"]}{note}')
        else:
            lines.append('- Identification misconfirmations: none')
        lines.append('')
        lines.append('### Misses (S2)')
        lines.append('')
        lines.append('| category | package | cause | tags | detail |')
        lines.append('| --- | --- | --- | --- | --- |')
        for cat, row in sorted(r['categories'].items()):
            for m in row['series']['S2']['misses']:
                lines.append(f'| {cat} | {m["ecosystem"]}/{m["name"]}@{m["version"]} | {m["cause"]} | '
                              f'{",".join(m["tags"]) or "-"} | {m["detail"]} |')
        lines.append('')
    return '\n'.join(lines) + '\n'


def check_same_image(run, truth):
    """Whether the measurement run and the truth run this truth.json came
    from used the exact same image ID. A measurement run scored against
    ground truth for a different image would score real packages against
    an inventory and used/unused set that describes a different set of
    bytes entirely - not a smaller shortfall in evidence, but a comparison
    of two unrelated things. Returns (True, "") when they match, or
    (False, reason) when they do not or either side's image ID is
    unavailable to compare at all."""
    measurement_image_path = f'{run}/image_id.txt'
    if not os.path.exists(measurement_image_path):
        return False, f'{measurement_image_path} does not exist; the measurement run\'s own image ID cannot be confirmed'
    measurement_image = open(measurement_image_path).read().strip()
    truth_image = truth.get('image_id')
    if not truth_image:
        return False, 'truth.json carries no image_id at all'
    if measurement_image != truth_image:
        return False, f'measurement run image_id {measurement_image!r} != truth run image_id {truth_image!r}'
    return True, ''


def check_operations_consistent(run, truth):
    """Whether THIS measurement run's own firing procedure
    (operations.jsonl, runtime-modules.jsonl, and image_id.txt) is
    actually consistent with the truth run this truth.json came from -
    the second precondition for scoring at all, alongside
    check_same_image. N (confirmed-unused) is only ever certified by
    truth.py once it has compared a truth run's own firing procedure
    against an actual measurement run and found the two consistent, but
    a truth.json's own SAVED operation_consistency/completeness.
    operations only ever reflects whichever measurement run truth.py
    itself happened to be pointed at when it was built (often none at
    all, or the truth run's own logs compared against themselves purely
    to unlock N during verification) - never necessarily THIS one.
    Trusting that saved verdict here would let a truth.json that once
    compared clean against an unrelated (or self-identical) run pass
    silently for every other run it is ever pointed at afterward.

    This function never reads that saved verdict for its own decision:
    it re-opens the truth run's own varlog fresh off disk (via
    truth_run_dir, which truth.py records as an absolute path) and
    re-runs truth.py's own comparison (compare_measurement_run) against
    THIS run's own directory, every time. The image_id match alone
    (check_same_image) does not catch a difference here either, since
    both runs can share an image while the firing procedure they each
    executed against it still differs.

    Returns (ok: bool, reason: str, result: dict|None): result is
    EXACTLY what this fresh truth_lib.compare_measurement_run call just
    produced (checked/measurement_run/consistent/detail/...) - what a
    caller should report as THIS run's own operation_consistency (see
    compute()'s own 'operation_consistency' output field), never
    truth.json's own saved value, which describes some other (or no)
    comparison entirely. result is None when the comparison could not
    even be attempted at all (no truth_run_dir recorded, or its own
    operations.jsonl is missing)."""
    truth_run_dir = truth.get('truth_run_dir')
    if not truth_run_dir:
        return (False, 'truth.json does not record its own truth run directory (truth_run_dir) to re-compare against',
                None)
    varlog = f'{truth_run_dir}/varlog'
    truth_ops_path = f'{varlog}/operations.jsonl'
    if not os.path.isdir(truth_run_dir):
        return False, f'truth run directory {truth_run_dir!r} no longer exists on disk to re-compare against', None
    if not os.path.exists(truth_ops_path):
        return (False, f'{truth_ops_path} does not exist; this truth run\'s own firing procedure cannot be re-read',
                None)
    truth_op_records = truth_lib.read_operation_records(truth_ops_path)
    result = truth_lib.compare_measurement_run(varlog, run, truth_op_records, truth.get('image_id'))
    if result.get('consistent') is True:
        return True, '', result
    return False, (result.get('detail')
                    or 'a fresh operation-sequence re-comparison against this measurement run failed'), result


def main():
    if len(sys.argv) != 3:
        print('Usage: coverage.py <run dir> <truth.json>', file=sys.stderr)
        return 2
    run = sys.argv[1].rstrip('/')
    truth = json.load(open(sys.argv[2]))

    same_image, image_hold_reason = check_same_image(run, truth)
    ops_consistent, ops_hold_reason, ops_result = check_operations_consistent(run, truth)
    if not same_image or not ops_consistent:
        reasons = []
        if not same_image:
            reasons.append(f'measurement run and truth run do not share an image ID: {image_hold_reason}')
        if not ops_consistent:
            reasons.append(ops_hold_reason)
        hold = {
            'hold': True,
            'hold_reason': '; '.join(reasons),
        }
        with open(f'{run}/coverage.json', 'w') as f:
            json.dump(hold, f, indent=1)
        with open(f'{run}/coverage.md', 'w') as f:
            f.write(f'# Coverage report: HOLD\n\n- {hold["hold_reason"]}\n'
                     '- No recall/false-positive figures were computed: scoring this run against this truth.json '
                     'without both preconditions met would compare real packages against a ground truth this tool '
                     'cannot yet trust for this run.\n')
        print(f'{run}: HOLD - {hold["hold_reason"]}', file=sys.stderr)
        return 0

    results = {}
    for variant in ('hc', 'all'):
        match_json = load_match(run, variant)
        if match_json is None:
            print(f'{run}: no match_{variant}.json; scoring against an empty confirmed set', file=sys.stderr)
            match_json = {'packages': []}
        results[variant] = compute(run, match_json, truth, variant, ops_result)

    with open(f'{run}/coverage.json', 'w') as f:
        json.dump(results, f, indent=1)
    with open(f'{run}/coverage.md', 'w') as f:
        f.write(render_markdown(truth.get('case_id', '?'), results))
    for variant in ('hc', 'all'):
        for cat, row in sorted(results[variant]['categories'].items()):
            s2 = row['series']['S2']
            recall = f'{s2["recall"]:.0%}' if s2['recall'] is not None else 'N/A'
            print(f'{run} [{variant}] {cat}: S2 recall={recall} FP={s2["fp"]} FN={s2["fn"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
