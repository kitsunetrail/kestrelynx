#!/usr/bin/env python3
"""Builds independent ground truth for one coverage-validation case (26,
27, or 28) from a tools/truth-run.sh output directory.

Usage: truth.py <truth run dir> <case json> [measurement run dir]
Reads:
  <truth run dir>/image_id.txt, container_id.txt, fired_at.txt, stopped_at.txt
  <truth run dir>/varlog/{usage,occurrences,operations,runtime-modules}.jsonl
  <truth run dir>/varlog/strace/trace.*
Writes: <truth run dir>/truth.json

Ownership resolution (OS package DB, Python RECORD, Node package.json,
jar pom.properties) is the same code gtb.py uses for measurement-run
GT-B, imported from it rather than duplicated, so a common resolution
mistake shows up in both places rather than only in the one that got
fixed. Unlike gtb.py's usage-log-driven GT-B, this tool also builds the
full bundled-package inventory (I) directly from the image, independent
of any log: every OS-database package, every Python distribution under
any placement this run's own filesystem walk finds (not a fixed
candidate list of conventional site-packages paths), every package.json
this run can read a name and version from anywhere in the image (not
only ones inside a node_modules directory, and not excluding Node's own
bundled npm/corepack tooling either — matching what a Trivy
--list-all-pkgs scan of the same image lists for its own node-pkg
population, since I is meant to be that same bundled-package population,
not this tool's own guess at which of those a running workload could
ever load), and every jar anywhere in the image (not only the
application's own directory).

Every inventory and used/unused key is the three-part (ecosystem, name,
version) rather than name alone, because a nested node_modules tree can
legitimately bundle two different versions of the same package at once
(npm nests a second copy where an inner dependency needs a version that
conflicts with the one already hoisted to the top); a name-only key would
merge a used copy and an unused one into a single, wrongly-labeled
outcome. The same applies to Python: two different site-packages
placements (a venv and a system install, say) can each bundle their own
version of the same-named distribution, kept apart per placement rather
than merged into one name-keyed table. A used path resolved to a package
whose specific version this run cannot read (an unreadable jar manifest,
say) is kept out of the ordinary used set and reported separately as
version-unknown instead of being silently dropped or guessed at.

When strace's own per-line time (-tt) and this run's own firing instant
(ready_at.txt/fired_at.txt) are both available, each used package also
carries when its evidence was first and last seen, relative to firing,
and — for the short-lived operational commands specifically — the
shortest exec-to-exit duration usage.jsonl recorded for it; coverage.py
uses these to tell a package that was simply never in the window from one
that was, but too briefly for a periodic sample to catch. Each used
package also carries whether it was used before the firing signal at all
(used_at_startup) and the set of named operations (from operations.jsonl)
during which it was used (used_during_operations), attributed from the
same timed evidence against each operation's own reconstructed
[start, end] span; coverage.py uses these two fields, together with a
measurement run's own operations.jsonl, to score recall against what
completed within that run's own observation window specifically, rather
than against this truth run's full life span.

A short-lived operational command's own children/threads that never exec
anything of their own (a certificate-loading helper curl spawns, say)
still belong to the short-lived subject: subject classification walks the
process tree strace's own clone/fork/vfork/clone3 records reconstruct,
inheriting a newly created process's starting subject from whichever one
its parent was at the moment it was created, rather than starting every
trace file over at "resident" and waiting for its own exec.

If a measurement run directory is given, this also compares that run's
own /var/log/operations.jsonl (copied out by cases/run.sh dump-logs)
against this truth run's operations.jsonl: the two runs are expected to
carry out the same firing procedure — the same named operations in the
same order — since they use the same image; a mismatch means the runs
are not commensurable and coverage.py must not score them against each
other as though they were.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gtb

# --- time parsing ---------------------------------------------------------

def parse_iso_utc(s):
    """Parses one of this harness's own RFC3339 timestamps (a fractional
    part of any length, in UTC or with a numeric offset) into an aware UTC
    datetime. Python's own fromisoformat only accepts a fractional part of
    up to six digits, so a longer one (this harness usually writes
    nanoseconds) is trimmed to microseconds rather than rejected. A
    numeric offset (an observation record written by a process whose local
    zone was not UTC) is honoured, never dropped: the instant is converted
    to UTC. A timestamp with no zone at all is taken as UTC."""
    s = s.strip()
    offset = None
    if s.endswith('Z'):
        s = s[:-1]
    else:
        # Only the RFC3339 form "+HH:MM"/"-HH:MM" is a zone offset here.
        # A trailing "+HHMM" is not accepted as one: the fractional part
        # and a date-only stem could both end in digits, so it is refused
        # outright rather than silently read as UTC.
        m = re.search(r'([+-])(\d{2}):(\d{2})$', s)
        if m and len(s) > 19 and 'T' in s:
            sign = 1 if m.group(1) == '+' else -1
            offset = timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
            s = s[:m.start()]
        elif re.search(r'[+-]\d{4}$', s) and 'T' in s:
            raise ValueError(f'unsupported zone offset form in timestamp {s!r}; use +HH:MM or Z')
    if '.' in s:
        head, frac = s.split('.', 1)
        frac = (frac + '000000')[:6]
        s = f'{head}.{frac}'
    dt = datetime.fromisoformat(s).replace(tzinfo=offset or timezone.utc)
    return dt.astimezone(timezone.utc)


def read_instant_file(path):
    """The single RFC3339 instant a ready_at.txt/fired_at.txt/stopped_at.txt
    file holds, or None when the file is missing or empty (an older run
    that predates it)."""
    if not os.path.exists(path):
        return None
    text = open(path, encoding='utf-8').read().strip()
    return parse_iso_utc(text) if text else None


def strace_time_of_day_to_datetime(time_of_day, reference_date):
    """Combines strace's own -tt time-of-day (HH:MM:SS.ffffff, no date) with
    a reference date into an aware UTC datetime."""
    h, m, rest = time_of_day.split(':')
    sec, _, frac = rest.partition('.')
    frac = (frac + '000000')[:6]
    return datetime(reference_date.year, reference_date.month, reference_date.day,
                     int(h), int(m), int(sec), int(frac), tzinfo=timezone.utc)


def strace_relative_seconds(time_of_day, fired_at):
    """Converts one strace -tt time-of-day into seconds relative to this
    run's own firing instant, resolving the day strace's own output never
    names. A trace that happened to straddle midnight UTC would otherwise
    show as either far in the future or far in the past relative to
    firing; either one is corrected by trying the neighboring date instead
    once the gap exceeds twelve hours, which no single truth run (bounded
    to 900 seconds by tools/truth-run.sh) can otherwise produce."""
    if fired_at is None or not time_of_day:
        return None
    candidate = strace_time_of_day_to_datetime(time_of_day, fired_at.date())
    delta = (candidate - fired_at).total_seconds()
    if delta < -43200:
        candidate = strace_time_of_day_to_datetime(time_of_day, fired_at.date() + timedelta(days=1))
        delta = (candidate - fired_at).total_seconds()
    elif delta > 43200:
        candidate = strace_time_of_day_to_datetime(time_of_day, fired_at.date() - timedelta(days=1))
        delta = (candidate - fired_at).total_seconds()
    return delta


# --- strace parsing -----------------------------------------------------

# A trace line's syscall name and raw argument text, e.g. for
#   03:11:52.361776 openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3
# time="03:11:52.361776", name="openat",
# args='AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY', result="3".
# The leading time is optional in the pattern (absent when a trace was not
# taken with -tt) so a trace lacking it still parses, only without a
# timestamp to convert. A line strace could not finish printing (an
# interrupted <unfinished ...> / resumed pair) does not match and is
# skipped: this tool has no way to reunite the two halves, and a partial
# argument list must never be read as a complete path.
_LINE_RE = re.compile(
    r'^(?:(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+)?'
    r'(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<args>.*)\)\s*=\s*(?P<result>-?\d+)')
_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _first_string_arg(args):
    """The first double-quoted argument in a syscall's argument text,
    unescaping strace's own backslash escapes. execve's first argument and
    open's/openat's/openat2's path argument are both in this position."""
    m = _STRING_RE.search(args)
    if not m:
        return None
    return m.group(1).encode().decode('unicode_escape')


def _dirfd_arg(args):
    """openat's/openat2's first argument: AT_FDCWD, or a numeric
    descriptor this tool does not track across the trace."""
    head = args.split(',', 1)[0].strip()
    return head


_EXEC_SYSCALLS = ('execve', 'execveat')
_OPEN_SYSCALLS = ('open', 'openat', 'openat2')
_CLONE_SYSCALLS = ('clone', 'clone3', 'fork', 'vfork')


def parse_strace_line(line):
    """Parses one strace output line into a syscall record, or None for a
    line this tool does not use (a different syscall, a signal delivery
    line, an unfinished/resumed pair, or text that fails to parse at all).

    Returns {"syscall": str, "path": str, "ok": bool, "resolved": bool,
    "is_dir_open": bool, "time_of_day": str|None}. "resolved" is False
    when the path argument was relative to a descriptor other than
    AT_FDCWD: this tool does not track open descriptors across a trace to
    recover what a numeric dirfd pointed at, so such a path is kept as a
    raw, unresolved fragment rather than guessed at. "is_dir_open" is True
    for an open carrying O_DIRECTORY: a package's dpkg .list entry names
    every path dpkg tracks for it, directories included, and a directory
    one package happens to be recorded as owning (/usr/share/doc, say) is
    routinely opened while iterating entries that belong to entirely
    different packages - so opening it is never used as evidence of using
    whichever package's .list happens to name it (see read_strace_dir).
    "time_of_day" is strace's own -tt reading (HH:MM:SS.ffffff, no date)
    when the trace carries one, else None.
    """
    line = line.strip()
    if not line or '<unfinished' in line or '<... ' in line:
        return None
    m = _LINE_RE.match(line)
    if not m:
        return None
    name = m.group('name')
    if name not in _EXEC_SYSCALLS and name not in _OPEN_SYSCALLS:
        return None
    args = m.group('args')
    ok = int(m.group('result')) >= 0
    path = _first_string_arg(args)
    if path is None:
        return None
    resolved = True
    if name in ('openat', 'openat2', 'execveat'):
        dirfd = _dirfd_arg(args)
        if dirfd != 'AT_FDCWD' and not path.startswith('/'):
            resolved = False
    return {
        'syscall': name, 'path': path, 'ok': ok,
        'resolved': resolved and path.startswith('/'),
        'is_dir_open': 'O_DIRECTORY' in args,
        'time_of_day': m.group('time'),
    }


def parse_clone_line(line):
    """Parses one strace line naming clone/clone3/fork/vfork, returning the
    new child's pid/tid this syscall reports in the CALLING (parent)
    process's own trace file - the only place strace -f records this
    relationship, since a traced child's own trace.<pid> file begins
    independently of who created it, with whatever it does next, never
    with a self-announcement of its own pid. Returns None for a failed
    call (no child was actually created), an unfinished/resumed pair, or
    a line naming a different syscall entirely."""
    line = line.strip()
    if not line or '<unfinished' in line or '<... ' in line:
        return None
    m = _LINE_RE.match(line)
    if not m or m.group('name') not in _CLONE_SYSCALLS:
        return None
    result = int(m.group('result'))
    return result if result > 0 else None


# A signal interrupting a blocking syscall (a slow open, most commonly)
# splits that one call across two lines in the SAME per-pid trace file:
# strace prints what it has so far followed by "<unfinished ...>", logs
# whatever the signal handler itself did in between, and later prints
# "<... name resumed>" with the rest of the original call's own args and
# result once it actually returns. Read one line at a time, as this
# tool's other per-line parsers do, both halves are unusable: the first
# carries no result, and the second carries no name to remember it by
# unless the two are stitched back together first.
_UNFINISHED_RE = re.compile(
    r'^(?:(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\((?P<partial_args>.*)\s<unfinished \.\.\.>$')
_RESUMED_RE = re.compile(
    r'^(?:(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+)?<\.\.\. (?P<name>[a-zA-Z_][a-zA-Z0-9_]*) resumed>(?P<rest>.*)$')

# Any line still carrying one of strace's own split-call markers after
# both exact patterns above have had a chance at it is a form neither
# recognizes - never treated as an ordinary, otherwise-uninteresting
# line the way check_strace_completeness's own benign-marker allowance
# treats a signal or attach notice: it is real, un-reconstructed
# syscall evidence this run cannot vouch for either way.
_SPLIT_SYSCALL_MARKERS = ('<unfinished', '<... ')


def _reconstruct_unfinished_lines(lines):
    """Reconstructs strace's own <unfinished ...>/<... resumed> pairs
    within one per-pid trace file's own line sequence into complete
    "name(args) = result" lines this tool's other per-line parsers
    (parse_strace_line/parse_clone_line) can read, so a call a signal
    happened to interrupt is not simply dropped as evidence even though
    it went on to succeed. Matches the most recently opened pending call
    of the same name first (a LIFO match), which is the correct pairing
    for the rare case of a syscall interrupted while a nested signal
    handler's own call is itself interrupted too.

    The "unfinished" half is not required to end in a comma before the
    marker: strace prints it wherever the interruption actually landed,
    which can just as well be right after the last argument value with
    no more expected ("O_RDONLY <unfinished ...>") as after a comma with
    more still to come ("AT_FDCWD, <unfinished ...>"), or with no
    arguments printed at all yet ("clone( <unfinished ...>"). Only the
    one mandatory separating whitespace character right before the
    marker itself is required; everything before it, comma or not, is
    kept verbatim and simply concatenated with the resumed half's own
    remainder.

    Returns (lines: list[str], unreconstructed: int): unreconstructed
    counts every kind of split-call evidence this run's own trace could
    not turn into one complete, parseable line - an "unfinished" this
    file's own trace never carried a matching "resumed" for at all by
    the time the file ended (the trace stopped mid-call), a "resumed"
    with no "unfinished" of the same name pending to pair it with at
    all, and a line carrying one of strace's own split-call markers in
    a shape neither exact pattern above recognizes (a strace version or
    locale difference this tool has not seen). None of these three is
    silently dropped or passed through as an ordinary line - each is a
    real completeness gap.
    """
    out = []
    pending = []  # [(name, time, partial_args), ...]
    unreconstructed = 0
    for raw in lines:
        stripped = raw.rstrip('\n').rstrip('\r')
        m = _UNFINISHED_RE.match(stripped)
        if m:
            pending.append((m.group('name'), m.group('time') or '', m.group('partial_args')))
            continue
        m = _RESUMED_RE.match(stripped)
        if m:
            name = m.group('name')
            idx = next((i for i in range(len(pending) - 1, -1, -1) if pending[i][0] == name), None)
            if idx is None:
                # A "resumed" with nothing pending to pair it to at all
                # - this file's own capture started mid-call, or the
                # matching "unfinished" used a shape this cannot
                # recognize. Either way, this call's own evidence is
                # incomplete, never silently dropped without a count.
                unreconstructed += 1
                continue
            _pname, time_prefix, partial_args = pending.pop(idx)
            prefix = f'{time_prefix} ' if time_prefix else ''
            out.append(f'{prefix}{name}({partial_args}{m.group("rest")}')
            continue
        if any(marker in stripped for marker in _SPLIT_SYSCALL_MARKERS):
            unreconstructed += 1
            continue
        out.append(stripped)
    return out, unreconstructed + len(pending)


def _read_reconstructed_trace_lines(path):
    """One per-pid trace file's own lines, with every <unfinished ...>/
    <... resumed> pair already stitched back together (see
    _reconstruct_unfinished_lines) - the shared reading this tool's own
    strace consumers (read_strace_dir, check_strace_completeness,
    _read_trace_events) all use, so a reconstruction fix in one place
    reaches every one of them.

    Returns (lines: list[str], unreconstructed: int).
    """
    with open(path, encoding='utf-8', errors='replace') as f:
        raw_lines = f.readlines()
    return _reconstruct_unfinished_lines(raw_lines)


def _is_directory_in_rootfs(path, rootfs_dir):
    """Whether path is actually a directory on this run's own exported
    rootfs. O_DIRECTORY is only ever an assertion a caller opts into (it
    makes the call fail when the target is NOT a directory); a plain
    open()/openat() with no such flag succeeds perfectly well against a
    directory too (getdents-style traversal), so is_dir_open alone (see
    parse_strace_line) does not catch every directory-iteration open —
    only every one honest enough to say so. Returns False (never treated
    as a directory) when rootfs_dir is not given, the path does not
    exist in it, or its type cannot be read at all: this check is only
    ever used to EXCLUDE evidence, and excluding on a guess would be
    worse than not excluding at all."""
    if rootfs_dir is None:
        return False
    resolved, state = resolve_rootfs_path(path, rootfs_dir)
    if state != 'resolved':
        return False
    local = _rootfs_local_path(rootfs_dir, resolved)
    if local is None:
        return False
    try:
        return os.path.isdir(local)
    except OSError:
        return False


def read_strace_dir(strace_dir, fired_at=None, rootfs_dir=None):
    """Every successful, resolved absolute path named by execve/open/
    openat/openat2 across every per-pid trace file, the count of
    unresolved (relative-to-a-descriptor) and failed occurrences this run
    could not use as positive evidence, and — when fired_at is given — one
    timed evidence record per successful, resolved occurrence. Only a
    successful call is ever used as a positive: a failed open or a
    nonexistent-path probe is not evidence of use.

    An open of a directory is excluded from package-resolution evidence
    entirely, whether or not the call itself said so with O_DIRECTORY
    (see _is_directory_in_rootfs): dpkg's own .list has no way to tell
    "this package's own directory" apart from "a shared directory dpkg
    happens to record this package as owning too", so crediting either
    would credit every package whose .list mentions it. rootfs_dir
    (this run's own exported container filesystem, from
    export_container_rootfs) is what makes the stat-based half of this
    check possible at all; without it, only the O_DIRECTORY-flagged
    half still applies.

    Returns (used_paths: set, unresolved: list, failed: int,
    evidence_by_path: dict[path] -> list of {"type": "exec"|"open",
    "source": "strace", "ts_relative_s": float|None, "pid": int|None}).
    "pid" is the trace.<pid> file's own pid (None when a file name this
    tool does not recognize produced it) — carried alongside the
    timestamp so a package-use occurrence originating in a short-lived
    subject's own trace can be tied to its own operation instance by
    process identity rather than by clock agreement (see
    attribute_evidence).
    """
    used_paths = set()
    unresolved = []
    failed = 0
    evidence_by_path = {}
    for path in sorted(glob.glob(os.path.join(strace_dir, 'trace.*'))):
        pid = _trace_pid_from_filename(path)
        lines, _unreconstructed = _read_reconstructed_trace_lines(path)
        for line in lines:
            rec = parse_strace_line(line)
            if rec is None:
                continue
            if not rec['ok']:
                failed += 1
                continue
            if not rec['resolved']:
                unresolved.append(rec['path'])
                continue
            if rec['is_dir_open']:
                continue
            kind = 'exec' if rec['syscall'] in _EXEC_SYSCALLS else 'open'
            if kind == 'open' and _is_directory_in_rootfs(rec['path'], rootfs_dir):
                continue
            used_paths.add(rec['path'])
            ts_relative = strace_relative_seconds(rec['time_of_day'], fired_at)
            evidence_by_path.setdefault(rec['path'], []).append(
                {'type': kind, 'source': 'strace', 'ts_relative_s': ts_relative, 'pid': pid})
    return used_paths, sorted(set(unresolved)), failed, evidence_by_path


# --- runtime introspection -----------------------------------------------

def read_runtime_modules(path, fired_at=None):
    """Every resolved file/class path runtime-modules.jsonl names, the
    unresolved module names it could name no file for (a module with no
    __file__ and no usable spec.origin, say), and — when fired_at is
    given — one timed "open" evidence record for the FIRST snapshot a
    resolved path is seen in.

    Each phase's own snapshot lists every module still loaded at that
    moment, cumulatively — a module loaded once keeps reappearing in
    every later phase's own dump for as long as it stays loaded, not
    just the one phase that first loaded it. Turning every one of those
    reappearances into its own "open" evidence record would let a
    module loaded early get misattributed, by attribute_evidence's own
    nearest-operation fallback, to whatever unrelated operation happens
    to be running near a LATER periodic checkpoint's own time, purely
    because the snapshot taken then still lists it. Only the first
    sighting becomes evidence for operation-attribution purposes; every
    later reappearance of the identical path is kept separately as
    held-at evidence — this run's own introspection confirming the
    module was still loaded at that later phase, not a new load — so a
    caller that wants it (as evidence the module was held resident
    through to some later point) still has it, without it being read as
    a fresh open near whatever operation was running then.

    A module recorded with origin "built-in" is never added to
    unresolved_modules at all: the workload's own dump routine uses that
    label for every module this run could confirm has no single
    resolvable file to begin with (an interpreter-compiled module, a
    native extension's own module created outside Python's normal import
    machinery, or a PEP 420 namespace package spread across directories
    rather than backed by one file) - a confirmed, well-understood
    state, not a gap in this run's own observation, so it never counts
    as evidence of incomplete capture the way a genuine resolution
    failure does.

    Returns (used_paths: set, unresolved_modules: list,
    evidence_by_path: dict[path] -> [{"type": "open", "source":
    "runtime_introspection", "ts_relative_s": float|None}] (at most one
    entry, the first sighting), held_by_path: dict[path] -> list of
    {"phase": str|None, "ts_relative_s": float|None} for every later
    reappearance of that same resolved path).
    """
    used_paths = set()
    unresolved_modules = []
    evidence_by_path = {}
    held_by_path = {}
    if not os.path.exists(path):
        return used_paths, unresolved_modules, evidence_by_path, held_by_path
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            resolved_path = rec.get('file') or rec.get('jar')
            if resolved_path:
                ts_relative = None
                if fired_at is not None and rec.get('ts'):
                    try:
                        ts_relative = (parse_iso_utc(rec['ts']) - fired_at).total_seconds()
                    except ValueError:
                        ts_relative = None
                if resolved_path not in used_paths:
                    used_paths.add(resolved_path)
                    evidence_by_path[resolved_path] = [
                        {'type': 'open', 'source': 'runtime_introspection', 'ts_relative_s': ts_relative}]
                else:
                    held_by_path.setdefault(resolved_path, []).append(
                        {'phase': rec.get('phase'), 'ts_relative_s': ts_relative})
            elif rec.get('resolved') is False and rec.get('origin') != 'built-in':
                unresolved_modules.append(rec.get('module') or rec.get('class') or '?')
    return used_paths, sorted(set(unresolved_modules)), evidence_by_path, held_by_path


# --- precise short-lived hold times and start/end pairs, from the
# workload's own usage log -------------------------------------------------

def _pair_usage_exec_exit(path):
    """Matches each usage.jsonl "exec" record with its "exit" (same pid
    and starttime), both parsed to aware UTC datetimes. usage.jsonl's own
    timestamps are written from a single wall-clock reading with real
    sub-second precision (see the operational loop's own script), which
    is more precise than anything strace's per-line timing could add.

    Returns {(pid, starttime): (path, start_dt, end_dt)}.
    """
    pairs = {}
    if not os.path.exists(path):
        return pairs
    starts = {}
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            key = (rec.get('pid'), rec.get('starttime'))
            if rec.get('event') == 'exec' and rec.get('path'):
                starts[key] = (rec['path'], rec.get('ts'))
            elif rec.get('event') == 'exit' and key in starts:
                exec_path, exec_ts = starts.pop(key)
                exit_ts = rec.get('ts')
                if exec_ts and exit_ts:
                    try:
                        pairs[key] = (exec_path, parse_iso_utc(exec_ts), parse_iso_utc(exit_ts))
                    except ValueError:
                        continue
    return pairs


def read_usage_exec_hold_seconds(path):
    """Every observed exec-to-exit duration in seconds, per executed
    path, from _pair_usage_exec_exit's own pairing — the source
    coverage.py's short-lived-use classification uses for those paths
    rather than a span derived from strace evidence."""
    holds = {}
    for _key, (exec_path, start_dt, end_dt) in _pair_usage_exec_exit(path).items():
        duration = (end_dt - start_dt).total_seconds()
        if duration >= 0:
            holds.setdefault(exec_path, []).append(duration)
    return holds


# --- operations-sequence comparison ---------------------------------------

def read_operations(path):
    """The ordered list of "op" names from one operations.jsonl, or None
    when the file does not exist (an older run, or a run this tool was
    not pointed at)."""
    if not os.path.exists(path):
        return None
    ops = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if 'op' in rec:
                ops.append(rec['op'])
    return ops


def compare_operations(truth_ops, measurement_ops):
    """Whether two runs of the same image carried out the same firing
    procedure. The operational loop's own osops_* operations repeat on a
    timer and are compared as a multiset (how many of each), since the two
    runs are not expected to complete the exact same number of five-second
    cycles in the same wall-clock window; every other operation (the
    fixed, once-each requests the resident program issues) is compared as
    an exact, ordered sequence, since those are not periodic and a
    mismatch in order or count there means the two runs did not do the
    same thing.

    Returns (consistent: bool, detail: str).
    """
    if truth_ops is None or measurement_ops is None:
        return None, 'one of the two runs has no operations.jsonl to compare'

    def split(ops):
        periodic = [o for o in ops if o.startswith('osops_')]
        fixed = [o for o in ops if not o.startswith('osops_')]
        return fixed, periodic

    t_fixed, t_periodic = split(truth_ops)
    m_fixed, m_periodic = split(measurement_ops)
    if t_fixed != m_fixed:
        return False, f'fixed operation sequence differs: truth={t_fixed} measurement={m_fixed}'
    from collections import Counter
    if Counter(t_periodic) == {} and Counter(m_periodic) == {}:
        return True, 'no periodic operations recorded in either run'
    # Both runs are expected to have exercised every kind of periodic
    # operation at least once; an operation missing from one side and not
    # the other is a real behavioral difference, not just a shorter window.
    t_kinds, m_kinds = set(t_periodic), set(m_periodic)
    if t_kinds != m_kinds:
        return False, f'periodic operation kinds differ: truth={sorted(t_kinds)} measurement={sorted(m_kinds)}'
    return True, f'fixed sequence matches ({len(t_fixed)} operations); periodic kinds match {sorted(t_kinds)}'


def read_operation_records(path):
    """The full operations.jsonl records (id/ts/op/ok/detail), not just
    the "op" names compare_operations reads: the fuller comparison below
    needs each operation's own success and recorded detail, not only
    whether the two runs named the same operations in the same order."""
    if not os.path.exists(path):
        return None
    records = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if 'op' in rec:
                records.append(rec)
    return records


def read_occurrences(path):
    """Every occurrences.jsonl record, in file order, or [] when the file
    does not exist."""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


_OSOPS_SEQ_RE = re.compile(r'-(?:op|exec)-osops-(\d+)$')


_FIXED_OCCURRENCE_PAIRING_TOLERANCE_S = 5.0


def read_operation_intervals(operations_path, occurrences_path, usage_path):
    """Every operation's own [start, end] instant, as aware UTC datetimes,
    built from the two logs the workload's own operational code writes
    independently of operations.jsonl's own single completion timestamp:
    a fixed (non-"osops_") operation's own occurrences.jsonl "load"
    record carries its own real start/end when one exists; a periodic
    "osops_" operation's matching occurrence (paired by the numeric
    sequence common to both logs' own id fields) carries only the
    launching exec's pid/starttime, which usage.jsonl's own exec/exit
    pair for that same (pid, starttime) resolves to a real start/end.

    A fixed operation's own occurrence, when it has one, is paired by
    timestamp proximity rather than by simple position: every one of
    this design's three language runtimes logs a "load" occurrence and
    then, in the same function call with nothing else in between, the
    matching operations.jsonl record for it — but not every fixed
    operation has an occurrence of its own at all ("fired", the firing
    signal itself, never does in any of the three; one language runtime
    among 26-28 also logs one further one-time operation this same way).
    Consuming occurrences strictly by position would then misattribute
    every occurrence from that point on to the wrong operation entirely.
    Matching each operation to the nearest not-yet-claimed occurrence
    whose own end timestamp precedes it by no more than a few seconds
    finds the right one regardless of how many operations before it had
    no occurrence of their own, and correctly pairs nothing at all for
    "fired" (nothing precedes it) rather than stealing a later
    operation's own occurrence.

    An operation this cannot pair with either source at all falls back
    to a zero-length interval at the operation's own recorded timestamp:
    not a real span, but never wrongly treated as unbounded either.

    Returns a list of {"op": str, "id": str, "ok": bool, "start":
    datetime|None, "end": datetime|None, "paired": bool, "pid": int|None}
    in operations.jsonl's own order. "paired" is False for the
    zero-length fallback, so a caller can tell an operation whose own
    interval is genuinely known from one this could not resolve at all.
    "pid" is set only for an "osops_" operation whose own occurrence
    named one (see attribute_evidence for why this matters more than the
    interval itself for that subject).
    """
    op_records = read_operation_records(operations_path) or []
    occurrences = read_occurrences(occurrences_path)
    exec_pairs = _pair_usage_exec_exit(usage_path)

    load_ends = []
    for o in occurrences:
        if o.get('kind') != 'load':
            continue
        try:
            load_ends.append((parse_iso_utc(o['end']), o))
        except (KeyError, ValueError):
            continue
    claimed = [False] * len(load_ends)
    osops_occ_by_seq = {}
    for o in occurrences:
        if o.get('kind') != 'exec':
            continue
        m = _OSOPS_SEQ_RE.search(str(o.get('id', '')))
        if m:
            osops_occ_by_seq[m.group(1)] = o

    def claim_nearest_occurrence(op_ts):
        if op_ts is None:
            return None
        best_idx, best_gap = None, None
        for idx, (end, _occ) in enumerate(load_ends):
            if claimed[idx]:
                continue
            gap = (op_ts - end).total_seconds()
            if 0 <= gap <= _FIXED_OCCURRENCE_PAIRING_TOLERANCE_S and (best_gap is None or gap < best_gap):
                best_idx, best_gap = idx, gap
        if best_idx is None:
            return None
        claimed[best_idx] = True
        return load_ends[best_idx][1]

    intervals = []
    for rec in op_records:
        op = rec.get('op', '')
        ts = None
        if rec.get('ts'):
            try:
                ts = parse_iso_utc(rec['ts'])
            except ValueError:
                ts = None
        start = end = ts
        paired = False
        pid = None
        if op.startswith('osops_'):
            m = _OSOPS_SEQ_RE.search(str(rec.get('id', '')))
            occ = osops_occ_by_seq.get(m.group(1)) if m else None
            if occ is not None:
                # The pid occurrences.jsonl's own osops "exec" record
                # names is exactly the pid that execs curl/git/openssl
                # directly (see run_cmd in the operational loop's own
                # script: "$path" "$@" & ; pid=$! captures the forked
                # child right before it execs $path) - kept here even
                # when usage.jsonl carries no matching exec/exit pair to
                # resolve a real span from, since attribute_evidence
                # still needs it to tie a short-lived subject's own raw
                # evidence to this exact operation instance by process
                # identity, independent of whether a real span was ever
                # resolved.
                pid = occ.get('pid')
                key = (occ.get('pid'), occ.get('starttime'))
                pair = exec_pairs.get(key)
                if pair:
                    _path, start, end = pair
                    paired = True
        else:
            occ = claim_nearest_occurrence(ts)
            if occ is not None:
                try:
                    start, end = parse_iso_utc(occ['start']), parse_iso_utc(occ['end'])
                    paired = True
                except (KeyError, ValueError):
                    pass
        intervals.append({'op': op, 'id': rec.get('id'), 'ok': rec.get('ok', True),
                           'start': start, 'end': end, 'paired': paired, 'pid': pid})
    return intervals


def compare_operation_records(truth_records, measurement_records):
    """Compares two operations.jsonl record sets by name, order, success,
    and recorded detail together. Two runs that named the same operations
    in the same order but disagreed on whether any one of them succeeded
    did not carry out the same procedure, and neither did two runs whose
    detail differs for the same fixed operation.

    The periodic "osops_" operations are compared by success too, even
    though compare_operations itself only compares their kinds as a
    multiset (an exact positional pairing across two runs of unequal
    cycle counts is not meaningful — see compare_operations): a periodic
    operation's own detail is never recorded (os-ops.sh's own
    run_cmd writes no "detail" field for any of curl/git/openssl at all),
    so nothing is compared there, but a run that recorded ANY failure of
    a given osops_ kind while the other recorded none at all for that
    same kind is a real behavioral difference — the shared local target
    (health endpoint, git repo, digest input) misbehaved in one run and
    not the other — and is reported the same way a fixed operation's own
    success mismatch is.

    Returns (consistent: bool|None, detail: str)."""
    if truth_records is None or measurement_records is None:
        return None, 'one of the two runs has no operations.jsonl to compare'
    consistent, detail = compare_operations(
        [r.get('op') for r in truth_records], [r.get('op') for r in measurement_records])
    if consistent is not True:
        return consistent, detail
    truth_fixed = [r for r in truth_records if not str(r.get('op', '')).startswith('osops_')]
    measurement_fixed = [r for r in measurement_records if not str(r.get('op', '')).startswith('osops_')]
    for i, (t, m) in enumerate(zip(truth_fixed, measurement_fixed)):
        if bool(t.get('ok', True)) != bool(m.get('ok', True)):
            return False, f'operation {i} ("{t.get("op")}") succeeded in one run and not the other'
        # "detail" is this harness's own available stand-in for an input
        # summary/digest: neither run's own operations.jsonl carries a
        # purpose-built content hash today, so a difference here is the
        # closest available signal that the two runs' inputs diverged.
        if t.get('detail') and m.get('detail') and t['detail'] != m['detail']:
            return False, f'operation {i} ("{t.get("op")}") recorded different detail in each run'

    # The periodic "osops_" operations are paired by POSITION across the
    # FULL interleaved timeline, never split apart by kind first: two
    # runs whose operational loop executes the exact same total count of
    # curl/git/openssl each but in a different relative order within
    # each cycle (curl, git, openssl vs. git, curl, openssl, say) are a
    # real behavioral difference a per-kind comparison could never even
    # see, since each kind's own count and per-kind ordering would still
    # match independently. Only the range both runs actually reached is
    # judged - the two runs are not expected to complete the same number
    # of periodic cycles (see compare_operations), so a cycle only the
    # longer run got to at all is neither compared nor treated as
    # agreeing; it is simply outside what this comparison can certify
    # either way (see osops_pairing_info, which exposes exactly which
    # instances that leaves on each side for a caller like coverage.py
    # to know not to treat as verified). Every cycle both runs DID reach
    # must line up exactly, in order: the same kind at the same
    # position, which ones succeeded and which failed, not merely the
    # same total counts of each - a run whose curl failed once amid
    # several successes and one whose curl failed every single time
    # would land in the same "some failures" bucket under a count-only
    # comparison despite being materially different outcomes, and two
    # runs whose failures fall at different positions in the same
    # sequence (succeeded then failed vs. failed then succeeded) would
    # too.
    t_seq = osops_sequence(truth_records)
    m_seq = osops_sequence(measurement_records)
    for i in range(min(len(t_seq), len(m_seq))):
        if t_seq[i][0] != m_seq[i][0]:
            return False, (f'periodic operation sequence differs in relative order at position {i}: '
                            f'truth ran "{t_seq[i][0]}", measurement ran "{m_seq[i][0]}"')
    # A periodic instance whose outcome differs between the runs (the
    # first curl of a run racing the server's own readiness, say) is not
    # a correspondence: that instance is taken out of the pairing, so a
    # package used only during it is never certified through it (see
    # osops_pairing_info), and the run is otherwise comparable. Only when
    # such instances stop being the exception does the comparison fail:
    # more than one of them, or more than two in every hundred paired,
    # means the two runs' loops did not behave the same way.
    mismatched = osops_mismatched_positions(t_seq, m_seq)
    reached = min(len(t_seq), len(m_seq))
    paired = reached - len(mismatched)
    if len(mismatched) > osops_mismatch_tolerance(paired):
        i = mismatched[0]
        return False, (f'{len(mismatched)} of {reached} periodic operation instances both runs reached differ '
                        f'in outcome or detail between the runs (first at position {i}, "{t_seq[i][0]}": '
                        f'truth ok={t_seq[i][1]}, measurement ok={m_seq[i][1]}), more than the '
                        f'{osops_mismatch_tolerance(paired)} such instance(s) tolerated for {paired} paired')
    if mismatched:
        return True, (f'fixed sequence matches; periodic kinds match in order; {len(mismatched)} periodic '
                       f'instance(s) differ in outcome and are left unpaired (positions {mismatched})')
    return True, detail


def osops_sequence(records):
    """[(kind, ok, detail, id), ...] for every periodic "osops_"
    operation in one operations.jsonl record set, in the record set's
    OWN INTERLEAVED order - never split apart by kind first (see
    compare_operation_records's own reasoning for why the full timeline,
    not a per-kind one, is what must be paired position by position)."""
    return [(str(r.get('op', '')), bool(r.get('ok', True)), r.get('detail'), r.get('id'))
            for r in records if str(r.get('op', '')).startswith('osops_')]


def osops_mismatched_positions(t_seq, m_seq):
    """Positions (in the interleaved periodic timeline both runs reached)
    where the same kind of periodic operation succeeded in one run and
    not the other, or recorded different detail."""
    out = []
    for i in range(min(len(t_seq), len(m_seq))):
        _t_kind, t_ok, t_detail, _t_id = t_seq[i]
        _m_kind, m_ok, m_detail, _m_id = m_seq[i]
        if t_ok != m_ok or (t_detail and m_detail and t_detail != m_detail):
            out.append(i)
    return out


def osops_mismatch_tolerance(paired):
    """How many mismatched periodic instances still leave two runs
    comparable: one, or two in every hundred instances that did pair
    (the mismatched ones are not among them)."""
    return max(1, paired * 2 // 100)


def osops_pairing_info(truth_records, measurement_records):
    """{'paired_count': int, 'paired_truth_osops_ids': [...],
    'paired_measurement_osops_ids': [...], 'unpaired_truth_osops_ids':
    [...], 'unpaired_measurement_osops_ids': [...]} - which of each
    side's own periodic "osops_" instances (by their own "id" field)
    compare_operation_records's own positional pairing actually verified
    against the other run (paired_count positions, the shorter side's
    own full length), and which ones were left over beyond that (the
    longer side's own trailing, never-compared tail). A caller scoring a
    specific candidate against a specific instance can check whether
    that instance's own id falls in the unpaired set for its own side -
    a package tied only to an instance never actually verified against
    the other run should not be treated as confirmed consistent by this
    comparison at all."""
    t_seq = osops_sequence(truth_records or [])
    m_seq = osops_sequence(measurement_records or [])
    reached = min(len(t_seq), len(m_seq))
    mismatched = set(osops_mismatched_positions(t_seq, m_seq))
    paired_positions = [i for i in range(reached) if i not in mismatched]
    return {
        'paired_count': len(paired_positions),
        'paired_truth_osops_ids': [t_seq[i][3] for i in paired_positions],
        'paired_measurement_osops_ids': [m_seq[i][3] for i in paired_positions],
        'mismatched_truth_osops_ids': [t_seq[i][3] for i in sorted(mismatched)],
        'mismatched_measurement_osops_ids': [m_seq[i][3] for i in sorted(mismatched)],
        # A mismatched instance is unpaired on both sides: nothing used
        # only during it is certified through this comparison.
        'unpaired_truth_osops_ids': [t_seq[i][3] for i in sorted(mismatched)] + [t_seq[i][3] for i in range(reached, len(t_seq))],
        'unpaired_measurement_osops_ids': [m_seq[i][3] for i in sorted(mismatched)] + [m_seq[i][3] for i in range(reached, len(m_seq))],
    }


def compare_measurement_run(varlog, measurement_run, truth_op_records, truth_image_id):
    """The complete comparison between this truth run and one measurement
    run of the same case: the firing procedure (name/order/success/
    detail), the runtime-introspection file set each side's own
    runtime-modules.jsonl resolved, and the image ID each side actually
    ran. The measurement run's own path is carried in the result so a
    caller can never mistake one comparison's outcome for another's.
    """
    measurement_ops_path = f'{measurement_run}/gtb-raw/operations.jsonl'
    if not os.path.exists(measurement_ops_path):
        measurement_ops_path = f'{measurement_run}/operations.jsonl'
    measurement_op_records = read_operation_records(measurement_ops_path)
    consistent, detail = compare_operation_records(truth_op_records, measurement_op_records)
    # Diagnostic, independent of consistent/detail above: which osops_
    # instances this comparison's own positional pairing actually
    # verified on each side, and which were left over in whichever
    # side's own sequence ran longer - a caller (coverage.py) can use
    # this to avoid treating a candidate tied only to an unpaired
    # instance as confirmed consistent by this comparison at all, even
    # when the paired range itself came back fully consistent.
    osops_pairing = osops_pairing_info(truth_op_records or [], measurement_op_records or [])

    truth_modules_path = f'{varlog}/runtime-modules.jsonl'
    measurement_modules_path = f'{measurement_run}/gtb-raw/runtime-modules.jsonl'
    if not os.path.exists(measurement_modules_path):
        measurement_modules_path = f'{measurement_run}/runtime-modules.jsonl'
    # A truth run that produced its own runtime-modules.jsonl at all (as
    # cases 26-28's own workloads do; a case with no such file, like 24,
    # never triggers any of this) makes the introspection comparison
    # MANDATORY on both sides: reading None here is never silently
    # treated the same as a genuine match. read_runtime_modules() also
    # tolerates individual bad JSON Lines by skipping them (matching
    # this tool's own lenient-parsing convention elsewhere), so a
    # capture that carries lines but resolved nothing usable at all
    # (every line unparseable, or the file truncated to zero bytes) is
    # read as absent here too, rather than as a hollow "empty set"
    # match against truth's own presumably non-empty one.
    truth_modules = _runtime_modules_or_none(truth_modules_path)
    measurement_modules = _runtime_modules_or_none(measurement_modules_path)
    modules_match = None
    if truth_modules is not None and measurement_modules is not None:
        modules_match = (truth_modules == measurement_modules)

    measurement_image_path = f'{measurement_run}/image_id.txt'
    measurement_image_id = None
    if os.path.exists(measurement_image_path):
        measurement_image_id = open(measurement_image_path, encoding='utf-8').read().strip()
    image_match = (measurement_image_id == truth_image_id) if measurement_image_id else None

    overall = consistent
    reasons = [detail] if detail else []
    if truth_modules is not None and modules_match is None:
        overall = False
        reasons.append('this truth run produced its own runtime-modules.jsonl, but this measurement run\'s '
                        'own copy is missing, empty, or could not be read at all - the runtime-introspection '
                        'comparison could not be completed')
    elif modules_match is False:
        overall = False
        reasons.append('runtime-modules.jsonl resolved-file sets differ between the two runs')
    if image_match is False:
        overall = False
        reasons.append(f'image_id differs: truth={truth_image_id!r} measurement={measurement_image_id!r}')

    return {
        'checked': True,
        'measurement_run': measurement_run,
        'consistent': overall,
        'detail': '; '.join(r for r in reasons if r),
        'runtime_modules_match': modules_match,
        'image_id_match': image_match,
        'osops_pairing': osops_pairing,
    }


def _runtime_modules_or_none(path):
    """The resolved module-path set from one run's own runtime-
    modules.jsonl (see read_runtime_modules), or None when the file
    does not exist, is empty, or otherwise carries nothing this run
    could resolve any path from at all - never a value indistinguishable
    from a genuinely empty-but-successfully-read capture."""
    if not os.path.exists(path):
        return None
    try:
        if os.path.getsize(path) == 0:
            return None
    except OSError:
        return None
    used_paths, _unresolved, _evidence, _held = read_runtime_modules(path)
    return used_paths


# --- evidence-period attribution (startup / one named operation / after
# the stop signal) ----------------------------------------------------------

_RESIDENT_OPERATION_ATTRIBUTION_TOLERANCE_S = 1.0


def _operation_for_instant(abs_ts, operation_intervals, tolerance_s=0.0):
    """The operation whose own [start, end] span abs_ts falls in or
    comes within tolerance_s of either edge of, picking the nearest edge
    distance when more than one span is in reach. Returns (op_name,
    exact): exact is True only when abs_ts falls strictly inside exactly
    one span (distance 0, unambiguous); False when the tolerance margin
    was needed, or more than one span's own strict containment applied -
    a "nearest" attribution either way, per the design's own separation
    between resident evidence (where a fraction of a second of drift is
    tolerated and disambiguated by distance) and pid-based short-lived
    attribution (which needs neither). Returns (None, False) when
    nothing is in reach even with the tolerance."""
    candidates = []
    for iv in operation_intervals:
        if iv['start'] is None or iv['end'] is None:
            continue
        if iv['start'] <= abs_ts <= iv['end']:
            dist = 0.0
        elif abs_ts < iv['start']:
            dist = (iv['start'] - abs_ts).total_seconds()
        else:
            dist = (abs_ts - iv['end']).total_seconds()
        if dist <= tolerance_s:
            candidates.append((dist, iv['op']))
    if not candidates:
        return None, False
    candidates.sort(key=lambda pair: pair[0])
    best_dist, best_op = candidates[0]
    exact = best_dist == 0.0 and sum(1 for d, _op in candidates if d == 0.0) == 1
    return best_op, exact


def classify_evidence_period(abs_ts, fired_at, stopped_at, operation_intervals,
                              tolerance_s=_RESIDENT_OPERATION_ATTRIBUTION_TOLERANCE_S):
    """Which of this run's own firing periods one timed evidence instant
    falls in. Returns (kind, op_name, exact): kind is "post_stop" (at or
    after the stop signal), "startup" (before firing), "operation"
    (inside, or within tolerance_s of, one named operation's own
    reconstructed [start, end] span, op_name naming it), or
    "unattributed" (between fire and stop, but not placeable against any
    operation's own span even with the tolerance — a periodic
    runtime-introspection dump taken between operational-loop cycles,
    say). exact is True for "startup"/"post_stop"/"unattributed"
    (unambiguous by construction) and for an "operation" placed by strict
    containment alone; False for one that needed the tolerance margin or
    had to be disambiguated by nearest distance (see
    _operation_for_instant)."""
    if stopped_at is not None and abs_ts >= stopped_at:
        return 'post_stop', None, True
    if abs_ts < fired_at:
        return 'startup', None, True
    op_name, exact = _operation_for_instant(abs_ts, operation_intervals, tolerance_s)
    if op_name is not None:
        return 'operation', op_name, exact
    return 'unattributed', None, True


def _matching_interval(abs_ts, op_name, operation_intervals, tolerance_s):
    """Whichever operation_intervals entry named op_name abs_ts would
    actually be placed against by _operation_for_instant's own distance
    rule (nearest edge within tolerance_s) - recovering the SPECIFIC
    instance a timestamp-based attribution matched (not merely its
    name), so attribute_evidence's own operation_offsets/
    operation_instances can measure this evidence's own position
    relative to that one instance's start, and name that one instance's
    own id, never firing overall or some other instance of the same
    periodic operation. Returns None when no candidate of that name is
    in reach at all."""
    best, best_dist = None, None
    for iv in operation_intervals:
        if iv.get('op') != op_name or iv.get('start') is None or iv.get('end') is None:
            continue
        if iv['start'] <= abs_ts <= iv['end']:
            dist = 0.0
        elif abs_ts < iv['start']:
            dist = (iv['start'] - abs_ts).total_seconds()
        else:
            dist = (abs_ts - iv['end']).total_seconds()
        if dist <= tolerance_s and (best_dist is None or dist < best_dist):
            best, best_dist = iv, dist
    return best


def attribute_evidence(evidence, fired_at, stopped_at, operation_intervals,
                        root_pid_by_pid=None, pid_to_interval=None):
    """Attributes one package's own timed evidence records to this run's
    firing periods.

    A short-lived subject's own evidence (an exec/open recorded under a
    strace pid this run's own process-tree reconstruction ties to one
    specific curl/git/openssl invocation, or a descendant of one — see
    root_pid_by_pid, from _simulate_process_tree) is attributed to its
    own operation instance by process identity via pid_to_interval,
    never by timestamp: occurrences.jsonl's own osops "exec" record
    names exactly the pid that execs the short-lived command directly,
    the same pid (or an ancestor a descendant's own root traces back to)
    strace's own trace.<pid> files are keyed by. Matching by pid
    sidesteps the timing drift strace's own added latency introduces
    between a shell script's own logged instant and the syscall strace
    itself observed — drift that otherwise leaves most of a short-lived
    command's own evidence outside even its own operation's reconstructed
    span, since the shell logs its own timestamp only after several more
    exec()s of its own (reading the process's start time, then the wall
    clock), each one individually slowed by strace's per-syscall
    overhead.

    Evidence with no pid to resolve this way (every source but strace,
    and strace evidence from a resident-subject pid) is instead placed
    by its own timestamp against each operation's reconstructed span via
    classify_evidence_period, which allows a small margin and picks the
    nearest span when more than one is in reach — a resident delayed
    load's own logged instant and the operation's own occurrence-derived
    span come from the same process, so there is no cross-process
    identity ambiguity to resolve by pid, but the two can still drift a
    fraction of a second apart under strace.

    Evidence this run could not time or place at all (no ts_relative_s,
    or no fired_at for this run) contributes to none of the counts below
    and is not attributed anywhere: absence of a timestamp is not
    evidence of any particular period. Short-lived evidence whose own
    root pid this run's own operations.jsonl carries no matching
    instance for (an incomplete log, say) is instead reported directly
    as "unattributed" — a real attribution shortfall this run's own data
    could not resolve, never guessed at by timestamp for this subject.

    Returns (used_at_startup: bool, used_during_operations: sorted list,
    evidence_periods: {"startup": n, "operations": {op: n},
    "operations_nearest": {op: n}, "post_stop": n, "unattributed": n},
    operation_offsets: {op: float}, operation_instances: sorted list).
    "operations_nearest" is the subset of "operations" placed via the
    tolerance/nearest method rather than strict containment or a direct
    pid match, kept apart so a caller can see how much of the attribution
    rests on the less certain of the two methods.

    operation_offsets is this package's own EARLIEST use during each
    operation, measured as seconds past that SPECIFIC instance's own
    start (never past firing overall, and never averaged or taken from
    the last instance) - a different measurement run's own instance of
    the same operation starts at a different wall-clock time entirely,
    but "how far into its own run of the operation" is the one thing
    about this timing that is portable across the two runs at all (see
    coverage.py's own main_membership, which maps this offset onto a
    measurement run's own matching instance to judge whether the use it
    describes actually falls before that run's own window closes).

    operation_instances is every SPECIFIC operation instance's own id
    (operations.jsonl's own "id" field for whichever record this run's
    own read_operation_intervals built that instance's [start, end] span
    from) this package's evidence was actually placed against - a
    short-lived subject's own instance found via pid_to_interval, a
    resident one's via the same nearest-match _matching_interval finds
    for its own operation_offsets. Never just the operation's own NAME:
    a periodic osops_ operation repeats many times, and coverage.py's
    own osops_pairing only ever verifies a PREFIX of those instances
    against a given measurement run (see truth.py's own
    compare_operation_records) - a package whose only evidence ties to
    an instance beyond that verified prefix is not confirmed consistent
    with any particular measurement run's own behavior just because the
    operation's own NAME matches.

    instance_offsets: {instance_id: float} is the SAME offset as
    operation_offsets, but keyed by the specific instance id rather than
    the operation's own repeating name - what coverage.py's own
    main_membership needs to apply an offset only within the exact
    truth-instance-to-measurement-instance correspondence osops_pairing
    names, rather than onto "any measurement instance sharing the same
    operation name", which could be one this run's own re-comparison
    never actually verified against this specific truth instance at all.
    """
    used_at_startup = False
    ops = set()
    counts = {'startup': 0, 'operations': {}, 'operations_nearest': {}, 'post_stop': 0, 'unattributed': 0}
    op_offsets = {}
    instance_ids = set()
    instance_offsets = {}

    def note_offset(op_name, instance_id, instant, start):
        if start is None:
            return
        offset = (instant - start).total_seconds()
        if op_name not in op_offsets or offset < op_offsets[op_name]:
            op_offsets[op_name] = offset
        if instance_id is not None and (instance_id not in instance_offsets or offset < instance_offsets[instance_id]):
            instance_offsets[instance_id] = offset

    if fired_at is None:
        return used_at_startup, sorted(ops), counts, op_offsets, sorted(instance_ids), instance_offsets
    root_pid_by_pid = root_pid_by_pid or {}
    pid_to_interval = pid_to_interval or {}

    def place(kind, op_name=None, nearest=False):
        nonlocal used_at_startup
        if kind == 'startup':
            used_at_startup = True
            counts['startup'] += 1
        elif kind == 'post_stop':
            counts['post_stop'] += 1
        elif kind == 'operation':
            ops.add(op_name)
            counts['operations'][op_name] = counts['operations'].get(op_name, 0) + 1
            if nearest:
                counts['operations_nearest'][op_name] = counts['operations_nearest'].get(op_name, 0) + 1
        else:
            counts['unattributed'] += 1

    for e in evidence:
        pid = e.get('pid')
        root_pid = root_pid_by_pid.get(pid) if pid is not None else None
        if root_pid is not None:
            interval = pid_to_interval.get(root_pid)
            if interval is None:
                place('unattributed')
                continue
            instant = interval['start'] or interval['end']
            if instant is None:
                place('unattributed')
                continue
            if stopped_at is not None and instant >= stopped_at:
                place('post_stop')
            elif instant < fired_at:
                place('startup')
            else:
                place('operation', interval['op'])
                # The offset needs this evidence's own ACTUAL instant
                # (this same strace record's own ts_relative_s), never
                # the matched instance's own start/end substituted in
                # for it - "instant" above is a stand-in used only for
                # PERIOD classification (startup/operation/post_stop),
                # deliberately chosen over this evidence's own timestamp
                # because strace's own per-syscall drift can otherwise
                # misclassify which period a short-lived command's
                # evidence falls in at all (see this function's own
                # docstring). That drift risk does not apply here: once
                # the period is already settled as "operation", the
                # offset only needs to measure how far into it this
                # evidence's own instant actually falls, and substituting
                # the instance's own start for it would silently always
                # measure a zero offset - hiding a real difference
                # between "used right at the start" and "used well
                # after starting", which coverage.py's own main_membership
                # depends on for a genuinely late use to stay unconfirmed
                # once mapped onto a measurement run's own tighter window.
                own_rel = e.get('ts_relative_s')
                own_instant = fired_at + timedelta(seconds=own_rel) if own_rel is not None else instant
                note_offset(interval['op'], interval.get('id'), own_instant, interval.get('start'))
                if interval.get('id') is not None:
                    instance_ids.add(interval['id'])
            continue
        rel = e.get('ts_relative_s')
        if rel is None:
            continue
        abs_ts = fired_at + timedelta(seconds=rel)
        # The tolerance/nearest margin is for strace's own per-syscall
        # timing drift (see classify_evidence_period): a real instant,
        # off by a fraction of a second. A runtime-introspection
        # snapshot is not that - it is a periodic dump taken at whatever
        # later checkpoint the runtime happens to reach, always AT OR
        # AFTER the module was actually loaded, sometimes long after
        # (the "after_lazy" checkpoint fires once only, after every lazy
        # trigger has already run, not right after each one) - so
        # "nearest" would systematically favor whichever operation last
        # ran before the checkpoint, not the one that actually loaded
        # the module. Introspection evidence is placed by strict
        # containment only; a snapshot instant that lands in the gap
        # between the operation that actually loaded it and the next
        # checkpoint is correctly left unattributed rather than credited
        # to whatever operation happens to be nearby.
        tolerance = 0.0 if e.get('source') == 'runtime_introspection' else _RESIDENT_OPERATION_ATTRIBUTION_TOLERANCE_S
        kind, op_name, exact = classify_evidence_period(
            abs_ts, fired_at, stopped_at, operation_intervals, tolerance_s=tolerance)
        place(kind, op_name, nearest=not exact)
        if kind == 'operation':
            matched = _matching_interval(abs_ts, op_name, operation_intervals, tolerance)
            if matched is not None:
                note_offset(op_name, matched.get('id'), abs_ts, matched.get('start'))
                if matched.get('id') is not None:
                    instance_ids.add(matched['id'])
    return used_at_startup, sorted(ops), counts, op_offsets, sorted(instance_ids), instance_offsets


# --- inventory (I): every bundled package, independent of any log --------
#
# Every inventory key is the three-part (ecosystem, name, version): a
# name-only key cannot tell apart two different versions of the same
# package bundled at once, which case 27's own node_modules tree actually
# does for several of npm's own transitive dependencies (a version an
# outer package needs conflicts with the version already hoisted to the
# top, so npm nests a second copy inside the package that needed it), and
# which two different Python site-packages placements can also do for the
# same-named distribution. Treating those as one inventory entry would
# silently merge a used copy and an unused one into a single,
# wrongly-labeled outcome.

def export_container_rootfs(cid, tmp):
    """Exports a docker-create'd container's entire filesystem with
    `docker export` and extracts it under tmp, skipping /proc, /sys and
    /dev entirely: these are runtime pseudo-filesystems with nothing of
    their own inside a container's own image layers, populated only once
    a container actually runs, so a `docker create`'d-but-never-started
    container has nothing real under them to lose by skipping. Every
    other top-level area is kept, so this run's own Python/Node/Java
    discovery below is never limited to a fixed candidate list the way
    the OS package database's own extraction still deliberately is (a
    separate, targeted copy — see gtb.extract_os_db — since only the
    language-ecosystem inventory needs to scan the whole tree).

    Returns (rootfs_dir, scan_record): scan_record carries the excluded
    areas and reasons, and every archive member this run could not
    extract, for this run's own inventory_scan record.
    """
    rootfs_dir = os.path.join(tmp, 'rootfs')
    os.makedirs(rootfs_dir, exist_ok=True)
    excluded = [
        {'path': '/proc', 'reason': 'runtime pseudo-filesystem; populated only while a container actually runs'},
        {'path': '/sys', 'reason': 'runtime pseudo-filesystem; populated only while a container actually runs'},
        {'path': '/dev', 'reason': 'runtime device nodes; populated only while a container actually runs'},
    ]
    excluded_names = ('proc', 'sys', 'dev')
    excluded_prefixes = tuple(f'{n}/' for n in excluded_names)

    tar_path = os.path.join(tmp, 'rootfs.tar')
    with open(tar_path, 'wb') as f:
        export = subprocess.run(['docker', 'export', cid], stdout=f, stderr=subprocess.PIPE)
    if export.returncode != 0:
        return rootfs_dir, {
            'excluded': excluded,
            'extraction_failures': [f'docker export failed: {export.stderr.decode(errors="replace")}'],
            'entries_extracted': 0, 'ok': False,
        }

    extraction_failures = []
    entries_extracted = 0
    try:
        tf = tarfile.open(tar_path)
    except tarfile.TarError as e:
        return rootfs_dir, {'excluded': excluded, 'extraction_failures': [f'tar open failed: {e}'],
                             'entries_extracted': 0, 'ok': False}
    with tf:
        for member in tf:
            name = member.name.lstrip('./')
            if not name or name in excluded_names or name.startswith(excluded_prefixes):
                continue
            try:
                # "fully_trusted" (Python 3.12+'s pre-PEP-706 behavior),
                # never the stricter "data"/"tar" filters: those refuse
                # an absolute-target symlink outright (update-alternatives
                # and plenty of ordinary shared-library symlinks use one),
                # which is a real extraction gap for this tool's own
                # fully-trusted source - this run's own `docker export` of
                # an image it built itself, not untrusted third-party
                # archive content the safety filters are meant to guard
                # against.
                tf.extract(member, path=rootfs_dir, set_attrs=False, filter='fully_trusted')
                entries_extracted += 1
            except (OSError, tarfile.TarError) as e:
                extraction_failures.append(f'{name}: {e}')
    try:
        os.remove(tar_path)
    except OSError:
        pass
    return rootfs_dir, {
        'excluded': excluded, 'extraction_failures': extraction_failures,
        'entries_extracted': entries_extracted, 'ok': True,
    }


def _rootfs_local_path(rootfs_dir, image_path):
    """The on-disk copy, under this run's own exported rootfs, of one
    absolute image path. Every ecosystem-specific resolver below and
    resolve_used_path share this one translation now that discovery is
    not confined to a single, fixed application directory."""
    if rootfs_dir is None or not image_path.startswith('/'):
        return None
    return os.path.join(rootfs_dir, image_path[1:])


def _image_path_from_local(rootfs_dir, local_path):
    rel = os.path.relpath(local_path, rootfs_dir)
    return '/' + rel.replace(os.sep, '/')


_SYMLINK_CHAIN_MAX_DEPTH = 10


def resolve_rootfs_path(image_path, rootfs_dir):
    """Resolves image_path entirely against this run's own exported
    rootfs, component by component, the way a real chroot would — never
    the host's own filesystem, which almost certainly has its own
    unrelated file at many of the same absolute paths (/etc/passwd,
    /run, /usr/bin/...).

    This is not just a trailing symlink chain on the final component
    (/usr/bin/awk -> /etc/alternatives/awk -> /usr/bin/mawk, say,
    Debian's own update-alternatives mechanism): an INTERMEDIATE
    directory component can be a symlink too (/var/run -> /run, or an
    absolute-target link some other layer added). Handing a single
    fully-built local path straight to lexists/islink/stat, as an
    earlier version of this function did, only ever protects the final
    component - the kernel itself resolves every symlink it encounters
    along the way, and an absolute intermediate target is resolved by
    the kernel against the REAL filesystem root, not rootfs_dir,
    silently escaping the export the instant the host happens to have
    anything at that same absolute path (which /run, /etc, /var and
    friends very often do). Resolving one component at a time and
    re-rooting every absolute target at rootfs_dir's own root (never at
    the real "/") before checking anything about it is what keeps the
    whole walk inside the export, the same way a chroot jail would.

    Returns (resolved_image_path, state): state is "resolved" (every
    component exists in this run's own rootfs and the final target is
    not itself a symlink) - which ALSO covers image_path simply not
    existing in this rootfs at all, PROVIDED no symlink was ever
    followed while looking for it: a path this run observed being used
    is not necessarily one this run's own export ever captured (an
    ephemeral file under a tmpfs mount like /run, say, which `docker
    export` never sees live content for at all), and that is a fact
    about the path's own place in the filesystem, not a broken link
    this function found; "broken" (a component along a symlink's own
    TARGET does not exist, the chain is circular, or it runs deeper
    than a normal alternatives setup ever would - a malformed or
    adversarial chain); or "unavailable" (rootfs_dir was not given at
    all, so nothing here could be checked against it either way, and
    image_path is returned unchanged).
    """
    if rootfs_dir is None:
        return image_path, 'unavailable'
    if not image_path.startswith('/'):
        return image_path, 'broken'
    remaining = [c for c in image_path.split('/') if c not in ('', '.')]
    resolved = []
    hops_left = _SYMLINK_CHAIN_MAX_DEPTH
    # Whether any symlink has been followed yet: a missing component
    # found while still walking image_path's own original components
    # (never having substituted in anyone's symlink target) means
    # image_path itself simply is not present in this rootfs at all -
    # "resolved" in the sense that nothing about the WALK is broken,
    # only that this exact path was not exported. A missing component
    # found after following at least one symlink's own target is a
    # genuine dangling link, and IS broken.
    followed_any_link = False
    while remaining:
        comp = remaining.pop(0)
        if comp == '..':
            if resolved:
                resolved.pop()
            continue
        candidate = '/' + '/'.join(resolved + [comp])
        local = _rootfs_local_path(rootfs_dir, candidate)
        if local is None or not os.path.lexists(local):
            if not followed_any_link:
                # Still walking image_path's own original components,
                # with no symlink target ever substituted in: return it
                # completely unchanged, the same way an earlier version
                # of this function did when the whole path's own first
                # lookup came up empty, rather than a partial prefix of
                # it - a caller comparing resolved_path != path must see
                # them as identical here, not a spurious partial match.
                return image_path, 'resolved'
            return candidate, 'broken'
        if not os.path.islink(local):
            resolved.append(comp)
            continue
        if hops_left <= 0:
            return candidate, 'broken'
        hops_left -= 1
        followed_any_link = True
        try:
            target = os.readlink(local)
        except OSError:
            return candidate, 'broken'
        target_parts = [c for c in target.split('/') if c not in ('', '.')]
        if target.startswith('/'):
            # Re-root at THIS rootfs's own "/", never the host's real
            # root: everything named by an absolute symlink target is
            # resolved from scratch, the same way this whole function
            # resolves image_path itself.
            remaining = target_parts + remaining
            resolved = []
        else:
            # Relative to the symlink's own containing directory
            # (resolved, the path so far - comp itself is the symlink,
            # not a directory to descend into).
            remaining = target_parts + remaining
    final = '/' + '/'.join(resolved) if resolved else '/'
    return final, 'resolved'


def discover_python_site_roots(rootfs_dir):
    """Every directory anywhere under the exported rootfs that directly
    holds a *.dist-info or *.egg-info entry — one Python environment's
    own site-packages placement each — found by walking the whole
    filesystem rather than a fixed candidate list, so a venv, a bare
    home-directory user install, or any other placement is found the
    same way a conventional site-packages is. Returns [(image_dir,
    local_dir), ...] in gtb.build_python_index's own site_roots shape,
    one entry per distinct placement."""
    if rootfs_dir is None or not os.path.isdir(rootfs_dir):
        return []
    seen = {}
    for root, dirs, _files in os.walk(rootfs_dir):
        if any(d.endswith('.dist-info') or d.endswith('.egg-info') for d in dirs):
            seen.setdefault(root, _image_path_from_local(rootfs_dir, root))
    return [(image_dir, local_dir) for local_dir, image_dir in seen.items()]


def collect_python_distributions_by_root(site_roots):
    """Every (name, version) this run can read a distribution's own
    METADATA/PKG-INFO for, kept separately per site root (per
    environment/placement) rather than merged into one name-keyed dict:
    two different placements can each bundle their own version of the
    same-named distribution at once (a venv pinning an older version
    alongside a newer one already installed system-wide, say), and a
    single flat dict would let the second one read silently overwrite the
    first's version for that name.

    Returns (by_root: {image_dir: {name: version}}, read_failures: list).
    name is PEP 503 normalized, matching gtb.normalize_py_name so this
    and a resolved-path lookup use the same string for the same package.
    A read_failures entry names a dist-info/egg-info directory this could
    not read a name from at all.
    """
    by_root = {}
    read_failures = []
    for image_dir, local_dir in site_roots:
        versions = {}
        if os.path.isdir(local_dir):
            for entry in sorted(os.listdir(local_dir)):
                full = os.path.join(local_dir, entry)
                if entry.endswith('.dist-info') and os.path.isdir(full):
                    name, version = gtb.read_kv_metadata(os.path.join(full, 'METADATA'))
                    if name:
                        versions[gtb.normalize_py_name(name)] = version
                    else:
                        read_failures.append({'site_root': image_dir, 'entry': entry,
                                               'reason': 'no readable Name:/Version: in METADATA'})
                elif entry.endswith('.egg-info') and os.path.isdir(full):
                    name, version = gtb.egg_info_metadata(full)
                    if name:
                        versions[gtb.normalize_py_name(name)] = version
                    else:
                        read_failures.append({'site_root': image_dir, 'entry': entry,
                                               'reason': "no readable name from PKG-INFO or the directory's own name"})
        by_root[image_dir] = versions
    return by_root, read_failures


def collect_python_distributions(site_roots):
    """A single-environment convenience view over
    collect_python_distributions_by_root: every (name, version) merged
    into one flat dict. Used only where a single environment's own
    inventory is all that is being asked for; build_inventory below never
    merges this way itself, since that is exactly the cross-environment
    loss the per-environment keeping exists to avoid."""
    by_root, _read_failures = collect_python_distributions_by_root(site_roots)
    merged = {}
    for versions in by_root.values():
        merged.update(versions)
    return merged


def find_owning_site_root(path, site_roots):
    """The (image_dir, local_dir) site root that owns an observed path —
    the longest-matching image_dir prefix, since this design's own
    placements are never nested one inside another. None when no known
    site root is a prefix of path at all."""
    best = None
    for image_dir, local_dir in site_roots:
        prefix = image_dir if image_dir.endswith('/') else image_dir + '/'
        if path == image_dir or path.startswith(prefix):
            if best is None or len(image_dir) > len(best[0]):
                best = (image_dir, local_dir)
    return best


def python_owner_with_versions(path, py_exact, py_prefixes, site_roots, versions_by_root):
    """Resolves one observed path to its owning distribution name(s) via
    gtb.python_owner exactly as before, then joins each name to the
    SPECIFIC version the path's own site root/environment bundles — never
    a flat, cross-environment name->version table, which would silently
    pick whichever environment's version happened to be read last when
    two placements bundle the same name. Returns a list of (name,
    version) pairs, or None when the path owns no distribution at all."""
    names = gtb.python_owner(path, py_exact, py_prefixes)
    if not names:
        return None
    root = find_owning_site_root(path, site_roots)
    if root is None:
        # A .pyc's own directory is one level below its site root's
        # equivalent .py, when a RECORD only lists the source: the same
        # translation gtb.python_owner itself falls back on, applied here
        # so the corresponding site root is still found.
        src = gtb.pycache_to_source(path)
        if src:
            root = find_owning_site_root(src, site_roots)
    root_versions = versions_by_root.get(root[0], {}) if root else {}
    return [(name, root_versions.get(name)) for name in names]


def _read_package_json(manifest):
    """(name, version) from one package.json, or None when it cannot be
    read or parsed at all."""
    if not os.path.exists(manifest):
        return None
    try:
        with open(manifest, encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except (ValueError, OSError):
        return None
    return data.get('name'), data.get('version')


def collect_node_packages(rootfs_dir):
    """Every (name, version) this run can read from a package.json
    anywhere under the exported rootfs — not only ones inside a
    node_modules directory — matching what Trivy's own node-pkg analyzer
    lists for a --list-all-pkgs scan against the same image: every
    node_modules copy at any nesting depth (npm's own bundled tooling
    and any other global install included, the same as any nested
    dependency's own node_modules), the workload's own root manifest, and
    any other tool's own bundled manifest a Dockerfile happened to lay
    down outside node_modules entirely (an extracted yarn distribution,
    say). Only /proc, /sys and /dev are ever excluded, at the rootfs
    export stage; nothing here narrows the search further, since the
    bundled-package population this is meant to match is Trivy's own,
    not a guess at which of these a running workload could ever load.

    Returned as a set of (name, version) pairs rather than a dict, so two
    differently versioned copies bundled under the same name are both
    kept as distinct inventory entries instead of one overwriting the
    other.

    Returns (pkgs: set, manifest_owner: {image_dir: (name, version)},
    read_failures: list, manifests_found: int). manifest_owner is keyed
    by the image-absolute directory each readable manifest lives in —
    every one this run's own ledger walk recorded, not only ones under a
    node_modules directory — for nearest_owning_manifest below to resolve
    an observed file against. A package.json this run found but that
    could not be parsed, or that parsed but named no name/version at
    all, is kept out of both pkgs and manifest_owner and reported in
    read_failures instead of being guessed at or silently dropped.
    """
    pkgs = set()
    manifest_owner = {}
    read_failures = []
    manifests_found = 0
    if not rootfs_dir or not os.path.isdir(rootfs_dir):
        return pkgs, manifest_owner, read_failures, manifests_found
    for root, _dirs, files in os.walk(rootfs_dir):
        if 'package.json' not in files:
            continue
        manifest = os.path.join(root, 'package.json')
        manifests_found += 1
        parsed = _read_package_json(manifest)
        if parsed is None:
            read_failures.append({'manifest': manifest,
                                   'reason': 'package.json exists but could not be read/parsed'})
            continue
        name, version = parsed
        if name and version:
            pkgs.add((name, version))
            manifest_owner[_image_path_from_local(rootfs_dir, root)] = (name, version)
        else:
            read_failures.append({'manifest': manifest,
                                   'reason': f'missing name and/or version (name={name!r}, version={version!r})'})
    return pkgs, manifest_owner, read_failures, manifests_found


def nearest_owning_manifest(path, manifest_owner):
    """The (name, version) of the nearest enclosing package.json this
    run's own ledger walk recorded (manifest_owner, from
    collect_node_packages), found by walking up path's own directory
    tree one directory at a time until a directory the ledger itself
    holds a manifest for is reached. Not limited to a node_modules
    boundary the way resolving purely through node_modules nesting would
    be: a path under the workload's own root manifest (/app/server.js,
    say, with /app/package.json as the nearest owner), or under any
    other tool's own bundled manifest laid down outside node_modules
    entirely, resolves the same way a node_modules package's own file
    does — the same population the ledger itself now covers (see
    collect_node_packages). Two differently versioned copies of the same
    name nested at different depths each still resolve to their own
    nearest manifest's own version, never to whichever copy the
    inventory walk happened to visit first. Returns None once the walk
    reaches the filesystem root without finding an owner."""
    d = os.path.dirname(path)
    while True:
        owner = manifest_owner.get(d)
        if owner is not None:
            return owner
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


# Maven coordinate (groupId:artifactId) -> version, read from one jar's own
# META-INF/maven/*/*/pom.properties. Unlike gtb.py's _pom_properties_scan
# (which this tool deliberately does not modify, since gtb_test.py's own
# tests fix its current return shape), this also keeps each pom's version
# field, because a truth-only version join needs it and gtb.py's
# measurement-run path_packages resolution never has to compare versions
# at all. Nested jars are not followed: none of cases 26-28's own jars is
# a fat jar packing others, so the shallow scan this needs is simpler than
# gtb.py's recursive one without losing anything for these fixtures.
def read_jar_pom_versions(jar_path):
    import zipfile
    versions = {}
    try:
        with zipfile.ZipFile(jar_path) as zf:
            for name in zf.namelist():
                if not gtb.POM_PROPERTIES_RE.match(name):
                    continue
                try:
                    raw = zf.read(name)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                props = {}
                for line in raw.decode('utf-8', 'replace').splitlines():
                    if '=' in line and not line.strip().startswith('#'):
                        k, _, v = line.partition('=')
                        props[k.strip()] = v.strip()
                group, artifact, version = props.get('groupId'), props.get('artifactId'), props.get('version')
                if group and artifact and version:
                    versions[f'{group}:{artifact}'] = version
    except (zipfile.BadZipFile, OSError):
        pass
    return versions


def collect_java_jars(rootfs_dir):
    """Every jar anywhere under the exported rootfs — not only the
    application's own directory — resolved through jar_owner_at exactly
    as gtb.py resolves an observed jar path, with its version read from
    the same jar's own pom.properties where one exists. Returns
    (versioned, version_unknown, read_failures): versioned is a set of
    (coordinate, version) pairs fit for the inventory; version_unknown
    lists jars this run can name (by Maven coordinate, or by file name
    when it carries no Maven metadata at all) but not assign a specific
    version to, which is kept out of the inventory rather than guessing;
    read_failures lists a jar this run could not even read from disk."""
    versioned = set()
    version_unknown = []
    read_failures = []
    if not rootfs_dir or not os.path.isdir(rootfs_dir):
        return versioned, version_unknown, read_failures
    for root, _dirs, files in os.walk(rootfs_dir):
        for fn in sorted(files):
            if not fn.endswith('.jar'):
                continue
            local_path = os.path.join(root, fn)
            image_path = _image_path_from_local(rootfs_dir, local_path)
            if not os.access(local_path, os.R_OK):
                read_failures.append({'jar_path': local_path, 'reason': 'not readable'})
                continue
            state, value = gtb.jar_owner_at(local_path, image_path)
            pom_versions = read_jar_pom_versions(local_path)
            if state == 'packages':
                for coord in value:
                    version = pom_versions.get(coord) or _jar_version_guess(fn)
                    if version:
                        versioned.add((coord, version))
                    else:
                        version_unknown.append({'name': coord, 'jar_path': local_path})
            else:
                # A jar this run cannot attribute to Maven coordinates at
                # all (the case's own compiled app.jar/lazy-classes.jar,
                # or a third-party jar with no embedded pom.properties)
                # has no name a truth-vs-plan comparison could use either,
                # so it is recorded as version-unknown by its file name
                # rather than entered into the inventory under a name
                # nothing else would ever resolve to.
                version_unknown.append({'name': fn, 'jar_path': local_path})
    return versioned, version_unknown, read_failures


def _jar_version_guess(filename):
    m = gtb.JAR_NAME_RE.match(filename)
    return m.group('version') if m else None


def build_inventory(image_id, tmp):
    """Builds I directly from the image's own full container filesystem:
    independent of any usage log, and not confined to a fixed candidate
    list of Python/Node/Java placements the way a single application
    directory or a short list of conventional site-packages paths would
    be. Returns (inventory, version_unknown, resolution_context,
    inventory_scan): version_unknown lists jars this run can name but not
    version, kept out of I; resolution_context is what resolve_used_path
    needs; inventory_scan records the scan's own range, sources, and
    failures for this run's own truth.json.
    """
    cid = subprocess.run(['docker', 'create', image_id], capture_output=True, text=True).stdout.strip()
    try:
        owners, os_versions, os_db_available = gtb.extract_os_db(cid, tmp)
        rootfs_dir, rootfs_scan = export_container_rootfs(cid, tmp)

        py_site_roots = discover_python_site_roots(rootfs_dir)
        py_exact, py_prefixes = gtb.build_python_index(py_site_roots)
        py_versions_by_root, py_read_failures = collect_python_distributions_by_root(py_site_roots)

        node_packages, node_manifest_owner, node_read_failures, node_manifests_found = collect_node_packages(rootfs_dir)
        java_versioned, java_unknown, java_read_failures = collect_java_jars(rootfs_dir)

        inventory = {}
        for name, version in sorted(os_versions.items()):
            inventory[('os', name, version)] = {'resolution': 'os-db'}
        for image_dir, versions in sorted(py_versions_by_root.items()):
            for name, version in sorted(versions.items()):
                inventory[('python', name, version)] = {'resolution': 'python-record', 'site_root': image_dir}
        for name, version in sorted(node_packages):
            inventory[('node', name, version)] = {'resolution': 'node-package'}
        for coord, version in sorted(java_versioned):
            inventory[('java', coord, version)] = {'resolution': 'jar-pom'}

        context = {
            'owners': owners, 'os_versions': os_versions,
            'py_exact': py_exact, 'py_prefixes': py_prefixes,
            'py_site_roots': py_site_roots, 'py_versions_by_root': py_versions_by_root,
            'rootfs_dir': rootfs_dir, 'os_db_available': os_db_available,
            'node_manifest_owner': node_manifest_owner,
            # Populated by resolve_used_path as it runs (see
            # resolve_rootfs_path): a path whose own symlink
            # chain broke and which no owner could be found for even
            # via its original spelling - a real completeness gap, fed
            # into main()'s own gate once every used path has been
            # resolved.
            'os_symlink_resolution_failures': [],
        }
        inventory_scan = {
            'scan_root': "/ (the container's own full filesystem, exported and extracted locally)",
            'excluded': rootfs_scan.get('excluded', []),
            'extraction_failures': rootfs_scan.get('extraction_failures', []),
            'rootfs_export_ok': rootfs_scan.get('ok', False),
            'os_db': {
                'source': 'dpkg /var/lib/dpkg or apk /lib/apk/db/installed, copied directly rather than through the rootfs export',
                'available': os_db_available,
            },
            'python': {
                'site_roots': [d for d, _local in py_site_roots],
                'distributions_found': sum(len(v) for v in py_versions_by_root.values()),
                'read_failures': py_read_failures,
            },
            'node': {
                'manifests_found': node_manifests_found,
                'packages_found': len(node_packages),
                'read_failures': node_read_failures,
            },
            'java': {
                'jars_found': len(java_versioned) + len(java_unknown),
                'read_failures': java_read_failures,
            },
        }
        return inventory, java_unknown, context, inventory_scan
    finally:
        subprocess.run(['docker', 'rm', cid], capture_output=True, text=True)


# --- path -> package conversion, reusing gtb.py's own cascade -------------

def resolve_used_path(path, context):
    """Converts one observed path to inventory keys, using exactly the
    resolution gtb.py's GT-B path_packages uses (no Go check: none of
    cases 26-28 embeds a Go module), joined with this run's own version
    reading for each ecosystem. Returns a list of (ecosystem, name,
    version) keys; version is None when this run cannot read one for that
    specific path (a jar with no readable pom.properties, say) — such a
    key deliberately still comes back, rather than being dropped, so a
    used path with no readable version is visible as its own outcome
    instead of silently vanishing from the used set entirely."""
    keys = []
    pk, _ = gtb.os_lookup(path, context['owners'])
    resolved_path, symlink_state = resolve_rootfs_path(path, context['rootfs_dir'])
    if resolved_path != path:
        pk_resolved, _ = gtb.os_lookup(resolved_path, context['owners'])
        for p in pk_resolved:
            if p not in pk:
                pk = pk + [p]
    if not pk and symlink_state == 'broken':
        context['os_symlink_resolution_failures'].append(path)
    for p in pk:
        keys.append(('os', p, context['os_versions'].get(p)))
    py = python_owner_with_versions(path, context['py_exact'], context['py_prefixes'],
                                     context['py_site_roots'], context['py_versions_by_root'])
    if py:
        for name, version in py:
            keys.append(('python', name, version))
    owned = nearest_owning_manifest(path, context['node_manifest_owner'])
    if owned:
        keys.append(('node', owned[0], owned[1]))
    if path.endswith('.jar'):
        # Uses the SAME rootfs-jailed resolution as the OS-ownership
        # lookup above (resolved_path), rather than stat-ing path's own
        # local mapping directly, so a jar reached through an
        # intermediate symlinked directory is not misread against
        # whatever the host's own real filesystem happens to have at
        # that same absolute path.
        local = _rootfs_local_path(context['rootfs_dir'], resolved_path)
        if local and os.path.exists(local):
            state, value = gtb.jar_owner_at(local, path)
            if state == 'packages':
                pom_versions = read_jar_pom_versions(local)
                for coord in value:
                    version = pom_versions.get(coord) or _jar_version_guess(os.path.basename(path))
                    keys.append(('java', coord, version))
            else:
                keys.append(('java', os.path.basename(path), _jar_version_guess(os.path.basename(path))))
        else:
            keys.append(('java', os.path.basename(path), _jar_version_guess(os.path.basename(path))))
    return keys


# --- OS package subject categorization (resident vs short-lived) ---------

SHORT_LIVED_COMMANDS = ('/usr/bin/curl', '/usr/bin/git', '/usr/bin/openssl')


def classify_exec_subject(path):
    """Whether an executed path belongs to the short-lived operational
    subject (curl/git/openssl themselves) or the resident subject
    (everything else, including the operational loop's own long-running
    shell, per the design rule that a launch shell or scheduler-equivalent
    process is always resident, whatever it repeatedly launches)."""
    return 'short_lived' if path in SHORT_LIVED_COMMANDS else 'resident'


def _trace_pid_from_filename(path):
    """The numeric pid/tid a trace.<pid> file name encodes, or None for a
    file this does not recognize as one (a stray file in the same
    directory)."""
    base = os.path.basename(path)
    _prefix, _sep, suffix = base.partition('.')
    try:
        return int(suffix)
    except ValueError:
        return None


def _read_trace_events(strace_dir):
    """Every trace.<pid> file's own successful-and-usable exec/open
    occurrences plus every clone/fork/vfork/clone3 success, in file
    order, as {pid: [event, ...]}. Each event is one of {'kind': 'exec',
    'path': str}, {'kind': 'open', 'path': str}, or {'kind': 'clone',
    'child_pid': int}. An occurrence this cannot use as positive package
    evidence (a failed call, an unresolved relative path, a directory
    open) never becomes an 'exec'/'open' event here at all, matching
    read_strace_dir's own filtering — but a clone/fork/vfork/clone3
    success is always kept, since it carries the process-tree edge this
    needs even though it is never itself usage evidence."""
    events_by_pid = {}
    for path in sorted(glob.glob(os.path.join(strace_dir, 'trace.*'))):
        pid = _trace_pid_from_filename(path)
        if pid is None:
            continue
        events = []
        lines, _unreconstructed = _read_reconstructed_trace_lines(path)
        for line in lines:
            rec = parse_strace_line(line)
            if rec is not None:
                if rec['ok'] and rec['resolved'] and not rec['is_dir_open']:
                    kind = 'exec' if rec['syscall'] in _EXEC_SYSCALLS else 'open'
                    events.append({'kind': kind, 'path': rec['path']})
                continue
            child_pid = parse_clone_line(line)
            if child_pid is not None:
                events.append({'kind': 'clone', 'child_pid': child_pid})
        events_by_pid[pid] = events
    return events_by_pid


def _simulate_process_tree(strace_dir):
    """Walks the reconstructed process tree once (see read_strace_subjects
    for the reconstruction itself), producing both the per-path subject
    tags read_strace_subjects returns and, for every pid, the pid of the
    short-lived command exec that pid's own short-lived lineage descends
    from (None while a pid is resident throughout its own trace). The
    operational loop's own run_cmd backgrounds the exact process that
    then execs curl/git/openssl directly and captures its pid via $!
    before that exec happens — the same pid occurrences.jsonl's own
    osops "exec" record names — so this root pid is exactly the
    identifier attribute_evidence needs to tie a short-lived descendant's
    own raw evidence back to one specific operation instance, without
    relying on any timestamp agreeing with anything.

    A pid strace -f reports as cloned but whose own trace.<pid> file this
    run has no events for at all (it exited immediately, its creation
    fell outside what this run captured, or the file was simply lost) is
    never dereferenced as though it had one: its own inherited subject
    and root are still recorded (a descendant of ITS OWN might yet be
    findable), but it contributes no events of its own, and is reported
    back in missing_trace_pids rather than raising.

    Returns (subjects_by_path: {path: set(subject)}, root_pid_by_pid:
    {pid: int|None}, missing_trace_pids: sorted list of pids strace
    named as cloned but whose own trace file this run has no events
    for).
    """
    events_by_pid = _read_trace_events(strace_dir)
    if not events_by_pid:
        return {}, {}, []

    parent_of = {}
    for parent_pid, events in events_by_pid.items():
        for ev in events:
            if ev['kind'] == 'clone':
                parent_of[ev['child_pid']] = parent_pid

    children_of = {}
    for child_pid, parent_pid in parent_of.items():
        children_of.setdefault(parent_pid, []).append(child_pid)

    # BFS from every pid this run never saw named as anyone's child (the
    # top-level tracee(s) strace itself attached to) so a pid is only
    # ever simulated once its own inherited starting subject is known.
    # A child pid strace named but whose own trace file carries no
    # events at all is still walked (its own descendants, if it somehow
    # had any despite leaving no trace of its own, must still inherit
    # correctly) but contributes no events of its own below.
    roots = [pid for pid in events_by_pid if pid not in parent_of]
    order = []
    seen = set()
    queue = list(roots)
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        order.append(pid)
        queue.extend(children_of.get(pid, []))

    inherited_subject = {}
    inherited_root = {}
    subjects = {}
    root_pid_by_pid = {}
    missing_trace_pids = []
    for pid in order:
        current = inherited_subject.get(pid, 'resident')
        current_root = inherited_root.get(pid)
        events = events_by_pid.get(pid)
        if events is None:
            missing_trace_pids.append(pid)
            root_pid_by_pid[pid] = current_root if current == 'short_lived' else None
            continue
        for ev in events:
            if ev['kind'] == 'exec':
                # Once a pid is short-lived, a FURTHER exec of its own
                # (into a different program than curl/git/openssl
                # themselves - git's own internal re-exec of a remote
                # helper, say) never demotes it back to resident: the
                # short-lived subject is a property of the invocation
                # this pid IS, not of which exact binary it happens to
                # be running at any one instant. Only a resident pid's
                # own exec of one of the three commands themselves ever
                # starts a new short-lived lineage.
                if current != 'short_lived' and classify_exec_subject(ev['path']) == 'short_lived':
                    current = 'short_lived'
                    # This pid is itself the one occurrences.jsonl's own
                    # osops "exec" record names: the root of this new
                    # short-lived lineage starts here.
                    current_root = pid
                subjects.setdefault(ev['path'], set()).add(current)
            elif ev['kind'] == 'open':
                subjects.setdefault(ev['path'], set()).add(current)
            elif ev['kind'] == 'clone':
                inherited_subject[ev['child_pid']] = current
                inherited_root[ev['child_pid']] = current_root
        root_pid_by_pid[pid] = current_root if current == 'short_lived' else None
    return subjects, root_pid_by_pid, sorted(missing_trace_pids)


def read_strace_subjects(strace_dir):
    """Which subject (resident/short_lived) each OS-owned path was
    observed under. Reconstructs the process tree from every
    clone/fork/vfork/clone3 success strace -f recorded (the calling
    process's own trace names the new pid/tid the call returned), then
    walks it in creation order (a newly created process is only ever
    simulated once its own parent has been): a process starts at
    whichever subject its own parent held at the exact moment it was
    created — inherited, never reset to "resident" as a default the way
    a per-file-only reading would — and its own subject then changes only
    when IT ITSELF execs one of the short-lived commands. This is what
    lets a short-lived command's own child or thread that never execs
    anything of its own (a certificate-loading helper curl spawns, say)
    still be attributed to the short-lived subject: it inherits it at the
    moment it is cloned, the same way any other descendant does.

    A process strace -f reports as cloned but whose own trace.<pid> file
    this run has no events for at all (it exited immediately, or its
    creation fell outside what this run captured) is simply absent from
    the tree walk and contributes nothing further — it left no evidence
    of its own to attribute either way.

    Returns {path: set(subject)}."""
    subjects, _root_pid_by_pid, _missing = _simulate_process_tree(strace_dir)
    return subjects


# --- declared-dependency cross-check --------------------------------------

CASE_ECOSYSTEM = {'26': 'python', '27': 'node', '28': 'java'}


def declaration_gaps(case, inventory):
    """Cross-references the case definition's own coverage_plan (its
    declared used_at_startup/used_lazily/unused groups - the nearest thing
    to the case's dependency declaration a case JSON carries, since this
    tool runs against a built image rather than a checked-out source tree)
    against the inventory this run actually enumerated from that image.

    Returns (declared_missing, undeclared_extra): declared_missing is a
    coverage_plan entry this run's own inventory walk never found at all
    (a real metadata gap - the walk should have found it, or the case's
    plan names something that was never actually installed); undeclared
    extra is an inventory entry in this case's own ecosystem that
    coverage_plan does not mention at all (ordinarily fine - a transitive
    dependency the plan did not itemize - and reported for completeness
    rather than as a problem)."""
    eco = CASE_ECOSYSTEM.get(case.get('case_id'))
    if eco is None:
        return [], []
    plan = case.get('coverage_plan', {})
    declared = set()
    for group in ('used_at_startup', 'used_lazily', 'unused'):
        declared |= set(plan.get(group, []))
    # coverage_plan names a package, not a specific version, so the
    # comparison is by name only even though inventory is now keyed by
    # (ecosystem, name, version).
    inventory_names = {name for (e, name, _v) in inventory if e == eco}
    missing = sorted(declared - inventory_names)
    extra = sorted(inventory_names - declared)
    return missing, extra


# --- completeness --------------------------------------------------------

# A syscall-completion-shaped line ("... = <something>") this tool's own
# grammar (parse_strace_line/parse_clone_line) could not read at all is
# corruption or truncation, not one of the benign non-matches strace's own
# output legitimately contains: a signal-delivery notice or an
# attach/detach announcement. An <unfinished .../resumed> pair is not
# among these: _read_reconstructed_trace_lines (see
# _reconstruct_unfinished_lines) has already turned every one it could
# recognize into a complete line before this function ever sees it, and
# counted every one it could not recognize, or could not pair up, into
# unreconstructed_lines instead of leaving it in the line stream at all -
# so a lingering "<unfinished"/"<... " marker reaching this loop would be
# a bug in that reconstruction, never something to allow through here.
_BENIGN_NON_MATCH_MARKERS = ('+++', '---')


def check_strace_completeness(strace_dir):
    """Independent completeness signals for a strace capture, beyond
    merely having a strace directory at all: whether any trace file
    carries no lines whatsoever (a process this run's own tracer
    attached to but captured nothing from before it exited), and how
    many lines look like a truncated or corrupted syscall completion —
    never a benign strace message this tool's own grammar was never
    meant to match in the first place (see _BENIGN_NON_MATCH_MARKERS).

    Lines are read through the same <unfinished ...>/<... resumed>
    reconstruction every other strace consumer here uses (see
    _read_reconstructed_trace_lines), so a call a signal happened to
    interrupt is judged by its own reconstructed, complete line rather
    than having both of its own halves independently misread as
    corrupted. Every way that reconstruction can fail - an "unfinished"
    never resumed, a "resumed" with nothing pending to pair it to, or a
    split-call marker in a shape neither pattern recognizes - is
    counted in unreconstructed_lines, not unparseable_lines: none of
    them is a syscall-completion-shaped line this tool's own grammar
    failed to parse, so counting them there would conflate two
    different kinds of gap.

    An empty file is a completeness gap only when nothing explains it.
    A thread or child whose creation some other trace file records (a
    clone/clone3/fork/vfork return naming its pid) and that then made
    none of the traced calls before exiting leaves an empty file of its
    own by construction: the tracer did follow it, and there was nothing
    to write. Those files are listed separately as empty_child_files and
    do not count against completeness.

    Returns {'empty_files': [path,...], 'empty_child_files': [path,...],
    'unparseable_lines': int, 'total_files': int,
    'unreconstructed_lines': int}.
    """
    empty_files = []
    empty_child_files = []
    unparseable = 0
    total_files = 0
    unreconstructed_total = 0
    cloned_pids = set()
    empty_candidates = []
    for path in sorted(glob.glob(os.path.join(strace_dir, 'trace.*'))):
        total_files += 1
        has_line = False
        lines, unreconstructed = _read_reconstructed_trace_lines(path)
        unreconstructed_total += unreconstructed
        for stripped in lines:
            if not stripped:
                continue
            has_line = True
            child = parse_clone_line(stripped)
            if child is not None:
                cloned_pids.add(str(child))
            if any(marker in stripped for marker in _BENIGN_NON_MATCH_MARKERS):
                continue
            if _LINE_RE.match(stripped) is not None:
                # The line grammar itself matched - whatever
                # parse_strace_line/parse_clone_line do with it next
                # (skip a syscall this tool has no use for, or a
                # legitimately FAILED clone/fork/vfork/clone3, e.g.
                # glibc's own clone3-support probe returning ENOSYS
                # before it falls back to plain clone()) is domain
                # filtering, not a parse failure.
                continue
            if '= ' not in stripped and not stripped.endswith(('=?', '= ?')):
                # Not shaped like a syscall completion line at all
                # (an strace startup banner, say) - nothing this
                # tool's own grammar was ever meant to read.
                continue
            unparseable += 1
        if not has_line:
            empty_candidates.append(path)
    for path in empty_candidates:
        pid = path.rsplit('.', 1)[-1]
        if pid in cloned_pids:
            empty_child_files.append(path)
        else:
            empty_files.append(path)
    return {'empty_files': empty_files, 'empty_child_files': empty_child_files,
            'unparseable_lines': unparseable, 'total_files': total_files,
            'unreconstructed_lines': unreconstructed_total}


# --- main -------------------------------------------------------------

def _evidence_summary(evidence):
    """(first_seen_s, last_seen_s, hold_seconds) from a list of evidence
    records with a ts_relative_s that may be None (a source this run
    could not time, or a run with no fired_at at all). hold_seconds is
    None whenever fewer than two distinct timed observations exist: a
    single sighting says a package was used at that moment, not for how
    long, and reporting a zero-length hold would look like a specific
    measurement rather than an absence of one."""
    times = sorted(e['ts_relative_s'] for e in evidence if e['ts_relative_s'] is not None)
    if not times:
        return None, None, None
    first, last = times[0], times[-1]
    hold = (last - first) if len(times) > 1 else None
    return first, last, hold


def main():
    if len(sys.argv) < 3:
        print('Usage: truth.py <truth run dir> <case json> [measurement run dir]', file=sys.stderr)
        return 2
    run = sys.argv[1].rstrip('/')
    case = json.load(open(sys.argv[2]))
    measurement_run = sys.argv[3].rstrip('/') if len(sys.argv) > 3 else None

    image_id = open(f'{run}/image_id.txt').read().strip()
    varlog = f'{run}/varlog'
    strace_dir = f'{varlog}/strace'
    fired_at = read_instant_file(f'{run}/ready_at.txt') or read_instant_file(f'{run}/fired_at.txt')
    stopped_at = read_instant_file(f'{run}/stopped_at.txt')
    if fired_at is None:
        print(f'{run}: no ready_at.txt/fired_at.txt; evidence timestamps will be unavailable', file=sys.stderr)

    tmp = tempfile.mkdtemp(prefix='truthdb-')
    # This run's own exported rootfs (see export_container_rootfs)
    # lives under tmp for the rest of this function's own use of
    # context['rootfs_dir'] - removed again once this run is done with
    # it (even on an exception partway through), so a truth.py
    # invocation never leaves its own multi-hundred-megabyte rootfs
    # export behind in /tmp. KL_TRUTH_KEEP_TMP=1 skips the cleanup, for
    # inspecting the export by hand.
    try:
        inventory, java_version_unknown, context, inventory_scan = build_inventory(image_id, tmp)

        strace_used, strace_unresolved, strace_failed, strace_evidence = (set(), [], 0, {})
        if os.path.isdir(strace_dir):
            strace_used, strace_unresolved, strace_failed, strace_evidence = read_strace_dir(
                strace_dir, fired_at, context['rootfs_dir'])
        else:
            print(f'{run}: no varlog/strace directory; used/unused cannot be certified from strace alone', file=sys.stderr)

        runtime_used, runtime_unresolved, runtime_evidence, runtime_held = read_runtime_modules(
            f'{varlog}/runtime-modules.jsonl', fired_at)
        subjects_by_path, root_pid_by_pid, missing_trace_pids = (
            _simulate_process_tree(strace_dir) if os.path.isdir(strace_dir) else ({}, {}, []))
        exec_hold_by_path = read_usage_exec_hold_seconds(f'{varlog}/usage.jsonl')
        operation_intervals = read_operation_intervals(
            f'{varlog}/operations.jsonl', f'{varlog}/occurrences.jsonl', f'{varlog}/usage.jsonl')
        # Every short-lived operation instance's own launching pid, straight
        # from its own occurrence — see attribute_evidence for why this
        # (rather than the interval's own timing) is what ties a short-lived
        # subject's raw evidence back to one specific instance.
        pid_to_interval = {iv['pid']: iv for iv in operation_intervals if iv.get('pid') is not None}

        all_paths = strace_used | runtime_used
        used_keys = {}  # (ecosystem, name, version) -> {"evidence": [...], "subjects": set(), "paths": set()}
        used_version_unknown = []
        unmapped_paths = []
        for path in sorted(all_paths):
            keys = resolve_used_path(path, context)
            if not keys:
                unmapped_paths.append(path)
                continue
            path_evidence = strace_evidence.get(path, []) + runtime_evidence.get(path, [])
            for key in keys:
                eco, name, version = key
                if version is None:
                    used_version_unknown.append({
                        'ecosystem': eco, 'name': name, 'path': path,
                        'evidence': sorted({e['source'] for e in path_evidence}),
                    })
                    continue
                entry = used_keys.setdefault(key, {'evidence': [], 'subjects': set(), 'paths': set()})
                entry['evidence'].extend(path_evidence)
                entry['paths'].add(path)
                entry['subjects'] |= subjects_by_path.get(path, set())

        all_used = []
        for (eco, name, version), info in sorted(used_keys.items()):
            first_s, last_s, hold_s = _evidence_summary(info['evidence'])
            exec_holds = [d for p in info['paths'] for d in exec_hold_by_path.get(p, [])]
            (used_at_startup, used_during_operations, evidence_periods, operation_offsets, operation_instances,
             operation_instance_offsets) = attribute_evidence(
                info['evidence'], fired_at, stopped_at, operation_intervals,
                root_pid_by_pid=root_pid_by_pid, pid_to_interval=pid_to_interval)
            held_evidence = [
                {'path': p, 'phase': h.get('phase'), 'ts_relative_s': h.get('ts_relative_s')}
                for p in sorted(info['paths']) for h in runtime_held.get(p, [])
            ]
            all_used.append({
                'ecosystem': eco, 'name': name, 'version': version,
                'in_inventory': (eco, name, version) in inventory,
                'evidence': sorted({e['source'] for e in info['evidence']}),
                'evidence_types': sorted({e['type'] for e in info['evidence']}),
                'subjects': sorted(info['subjects']) or ['resident'],
                'paths': sorted(info['paths']),
                'first_seen_s': first_s,
                'last_seen_s': last_s,
                'hold_seconds': hold_s,
                'exec_hold_seconds_min': min(exec_holds) if exec_holds else None,
                'used_at_startup': used_at_startup,
                'used_during_operations': used_during_operations,
                'evidence_periods': evidence_periods,
                # This package's own earliest use during each operation,
                # measured as seconds past THAT SPECIFIC instance's own
                # start (see attribute_evidence) - the only part of this
                # run's own timing that is portable to a different
                # measurement run's own instance of the same operation.
                'operation_offsets_s': operation_offsets,
                # The specific operation instance ids (never just the
                # operation's own repeating NAME) this package's own
                # evidence was actually placed against (see
                # attribute_evidence) - coverage.py cross-references
                # this against truth.py's own osops_pairing to tell a
                # package used during an instance a measurement run's
                # own re-comparison actually verified apart from one
                # used only during an instance beyond what that
                # comparison could confirm at all.
                'operation_instances': operation_instances,
                # The same offset as operation_offsets_s, keyed by the
                # specific instance id rather than the operation's own
                # repeating name - see attribute_evidence's own
                # instance_offsets. Lets coverage.py apply an offset
                # only within the exact truth-to-measurement instance
                # correspondence osops_pairing names, never onto any
                # measurement instance that merely shares the same
                # operation name.
                'operation_instance_offsets_s': operation_instance_offsets,
                # This run's own runtime-introspection snapshots that still
                # showed one of this package's own paths loaded at a LATER
                # phase than its first sighting - held-resident evidence,
                # never itself counted as a fresh open near whatever
                # operation happened to be running at that later phase (see
                # read_runtime_modules).
                'held_evidence': held_evidence,
            })

        # U is confirmed use of a package this run's own inventory walk also
        # found; confirmed use of something the walk never found at all is a
        # defect in the ledger, not a fact about the workload, and is kept
        # out of U entirely rather than silently counted as a used bundled
        # package (see ledger_gaps below).
        used = [u for u in all_used if u['in_inventory']]
        ledger_gaps = [u for u in all_used if not u['in_inventory']]
        used_key_set = {(u['ecosystem'], u['name'], u['version']) for u in used}

        version_unknown = (
            [{'side': 'inventory', 'ecosystem': 'java', **e} for e in java_version_unknown]
            + [{'side': 'used', **e} for e in used_version_unknown]
        )

        declared_missing, undeclared_extra = declaration_gaps(case, inventory)

        truth_op_records = read_operation_records(f'{varlog}/operations.jsonl')
        op_consistency = {'checked': False}
        if measurement_run is not None:
            op_consistency = compare_measurement_run(varlog, measurement_run, truth_op_records, image_id)

        # N (confirmed not used) vs X (use/non-use cannot be certified): a
        # candidate is only ever moved into N when this run's own completeness
        # signals allow it. Without a strace log at all, nothing about the
        # rest of the inventory was actually watched, and defaulting every
        # unconfirmed package to "not used" would be reporting an absence of
        # looking as though it were a finding. An inconsistency between this
        # truth run's own firing procedure and the measurement run's is the
        # same kind of gap: the two are not shown to have done the same
        # thing, so nothing this run failed to see can be certified absent
        # from the other's window either.
        strace_available = os.path.isdir(strace_dir)
        # op_consistency_state is a tristate, never collapsed into a plain
        # bool: "unchecked" (no measurement_run was given to compare against
        # at all - true of every standalone truth.py invocation, which is
        # the normal way this tool is run: truth.json is meant to be built
        # once and scored against several later measurement runs, each of
        # which is coverage.py's own job to compare against its own
        # operations.jsonl before trusting this run's own N at all - see
        # coverage.py's own scoring gate), "consistent" (checked, and
        # actually agreed), or "inconsistent" (checked, and did not). Only
        # "consistent" ever allows completeness_ok: an unchecked comparison
        # is not proof of agreement, and reporting N on the strength of one
        # this tool never actually performed would let a *different*
        # measurement run's own mismatched firing procedure go unnoticed.
        if not op_consistency.get('checked'):
            op_consistency_state = 'unchecked'
        elif op_consistency.get('consistent') is True:
            op_consistency_state = 'consistent'
        else:
            op_consistency_state = 'inconsistent'
        strace_completeness = (
            check_strace_completeness(strace_dir) if strace_available
            else {'empty_files': [], 'empty_child_files': [], 'unparseable_lines': 0, 'total_files': 0,
                  'unreconstructed_lines': 0})
        has_unresolved_evidence = bool(strace_unresolved) or bool(runtime_unresolved)
        os_symlink_resolution_failures = context['os_symlink_resolution_failures']
        completeness_ok = (
            strace_available
            and strace_completeness['total_files'] > 0
            and not strace_completeness['empty_files']
            and strace_completeness['unparseable_lines'] == 0
            and strace_completeness['unreconstructed_lines'] == 0
            and not has_unresolved_evidence
            and not missing_trace_pids
            and not os_symlink_resolution_failures
            and op_consistency_state == 'consistent'
        )
        completeness_reasons = []
        if not strace_available:
            completeness_reasons.append('no varlog/strace directory for this truth run')
        else:
            if strace_completeness['total_files'] == 0:
                completeness_reasons.append('varlog/strace carries no trace.<pid> files at all')
            if strace_completeness['empty_files']:
                completeness_reasons.append(
                    f'{len(strace_completeness["empty_files"])} trace file(s) carry no lines at all')
            if strace_completeness['unparseable_lines']:
                completeness_reasons.append(
                    f'{strace_completeness["unparseable_lines"]} trace line(s) look truncated or corrupted')
            if strace_completeness['unreconstructed_lines']:
                completeness_reasons.append(
                    f'{strace_completeness["unreconstructed_lines"]} interrupted syscall(s) never resumed '
                    'in this run\'s own trace')
        if strace_unresolved:
            completeness_reasons.append(f'{len(strace_unresolved)} strace path(s) could not be resolved '
                                         '(relative to a descriptor this tool does not track)')
        if runtime_unresolved:
            completeness_reasons.append(f'{len(runtime_unresolved)} runtime-introspection module(s) '
                                         'could not be resolved to a file at all')
        if missing_trace_pids:
            completeness_reasons.append(f'{len(missing_trace_pids)} cloned pid(s) have no trace file of their own')
        if os_symlink_resolution_failures:
            completeness_reasons.append(f'{len(os_symlink_resolution_failures)} path(s) have a broken symlink chain '
                                         'on this run\'s own exported rootfs and no owner via either spelling')
        if op_consistency_state == 'unchecked':
            completeness_reasons.append('no measurement run was given to compare this truth run\'s own firing '
                                         'procedure against; N cannot be certified until one is (see coverage.py)')
        elif op_consistency_state == 'inconsistent':
            completeness_reasons.append('this truth run\'s own firing procedure does not match the measurement run\'s')

        unused = []
        unknown = []
        for (eco, name, version), _info in sorted(inventory.items()):
            if (eco, name, version) in used_key_set:
                continue
            entry = {'ecosystem': eco, 'name': name, 'version': version}
            if completeness_ok:
                unused.append(entry)
            else:
                entry['reasons'] = list(completeness_reasons)
                unknown.append(entry)

        assert len(used_key_set) + len(unused) + len(unknown) == len(inventory), (
            f'U({len(used_key_set)}) + N({len(unused)}) + X({len(unknown)}) != I({len(inventory)})')

        # Identification mismatches: something confirmed, at a version this
        # run could read, that the inventory walk never found at all - the
        # same set ledger_gaps above already carries, restated with the
        # (ecosystem, name, version) key alone for a quick data-quality count.
        identification_gaps = [
            {'ecosystem': g['ecosystem'], 'name': g['name'], 'version': g['version']}
            for g in ledger_gaps
        ]

        truth = {
            'case_id': case.get('case_id'),
            'image_id': image_id,
            'fired_at': fired_at.isoformat() if fired_at else None,
            'stopped_at': stopped_at.isoformat() if stopped_at else None,
            # This truth run's own directory, as an absolute path regardless
            # of what was typed on this invocation's own command line -
            # coverage.py reads this back to re-open this run's own
            # varlog/operations.jsonl etc. and re-compare against whatever
            # measurement run it is actually scoring, fresh, every time,
            # rather than trusting operation_consistency/completeness.
            # operations below (which only ever reflect whatever measurement
            # run THIS truth.py invocation happened to be pointed at, if any).
            'truth_run_dir': os.path.abspath(run),
            'source': {
                'strace_dir': strace_dir if os.path.isdir(strace_dir) else None,
                'runtime_modules_log': f'{varlog}/runtime-modules.jsonl',
                'strace_failed_calls': strace_failed,
            },
            'used': used,
            'unused': unused,
            'unknown': unknown,
            'ledger_gaps': ledger_gaps,
            'completeness': {
                'strace_available': strace_available,
                'strace_total_files': strace_completeness['total_files'],
                'strace_empty_files': strace_completeness['empty_files'],
                'strace_empty_child_files': strace_completeness['empty_child_files'],
                'strace_unparseable_lines': strace_completeness['unparseable_lines'],
                'strace_unreconstructed_lines': strace_completeness['unreconstructed_lines'],
                'missing_trace_pids': missing_trace_pids,
                'operations': op_consistency_state,
                'ok': completeness_ok,
                'reasons': completeness_reasons,
            },
            'unresolved': {
                'strace_paths': strace_unresolved,
                'runtime_modules': runtime_unresolved,
                'unmapped_paths': unmapped_paths,
                'os_symlink_resolution_failures': os_symlink_resolution_failures,
            },
            'version_unknown': version_unknown,
            'identification_gaps': identification_gaps,
            'declaration_gaps': {
                'declared_missing_from_inventory': declared_missing,
                'inventory_not_in_coverage_plan': undeclared_extra,
            },
            'inventory_size': len(inventory),
            'inventory_scan': inventory_scan,
            'operation_consistency': op_consistency,
        }
        with open(f'{run}/truth.json', 'w') as f:
            json.dump(truth, f, indent=1)
        print(f'{run}: inventory={len(inventory)} used={len(used)} unused={len(unused)} unknown={len(unknown)} '
              f'unmapped_paths={len(unmapped_paths)} version_unknown={len(version_unknown)} '
              f'identification_gaps={len(identification_gaps)}')
        return 0
    finally:
        if not os.environ.get('KL_TRUTH_KEEP_TMP'):
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
