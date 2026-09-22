#!/usr/bin/env bash
# What: attach_running observation of already-running production containers, kept alive across
# a container restart or re-creation, ending with a findings-only match per container generation.
#
# Unlike case-run.sh / check-tracing.sh, this script never creates, starts or stops a container:
# it only watches whatever is already running. It does not fire a workload, does not tear a
# container down, and its cleanup touches only its own processes, its own cgroups, its own
# temporary Docker config directory (never a pre-existing DOCKER_CONFIG the caller set), and its
# own cgroup-map file.
#
# All process supervision (cgroup creation, starting the tracer/collector INSIDE their own
# cgroup from their very first instruction via clone3, verifying the real exe, forwarding a stop
# request through a bounded SIGINT/SIGTERM/SIGKILL sequence, enforcing a hard deadline, reading
# final cpu/mem counters) is delegated to the Go `supervise` subcommand, mirroring
# tools/load-run.sh's own use of it - see experiments/runtime-discovery/supervise.go for what it
# guarantees. Both the tracer and the collector run with -keep-cgroup: their cgroups are not
# supervise's own to remove, because this script itself still needs to read final counters from
# them (at the window's own start and end, via `cgroup-stat`) before they go away, and a
# collector whose own sampling loop finishes before the window's end must not take its cgroup
# away with it. This script removes them itself, via `cgroup-remove`, once every reading it
# needs is in hand.
#
# From the moment the tracer's supervise process is first started, every stop this script makes
# - a setup failure, an operator signal, watch-run.sh's own stop request, or the window's own
# planned end - goes through exactly one path: write (or confirm) the stop-request file every
# supervise process already polls, then wait for each supervise process itself to finish its own
# bounded stop sequence, resuming that wait if a trapped signal interrupts it rather than mistaking
# the interruption for the child having exited. The supervisor PIDs themselves are never sent
# SIGKILL - only a forwardable TERM, which makes a stuck supervisor run its own stop sequence
# instead of abandoning the real tracer or collector process to nothing supervising it.
#
# Monitoring (tools/watch-run.sh, sharing tools/load-lib.sh) starts BEFORE the tracer, not after
# it: the tracer's own start, compile-time attach wait and cgroup registration can themselves
# consume CPU and disk, and a monitor that only starts once all of that is already done cannot
# see any of it. It is fed the tracer/collector pids and cgroup, the run's own planned window
# end (min_until_epoch), a bound on how long it may wait to be told anything at all
# (watch_until_epoch), and a termination-confirmation file it will not consider itself done
# without (see write_targets below). Its own disappearance before the common stop path is ever
# reached is unconditionally a run failure: watch-run.sh's own normal exit requires BOTH the
# planned window end and that confirmation file, and the file is never written before this
# controller loop's own wait is already over - so nothing about the tracer or collector's own
# state at that moment can make the monitor's absence a legitimate, clean exit.
#
# Usage (from the repository root, or from a copy of this tools/ directory that keeps the same
# layout relative to itself - see KL_ROOT below):
#   sudo bash experiments/runtime-discovery/tools/prod-observe.sh <out dir> <window seconds> [container names...]
#   out dir          = a directory this script may create/write into; not required to be (and by
#                       default is not) under experiments/runtime-discovery/out/
#   window seconds   = requested observation window, passed to collect's own -window - clamped to
#                       KL_PROD_MAX_SECONDS (default 1800) as a hard safety ceiling; a request
#                       above it is logged and reduced, never silently honored
#   container names  = specific containers to observe (default: every currently running one,
#                       matching collect's own attach_running default)
#
# This script's own exit status is non-zero whenever a required step failed: the collector
# itself exiting with a real error (not an empty target population, and not its own expected
# sub-window completion), the tracer exiting other than through a requested, confirmed-clean
# stop, the initial cgroup-table registration, converting collected events, matching a
# generation, or scanning a generation's image. Whatever generations DID complete are still
# written and summarized - a later generation's Trivy failure does not erase an earlier one's
# match result - but the script tells its caller something needed attention rather than exiting
# 0 over a run that only partly worked. An empty target population (no containers were running
# to observe) is not a failure and exits 0 with that stated plainly.
#
# Environment variables:
#   KL_ROOT                    repository root, when this tools/ directory was copied elsewhere
#                               (default: three directories above this script)
#   KL_RD_BIN                  path to the prebuilt runtime-discovery binary
#                               (default: experiments/runtime-discovery/out/runtime-discovery)
#   KL_RE_BIN                  path to the prebuilt runtime-events binary
#                               (default: experiments/runtime-discovery/out/runtime-events)
#   KL_PROD_PAGES              64 | 256 | 512 | none (default: 512); none = procfs-only, no
#                               tracer, no events (equivalent to -config-id none)
#   KL_PROD_INTERVAL           seconds between sample starts (default: 30)
#   KL_PROD_MAX_SECONDS        hard ceiling on the observation window (default: 1800)
#   KL_PROD_ALLOW_UNMEASURED_LOAD  1 to run BOTH the tracer and the collector via supervise's own
#                               -no-cgroup (no dedicated cgroup is created for either, and every
#                               cgroup-derived reading, on both the supervise side and the
#                               collector's own load measurement, reads not_measured with a
#                               stated reason instead of silently attributing a shared, inherited
#                               cgroup's load to this run) - the explicit operator override for a
#                               host where no cgroup can be created at all (default: 0)
#   KL_STOP_TIMEOUT_S          supervise's own per-signal-stage grace (SIGINT->SIGTERM->SIGKILL),
#                               shared with tools/load-run.sh's own use of the same env var
#                               (default: 15)
#   KL_SUPERVISE_WAIT_S        how long this script waits for one supervise process to finish its
#                               own stop sequence before sending it (the supervisor, never the
#                               child directly) a TERM and waiting again (default: 90)
#   KL_WINDOW_LEAD_S           seconds between deciding the window's own start and the window
#                               itself actually opening, giving the collector time to start
#                               before the instant its own -phase-base names (default: 5)
#   KL_WINDOW_START_TOLERANCE_S  how many seconds late the window may actually open before this
#                               run's window-start checkpoint is recorded as not established
#                               (default: 2)
#   KL_PREP_BUDGET_S           allowance for tracer start + attach-check + cgroup map, added to
#                               the tracer's own -deadline (its clock starts at its own launch,
#                               before the window's start barrier) (default: 180)
#   KL_WATCH_HARD_DEADLINE_GRACE_S  extra seconds added to the window when computing supervise's
#                               own absolute -deadline, a safety net independent of the
#                               stop-request file (default: 120)
#   KL_CGROUP_REMOVE_WAIT_S    how long `cgroup-remove` waits for a cgroup to report
#                               populated=0 before giving up (default: 30)
#   KL_PROD_CGROUP_REFRESH_SECONDS  periodic cgroup-table refresh interval regardless of restart
#                               activity, so a container that started after the initial refresh
#                               is still resolvable by the tracer (default: 60)
#   KL_PROD_RESTART_POLL_SECONDS    how often restarts.jsonl is checked for new generation-change
#                               events, each of which also triggers an immediate cgroup refresh
#                               (default: 5)
#   KL_PROD_LOG_BYTES          this run's own log is truncated to its tail once it exceeds this
#                               many bytes (default: 52428800, 50 MiB)
#   KL_TRIVY_CMD                the command used to scan an image, split on spaces (default:
#                               "trivy"); set to e.g. "docker exec kestrelynx trivy" to scan
#                               through Trivy installed in an already-running container that has
#                               the Docker socket. This script never passes Trivy's -o flag (an
#                               exec'd Trivy's -o would write inside that other container's own
#                               filesystem); every scan is instead captured from stdout.
#   KL_INTEL_SNAPSHOT           reuse a saved KEV/EPSS snapshot instead of a live lookup
#   KL_WATCH_CPU_CORES, KL_WATCH_RUN_BYTES, KL_WATCH_ROOT_BYTES, KL_WATCH_FREE_BYTES,
#   KL_WATCH_INTERVAL, KL_WATCH_WEB_FAILURES
#                               forwarded to tools/watch-run.sh, exactly as tools/load-run.sh
#                               already uses them (web_timing is not applicable here and is
#                               always "-").
#
# Restart / re-creation: the collector runs with -track-restarts, so a target container that
# restarts (same id, new StartedAt) or is re-created (new id under the same name) is detected at
# the collector's next sample, finalizes that generation's own record with its own narrowed
# validity window closed at the moment of detection (independent of whether a replacement
# generation is ever successfully committed for it, and independent of any FURTHER change
# detected while that replacement is still pending - see collect_restart.go's
# closeGenerationEnd/rolloverGeneration), refreshes the cgroup table (register-cgroups, the same
# mechanism case-run.sh uses) so the tracer's attribution keeps up, and takes a fresh layout
# reading before trusting anything read from the replacement.
#
# The run's own planned observation window (independent of any later generation splitting) is
# decided once, before the collector starts, saved to run_window.json, and given to the collector
# itself via -phase-base so its own internal window matches exactly - this is what convert is
# given, never anything derived from a (possibly narrowed, possibly still-pending) generation
# file.
#
# Prerequisites: run as root (supervise creates cgroup v2 directories); bpftrace installed unless
# KL_PROD_PAGES=none; the native Docker Engine daemon (not Docker Desktop) reachable at
# /var/run/docker.sock; the runtime-discovery/runtime-events binaries built (see
# KL_RD_BIN/KL_RE_BIN); tools/load-lib.sh and tools/watch-run.sh present alongside this script -
# both are hard requirements, not optional extras.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${KL_ROOT:-$here/../../..}"
# shellcheck source=./load-lib.sh
. "$here/load-lib.sh"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock

RD="${KL_RD_BIN:-experiments/runtime-discovery/out/runtime-discovery}"
RE="${KL_RE_BIN:-experiments/runtime-discovery/out/runtime-events}"
RUN=experiments/runtime-discovery/cases/run.sh
T=experiments/runtime-discovery/tools
BT_DIR=experiments/runtime-events/bpftrace

USAGE="Usage: sudo bash experiments/runtime-discovery/tools/prod-observe.sh <out dir> <window seconds> [container names...]"
[ $# -ge 2 ] || { echo "$USAGE" >&2; exit 2; }
R="$1"; REQUESTED_WINDOW="$2"; shift 2
NAMES=("$@")
case "$REQUESTED_WINDOW" in ''|*[!0-9]*) echo "window must be a positive whole number of seconds" >&2; exit 2;; esac
[ "$REQUESTED_WINDOW" -gt 0 ] || { echo "window must be a positive whole number of seconds" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "prod-observe: must run as root (sudo) - supervise creates cgroup v2 directories" >&2; exit 2; }
[ -x "$RD" ] || { echo "prod-observe: $RD not found or not executable (set KL_RD_BIN)" >&2; exit 2; }
[ -f "$T/watch-run.sh" ] || { echo "prod-observe: $T/watch-run.sh not found; safety monitoring is a precondition of observing, not optional" >&2; exit 2; }

MAX_SECONDS="${KL_PROD_MAX_SECONDS:-1800}"
WINDOW="$REQUESTED_WINDOW"; CLAMPED=0
if [ "$WINDOW" -gt "$MAX_SECONDS" ]; then WINDOW="$MAX_SECONDS"; CLAMPED=1; fi

PAGES="${KL_PROD_PAGES:-512}"
case "$PAGES" in 64|256|512|none) ;; *) echo "KL_PROD_PAGES must be 64, 256, 512 or none" >&2; exit 2;; esac
INTERVAL="${KL_PROD_INTERVAL:-30}"
CGROUP_REFRESH_SECONDS="${KL_PROD_CGROUP_REFRESH_SECONDS:-60}"
RESTART_POLL_SECONDS="${KL_PROD_RESTART_POLL_SECONDS:-5}"
LOG_MAX_BYTES="${KL_PROD_LOG_BYTES:-52428800}"
ALLOW_UNMEASURED_COLLECTOR="${KL_PROD_ALLOW_UNMEASURED_LOAD:-0}"
FREE_BYTES_LIMIT="${KL_WATCH_FREE_BYTES:-21474836480}"
SUPERVISE_GRACE="${KL_STOP_TIMEOUT_S:-15}"
SUPERVISE_WAIT_S="${KL_SUPERVISE_WAIT_S:-90}"
LEAD_S="${KL_WINDOW_LEAD_S:-5}"
WINDOW_START_TOLERANCE_S="${KL_WINDOW_START_TOLERANCE_S:-2}"
PREP_BUDGET_S="${KL_PREP_BUDGET_S:-180}"
HARD_DEADLINE_GRACE="${KL_WATCH_HARD_DEADLINE_GRACE_S:-120}"
CGROUP_REMOVE_WAIT_S="${KL_CGROUP_REMOVE_WAIT_S:-30}"
TRACER_DEADLINE_S=$((PREP_BUDGET_S + LEAD_S + WINDOW + HARD_DEADLINE_GRACE))
COLLECTOR_DEADLINE_S=$((LEAD_S + WINDOW + HARD_DEADLINE_GRACE))

case "$PAGES" in
  64)   BTSCRIPT="$BT_DIR/runtime-events-nofilter.bt"; VARIANT=nofilter; CFG=bpftrace-v2-nofilter-64p;;
  256)  BTSCRIPT="$BT_DIR/runtime-events-nofilter-256p.bt"; VARIANT=nofilter-256p; CFG=bpftrace-v2-nofilter-256p;;
  512)  BTSCRIPT="$BT_DIR/runtime-events-nofilter-512p.bt"; VARIANT=nofilter-512p; CFG=bpftrace-v2-nofilter-512p;;
  none) BTSCRIPT=""; VARIANT=""; CFG=none;;
esac
RUN_TRACER=0; [ -n "$BTSCRIPT" ] && RUN_TRACER=1
# bpftrace reads these from the environment; supervise removes them from the CHILD's own
# environment directly (-unset-env), rather than this script wrapping the command in `env
# -u ...`, so the process supervise starts, verifies (-expect-exe) and supervises is bpftrace
# itself, never a short-lived `env` that then execs into it.
BPF_UNSET_ENV=BPFTRACE_MAX_STRLEN,BPFTRACE_PERF_RB_PAGES,BPFTRACE_ON_STACK_LIMIT

mkdir -p "$R/collect" "$R/case" "$R/scans" "$R/match" || { echo "prod-observe: cannot create $R" >&2; exit 2; }
LOG="$R/run.log"
log(){
  printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$*" >> "$LOG"
  local sz; sz=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
  if [ "$sz" -gt "$LOG_MAX_BYTES" ]; then
    tail -c "$LOG_MAX_BYTES" "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
  fi
}
# tl appends one timeline event as a proper line of JSON (the timestamp is
# a real JSON field, never a bare prefix outside the object). Every extra
# argument is a "key=value" pair; a value containing a double quote or
# backslash is escaped rather than breaking the line.
tl(){
  local event="$1"; shift
  local line; line="{\"ts\":\"$(date -u +%FT%T.%NZ)\",\"event\":\"$event\""
  local kv k v
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    line="$line,\"$k\":\"$v\""
  done
  line="$line}"
  echo "$line" >> "$R/timeline.jsonl"
}
FAILED_STEPS=(); WARNINGS=()
fail_step(){ FAILED_STEPS+=("$1"); log "STEP FAILED: $1"; }
warn(){ WARNINGS+=("$1"); log "WARNING: $1"; }

# record_field polls a JSON file (a supervise record, still being written
# the first time this is called right after launch) for up to $2 seconds
# and prints field $3, or nothing if it never appears with a non-empty
# value for that field.
record_field(){
  local path="$1" timeout="$2" field="$3" waited=0 v=""
  while [ "$waited" -le "$timeout" ]; do
    if [ -s "$path" ]; then
      v=$(python3 -c "import json,sys
try:
  print(json.load(open(sys.argv[1])).get(sys.argv[2]) or '')
except Exception:
  print('')" "$path" "$field" 2>/dev/null)
      [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    fi
    sleep 1; waited=$((waited + 1))
  done
  printf '%s' "$v"
}

# physical_termination_confirmed reads one supervise record and answers ONLY the physical
# question (as two lines: a failure reason, then a note) - has this run's own tooling
# actually confirmed the child, and where a dedicated cgroup exists to check, every
# descendant it may have left behind, is gone. It never treats supervise's own process exit
# as the answer: supervise writes a final record and exits normally even when the CHILD it
# supervised could not itself be confirmed stopped (status=stop_unconfirmed) - a supervisor
# that is merely reaped says nothing about whether its child physically terminated. It also
# never asks whether the exit was the one this script wanted (clean, requested, zero exit
# code) - that is check_supervise_stop's own, separate, business-level judgement below, made
# only once this function has already said termination is physically confirmed, and reported
# through fail_step without blocking anything physical: a tracer that exited on its own, or
# with a non-zero code, is still just as gone as one that stopped cleanly, and it is just as
# safe to remove its cgroup and tell the monitor termination is confirmed. Mode "dedicated"
# requires termination_confirmed to be both measured and true; mode "no_cgroup" only requires
# a confirmed exit (no residual check is possible there at all) and reports the weaker
# guarantee as a note, never a failure.
physical_termination_confirmed(){
  python3 - "$1" "$2" <<'PY'
import json, sys
path, mode = sys.argv[1], sys.argv[2]
def done(failure="", note=""):
    # Prefixed so an empty failure/note (the ordinary success case) still prints a
    # non-empty, unambiguous line - read_confirmation_result on the bash side tells that
    # apart from a crashed or killed helper's own empty output by this shape alone, never
    # by line count (an empty "" and an absent line otherwise look identical).
    print("FAILURE:" + failure)
    print("NOTE:" + note)
    sys.exit(0)
try:
    d = json.load(open(path))
except Exception as e:
    done(f"could not read its own supervise record: {e}")
status = d.get("status")
if status == "exited_residual_tasks":
    done("exited but a residual descendant task was found in its own cgroup afterward")
if status != "exited":
    done(f"never reached a confirmed exit (status={status})")
if mode == "dedicated":
    tc = d.get("termination_confirmed") or {}
    if not tc.get("measured"):
        done(f"termination could not be confirmed in its own dedicated cgroup: {tc.get('reason', '')}")
    if not tc.get("value"):
        done(f"termination_confirmed reports false: {tc.get('reason', '')}")
    done()
else:
    done(note="termination_confirmed could not check for a residual descendant task: this run had no dedicated cgroup of its own (supervise -no-cgroup); only the child's own reap is confirmed here")
PY
}

# read_confirmation_result validates and unpacks the FAILURE:/NOTE: contract both
# physical_termination_confirmed and check_supervise_stop use, given the command's own exit
# code ($1) and its captured raw stdout ($2). It sets RESULT_FAILURE/RESULT_NOTE and returns
# 0 only when the check actually ran to completion and said there was no failure. An
# abnormal exit (the helper crashed, or was killed - status 137 for a SIGKILL, among others)
# or output that does not match the expected two-line shape is ITSELF a failure, with its
# own stated reason, rather than being read as "the check said nothing was wrong" - an empty
# RESULT_FAILURE must only ever mean the check actually ran and found no problem, never that
# there was no output to look at in the first place.
read_confirmation_result(){
  local rc="$1" out="$2"
  RESULT_FAILURE=""; RESULT_NOTE=""
  if [ "$rc" -ne 0 ]; then
    RESULT_FAILURE="the confirmation check itself exited abnormally (status $rc)"
    return 1
  fi
  local lines=()
  mapfile -t lines <<< "$out"
  case "${lines[0]:-}" in
    FAILURE:*) ;;
    *) RESULT_FAILURE="the confirmation check produced malformed output (missing or unrecognized result line)"; return 1 ;;
  esac
  case "${lines[1]:-}" in
    NOTE:*) ;;
    *) RESULT_FAILURE="the confirmation check produced malformed output (missing or unrecognized note line)"; return 1 ;;
  esac
  RESULT_FAILURE="${lines[0]#FAILURE:}"
  RESULT_NOTE="${lines[1]#NOTE:}"
  [ -z "$RESULT_FAILURE" ]
}

# write_termination_confirmed_file is called only once physical_termination_confirmed has
# already said yes for every target this run actually started: it is the one thing that
# tells watch-run.sh termination is no longer undetermined. Its own write is verified (a
# short, non-empty file, read back rather than assumed) before anything downstream treats
# the confirmation as real - a write that silently failed must not be reported as done.
write_termination_confirmed_file(){
  printf 'confirmed at %s\n' "$(date -u +%FT%T.%NZ)" > "$TERMINATION_CONFIRMED_FILE" 2>/dev/null
  [ -s "$TERMINATION_CONFIRMED_FILE" ]
}

# check_supervise_stop reads one supervise record and reports (as two lines: a failure reason,
# then a note) whether that process's own stop meets this script's OWN business expectation
# for it (a clean, requested, zero-exit-code stop) - called only once
# physical_termination_confirmed has already passed for the same record, so every check here
# is about how the exit is judged, never about whether it physically happened.
check_supervise_stop(){
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, role, mode = sys.argv[1], sys.argv[2], sys.argv[3]
def done(failure="", note=""):
    # Same FAILURE:/NOTE: contract as physical_termination_confirmed, and for the same
    # reason: an empty failure/note (the ordinary success case) must still be
    # distinguishable, by shape alone, from a crashed or killed helper's own empty output.
    print("FAILURE:" + failure)
    print("NOTE:" + note)
    sys.exit(0)
try:
    d = json.load(open(path))
except Exception as e:
    done(f"could not read its own supervise record: {e}")
status = d.get("status")
if status not in ("exited", "exited_residual_tasks"):
    done(f"never reached a confirmed exit (status={status})")
if status == "exited_residual_tasks":
    done("exited but a residual descendant task was found in its own cgroup afterward")
if role == "tracer" and not d.get("stop_requested"):
    done("exited on its own, without ever being asked to stop")
if d.get("exit_signal"):
    done(f"had to be force-stopped (exit_signal={d.get('exit_signal')})")
if d.get("exit_code"):
    done(f"exited with status {d.get('exit_code')}")
tc = d.get("termination_confirmed") or {}
measured, value, reason = tc.get("measured"), tc.get("value"), tc.get("reason", "")
if mode == "dedicated":
    if not measured:
        done(f"termination could not be confirmed in its own dedicated cgroup: {reason}")
    if not value:
        done(f"termination_confirmed reports false: {reason}")
    done()
else:
    done(note="termination_confirmed could not check for a residual descendant task: this run had no dedicated cgroup of its own (supervise -no-cgroup); only the child's own reap is confirmed here")
PY
}

log "## prod-observe start: out=$R window=${WINDOW}s (requested ${REQUESTED_WINDOW}s) pages=$PAGES interval=${INTERVAL}s containers=${NAMES[*]:-<all running>}"
tl run_start window="$WINDOW" requested_window="$REQUESTED_WINDOW" pages="$PAGES" interval="$INTERVAL"
if [ "$CLAMPED" = 1 ]; then
  warn "requested window ${REQUESTED_WINDOW}s exceeds the ${MAX_SECONDS}s safety ceiling (KL_PROD_MAX_SECONDS); clamped to ${WINDOW}s"
  tl window_clamped requested="$REQUESTED_WINDOW" effective="$WINDOW" ceiling="$MAX_SECONDS"
fi

# --- OBSERVING gates only how the INT/TERM trap below reacts: before the window opens, the
# handler runs the common stop-and-save path itself (cleanup_all) and exits; once observing, it
# only writes the stop request and lets the main flow's own later call to the same common path
# (stop_supervised, from the controller loop below) do the waiting. Either way, and regardless of
# OBSERVING, every stop - including one reached through fail() below - goes through the SAME
# cleanup_all/stop_supervised path; nothing here ever sends a supervisor SIGKILL. The
# stop-request file itself is created (empty) once, before the monitor or either supervise
# process starts, and is never deleted or re-initialized again after that.
OBSERVING=0
TP=""; CP=""; WATCHP=""
# TRACER_STARTED/COLLECTOR_STARTED record whether this run's own supervise process for that
# role was actually launched, independent of TP/CP themselves (which are cleared back to ""
# once wait_for_supervisor confirms the supervisor is gone) and independent of RUN_TRACER
# (which only says this run's own CONFIG wants a tracer, not that it ever got as far as
# starting one - a fail() reached before that point must not go on to expect a tracer record
# that was never going to exist). This is what cleanup_all's own physical-confirmation check
# below uses to decide which records it must actually read.
TRACER_STARTED=0; COLLECTOR_STARTED=0
CGROOT=""; CGROOT_MADE=0
OWN_DOCKER_CONFIG=""
CLEANED=0
CLEANING=0
STOPFILE="$R/stop_request.txt"
rm -f "$STOPFILE"
TARGETS="$R/watch_targets.txt"
TRACER_CGROUP="-"; COLLECTOR_CGROUP="-"
REFRESH_PID=""
CGROUP_REFRESH_FAILED_FLAG="$R/.cgroup_refresh_failed"
# TERMINATION_CONFIRMED_FILE's own PATH is known from the start and published to
# watch-run.sh in every write_targets call below; its CONTENT only appears once
# cleanup_all's own physical-confirmation check actually passes (see
# write_termination_confirmed_file) - watch-run.sh itself treats the file's mere
# non-existence/emptiness as "termination still undetermined", exactly the state this run is
# actually in before that point.
TERMINATION_CONFIRMED_FILE="$R/termination_confirmed.txt"
rm -f "$TERMINATION_CONFIRMED_FILE"

# write_targets (re)publishes what watch-run.sh should be watching. It is written before the
# watcher starts (naming which processes this run WILL have, but with no pids yet) and
# rewritten as each one comes up, so the watcher is already running - and already enforcing the
# disk/space limits - during the tracer's own startup and attach, not only afterwards.
# expect_tracer/expect_collector are what stop the watcher from reading a preparation phase in
# which no pid exists yet as "everything has already finished".
# watch_deadline_epoch computes watch-run.sh's own single absolute bound (watch_until_epoch):
# the one way it stops without ever having been told termination is confirmed. Before the
# start barrier decides WINDOW_END_PLANNED_EPOCH, it is estimated generously from now (prep +
# lead + the full window); once the real planned end is known, it is computed from THAT
# instead - always with the same generous teardown budget added (both supervise waits, in
# their own worst case, for both roles; all three cgroup removals; a fixed buffer). Because
# write_targets recomputes this fresh on every call and watch-run.sh re-reads the targets
# file every sample, a later call with a now-known, more accurate WINDOW_END_PLANNED_EPOCH
# naturally EXTENDS (or corrects) whatever bound an earlier, prep-phase estimate published -
# the watcher is never left running past an early guess with no way to give it a better one,
# and never left with no bound at all in the meantime either.
watch_deadline_epoch(){
  local base
  if [ -n "${WINDOW_END_PLANNED_EPOCH:-}" ]; then
    base="$WINDOW_END_PLANNED_EPOCH"
  else
    base=$(( $(date -u +%s) + PREP_BUDGET_S + LEAD_S + WINDOW ))
  fi
  echo $(( base + HARD_DEADLINE_GRACE + 4 * SUPERVISE_WAIT_S + 3 * CGROUP_REMOVE_WAIT_S + 60 ))
}

write_targets(){
  local tracer_cg="-" trace_err="-"
  if [ "$RUN_TRACER" = 1 ]; then tracer_cg="$TRACER_CGROUP"; trace_err="$R/trace.err"; fi
  {
    printf 'expect_tracer=%q\n' "$RUN_TRACER"
    printf 'expect_collector=%q\n' 1
    printf 'tracer_pid=%q\n' "${TP:--}"
    printf 'collector_pid=%q\n' "${CP:--}"
    printf 'tracer_cgroup=%q\n' "$tracer_cg"
    printf 'trace_err=%q\n' "$trace_err"
    printf 'web_timing=%q\n' "-"
    printf 'termination_confirmed_file=%q\n' "$TERMINATION_CONFIRMED_FILE"
    printf 'min_until_epoch=%q\n' "${WINDOW_END_PLANNED_EPOCH:-}"
    printf 'watch_until_epoch=%q\n' "$(watch_deadline_epoch)"
  } > "$TARGETS.tmp"
  mv "$TARGETS.tmp" "$TARGETS"
}

# wait_for_supervisor waits for one supervise process to finish the bounded stop sequence it
# performs on its own child, escalating only as far as a SIGTERM of the SUPERVISOR (which makes
# it run that same sequence) - never a SIGKILL of it, which would abandon the real tracer or
# collector. A supervisor that still has not finished is recorded as a stop failure rather than
# papered over. The kill -0 poll loop (rather than a bare `wait`) is what lets this resume
# correctly if a trapped signal interrupts an in-progress wait: only once kill -0 itself reports
# the process gone is `wait` finally called, at which point it just reaps rather than blocks.
wait_for_supervisor(){
  local label="$1" pid="$2" waited=0
  [ -n "$pid" ] && [ "$pid" != "-" ] || return 0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$SUPERVISE_WAIT_S" ]; do sleep 1; waited=$((waited + 1)); done
  if kill -0 "$pid" 2>/dev/null; then
    log "$label supervise (pid $pid) has not finished its own stop sequence after ${SUPERVISE_WAIT_S}s; sending TERM so it runs that sequence now"
    kill -TERM "$pid" 2>/dev/null
    waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$SUPERVISE_WAIT_S" ]; do sleep 1; waited=$((waited + 1)); done
  fi
  if kill -0 "$pid" 2>/dev/null; then
    log "$label supervise (pid $pid) is STILL running; not sending SIGKILL, which would leave the real $label process with nothing supervising it"
    warn "$label supervise did not finish its stop sequence within $((SUPERVISE_WAIT_S * 2))s"
    return 1
  fi
  wait "$pid" 2>/dev/null
  log "$label supervise exit $?"
  return 0
}

# stop_supervised is the one stop path: request the stop in the file every supervise process
# already polls (unless already requested), then confirm each supervisor - and with it its
# child - has actually finished. Its own return code is the caller's only license to treat
# the tracer/collector as actually stopped: non-zero means at least one of them did NOT
# confirm within the wait budget, and that one's PID is deliberately left non-empty (never
# cleared) rather than assumed gone - a caller that pressed on to cgroup removal or convert
# regardless would be reading a process that might still be running as though it were done.
stop_supervised(){
  local reason="$1" rc=0
  [ -n "$TP$CP" ] || return 0
  [ -s "$STOPFILE" ] || echo "$reason" > "$STOPFILE"
  if [ -n "$TP" ]; then
    if wait_for_supervisor tracer "$TP"; then TP=""; else rc=1; fi
  fi
  if [ -n "$CP" ]; then
    if wait_for_supervisor collector "$CP"; then CP=""; else rc=1; fi
  fi
  return "$rc"
}

# remove_cgroups removes what supervise deliberately left behind (-keep-cgroup): each child
# cgroup first, then their common parent, each attempt recorded as its own JSON file so a
# removal that could not happen is a stated fact with a reason, not a silent leftover. A
# failed removal is recorded as a failed step (with the residual path named) and CGROOT_MADE
# is deliberately left at 1 rather than reset - the one signal a later call (the EXIT trap's
# own final cleanup_all, in particular) has that there is still something here to retry
# rather than nothing left to check.
remove_cgroups(){
  [ "$CGROOT_MADE" = 1 ] || return 0
  local path label residual=0
  for label in tracer collector; do
    case "$label" in tracer) path="$TRACER_CGROUP";; collector) path="$COLLECTOR_CGROUP";; esac
    [ -d "$path" ] || continue
    if ! "$RD" cgroup-remove -wait "$CGROUP_REMOVE_WAIT_S" "$path" > "$R/cgroup-remove-$label.json" 2>>"$LOG"; then
      log "cgroup-remove $label FAILED: $(cat "$R/cgroup-remove-$label.json" 2>/dev/null)"
      fail_step "cgroup-remove $label failed; residual cgroup left at $path"
      residual=1
    fi
  done
  if [ -d "$CGROOT" ]; then
    if ! "$RD" cgroup-remove -wait "$CGROUP_REMOVE_WAIT_S" "$CGROOT" > "$R/cgroup-remove-parent.json" 2>>"$LOG"; then
      log "cgroup-remove parent FAILED: $(cat "$R/cgroup-remove-parent.json" 2>/dev/null)"
      fail_step "cgroup-remove parent failed; residual cgroup left at $CGROOT"
      residual=1
    fi
  fi
  [ "$residual" = 0 ] && CGROOT_MADE=0
  return "$residual"
}

# cleanup_all is the one place that decides the run is actually stopped and torn down. It is
# reentrancy-guarded by TWO separate flags, deliberately kept apart (CLEANING: a cleanup is
# running right now; CLEANED: one has already finished successfully) rather than folded into
# one: a signal arriving while CLEANING=1 must not start a second, overlapping cleanup or cut
# the one already running short (see handle_signal below) - it only gets to happen once
# CLEANED itself is set, and CLEANED is set ONLY when every target this run actually started
# was independently confirmed PHYSICALLY terminated from its own supervise record (never from
# the supervisor process merely having been reaped - see physical_termination_confirmed's own
# doc comment for why those are not the same thing) AND every cgroup was actually removed. A
# cleanup that fails any of that leaves CLEANED at 0 on purpose, so the EXIT trap's own final
# call to this same function re-checks and retries rather than silently treating an
# unconfirmed stop or a residual cgroup as done.
STOP_CONFIRMED=0
cleanup_all(){
  [ "$CLEANED" = 1 ] && return 0
  CLEANING=1
  [ -n "$REFRESH_PID" ] && { kill "$REFRESH_PID" 2>/dev/null; wait "$REFRESH_PID" 2>/dev/null; REFRESH_PID=""; }

  local reaped=1
  if stop_supervised "runner_cleanup"; then
    reaped=1
  else
    reaped=0
    fail_step "supervise did not confirm its own process exit for the tracer and/or collector within the wait budget; the unconfirmed pid is left running rather than assumed stopped"
  fi

  # reaped=1 only means each SUPERVISOR process itself is gone and its record is now final -
  # supervise writes that record and exits normally even when the CHILD it supervised could
  # never itself be confirmed stopped (status=stop_unconfirmed). Physical termination is
  # judged from each record independently, here, before anything below touches the monitor,
  # a cgroup, or CLEANED itself.
  STOP_CONFIRMED=0
  if [ "$reaped" = 1 ]; then
    local ok=1
    if [ "$TRACER_STARTED" = 1 ]; then
      if [ -s "$TRACER_RECORD" ]; then
        local pc_out pc_rc
        pc_out="$(physical_termination_confirmed "$TRACER_RECORD" "$STOP_MODE")"; pc_rc=$?
        if ! read_confirmation_result "$pc_rc" "$pc_out"; then
          fail_step "tracer: not physically confirmed stopped: $RESULT_FAILURE"
          ok=0
        fi
        [ -n "$RESULT_NOTE" ] && warn "tracer: $RESULT_NOTE"
      else
        fail_step "tracer: its supervise record was never written at all"
        ok=0
      fi
    fi
    if [ "$COLLECTOR_STARTED" = 1 ]; then
      if [ -s "$COLLECTOR_RECORD" ]; then
        local pc_out pc_rc
        pc_out="$(physical_termination_confirmed "$COLLECTOR_RECORD" "$STOP_MODE")"; pc_rc=$?
        if ! read_confirmation_result "$pc_rc" "$pc_out"; then
          fail_step "collector: not physically confirmed stopped: $RESULT_FAILURE"
          ok=0
        fi
        [ -n "$RESULT_NOTE" ] && warn "collector: $RESULT_NOTE"
      else
        fail_step "collector: its supervise record was never written at all"
        ok=0
      fi
    fi
    [ "$ok" = 1 ] && STOP_CONFIRMED=1
  fi

  local cgroups_ok=1
  if [ "$STOP_CONFIRMED" = 1 ]; then
    # Only now, with every started target's own physical termination independently
    # confirmed, is watch-run.sh actually told so (and that write verified), and only now
    # are the monitor and the cgroups themselves touched.
    if write_termination_confirmed_file; then
      [ -n "$WATCHP" ] && { stop_process "$WATCHP" TERM 5 "safety monitor" 2>&1 | tee -a "$LOG" >/dev/null; WATCHP=""; }
      remove_cgroups || cgroups_ok=0
    else
      fail_step "the termination-confirmation file could not be written; leaving the safety monitor running rather than reporting a confirmation that was never actually saved"
      STOP_CONFIRMED=0
      cgroups_ok=0
    fi
  else
    log "termination not physically confirmed; leaving the safety monitor running and any cgroups in place rather than tearing down around a possibly-still-running supervised process"
    cgroups_ok=0
  fi
  [ -n "$OWN_DOCKER_CONFIG" ] && { rm -rf "$OWN_DOCKER_CONFIG" 2>/dev/null; OWN_DOCKER_CONFIG=""; }
  CLEANING=0
  if [ "$STOP_CONFIRMED" = 1 ] && [ "$cgroups_ok" = 1 ]; then
    CLEANED=1
  fi
}
fail(){ log "FAILED (setup): $*"; tl setup_failed reason="$*"; cleanup_all; exit 1; }
handle_signal(){
  local sig="$1"
  if [ "$CLEANING" = 1 ]; then
    # A cleanup is already running (started by an earlier signal, by fail(), or by the main
    # flow's own step 10). Starting a second, overlapping one here - or exiting mid-way
    # through the one already in progress, as a bare `exit 130` would - is exactly what
    # would abandon a wait_for_supervisor loop the running cleanup is still inside of.
    # Recording another stop request is enough: it is already what every supervise process
    # and the loop waiting on them are polling for.
    log "received $sig while cleanup is already in progress; recording another stop request and letting it finish"
    [ -s "$STOPFILE" ] || echo "operator_stop_$sig" > "$STOPFILE"
    return
  fi
  if [ "$OBSERVING" = 1 ]; then
    log "operator stop: received $sig during observation"
    [ -s "$STOPFILE" ] || echo "operator_stop_$sig" > "$STOPFILE"
  else
    log "received $sig during setup; stopping everything already started through the common stop path"
    [ -s "$STOPFILE" ] || echo "operator_stop_${sig}_during_setup" > "$STOPFILE"
    cleanup_all
    exit 130
  fi
}
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'cleanup_all' EXIT

DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)
case "$DAEMON" in
  "") fail "docker daemon unreachable";;
  *Desktop*) fail "docker socket belongs to Docker Desktop ($DAEMON); production observation needs the native daemon";;
esac
[ "$RUN_TRACER" = 0 ] || command -v bpftrace >/dev/null || fail "bpftrace not installed"
tl daemon_ok os="$DAEMON"

FREE_NOW=$(df --output=avail -B1 "$R" 2>/dev/null | tail -n1 | tr -d ' ')
if [ -n "$FREE_NOW" ] && [ "$FREE_NOW" -lt "$FREE_BYTES_LIMIT" ]; then
  fail "free space on the output filesystem ($FREE_NOW bytes) is already below the ${FREE_BYTES_LIMIT}-byte minimum; refusing to start"
fi

# Monitoring precondition: the helper functions load-lib.sh defines (sourced above) must
# actually work on this host before anything is observed, not merely be defined - a real,
# smoke-tested read against this run's own directory, not just a successful `source`.
SMOKE_ERR=""
dir_size_bytes "$R" >/dev/null 2>&1 || SMOKE_ERR="dir_size_bytes could not read $R"
[ -z "$SMOKE_ERR" ] && { fs_free_bytes "$R" >/dev/null 2>&1 || SMOKE_ERR="fs_free_bytes could not read $R's filesystem"; }
[ -z "$SMOKE_ERR" ] && { : > "$R/.smoke_test_empty"; count_lost_notifications "$R/.smoke_test_empty" >/dev/null 2>&1 || SMOKE_ERR="count_lost_notifications could not read a file it was just given"; rm -f "$R/.smoke_test_empty"; }
[ -z "$SMOKE_ERR" ] || fail "monitoring precondition failed: $SMOKE_ERR (load-lib.sh's own helpers do not work on this host)"
tl monitoring_smoke_test result=ok

# One dedicated parent cgroup for this run's tracer/collector; supervise creates and manages
# each CHILD directory itself (but, given -keep-cgroup below, does not remove it - see
# remove_cgroups). $$ makes the name unique to this specific invocation, matching
# tools/load-run.sh's own reasoning: a leftover of the same name from an earlier, incompletely
# torn down run must fail loudly rather than silently reuse its stale counters.
#
# KL_PROD_ALLOW_UNMEASURED_LOAD=1 skips creating one at all and passes supervise's own
# -no-cgroup to both the tracer and the collector instead (every supervise-side cgroup reading
# then reads not_measured), and also tells the collector itself (-load-unmeasured) to record its
# own steady-state/Docker-daemon load tiers as not_measured rather than reading whatever cgroup
# it happens to have inherited (a shared cgroup whose load includes other processes) - the
# explicit operator override for a host where no cgroup can be created at all, rather than this
# script silently degrading, or silently attributing someone else's load to this run, on its own.
TRACER_CGROUP_ARGS=(); COLLECTOR_CGROUP_ARGS=(); LOAD_UNMEASURED_ARGS=(); STOP_MODE="dedicated"
if [ "$ALLOW_UNMEASURED_COLLECTOR" = 1 ]; then
  warn "KL_PROD_ALLOW_UNMEASURED_LOAD=1: tracer and collector both run via supervise -no-cgroup; load will read not_measured"
  STOP_MODE="no_cgroup"
  TRACER_CGROUP_ARGS=(-no-cgroup)
  COLLECTOR_CGROUP_ARGS=(-no-cgroup)
  LOAD_UNMEASURED_ARGS=(-load-unmeasured "supervise -no-cgroup: this run was not placed in a cgroup of its own")
else
  CGROOT="/sys/fs/cgroup/kestrelynx-prodobs-$$"
  mkdir "$CGROOT" || fail "cgroup: cannot create $CGROOT (a leftover of the same name from an earlier, incompletely torn down run? set KL_PROD_ALLOW_UNMEASURED_LOAD=1 to proceed without dedicated load accounting instead)"
  CGROOT_MADE=1
  TRACER_CGROUP="$CGROOT/tracer"; COLLECTOR_CGROUP="$CGROOT/collector"
  TRACER_CGROUP_ARGS=(-cgroup "$TRACER_CGROUP" -allow-unmeasured -keep-cgroup)
  COLLECTOR_CGROUP_ARGS=(-cgroup "$COLLECTOR_CGROUP" -keep-cgroup)
fi

log "## 1 clock and cgroup table"
"$RE" clock -out "$R/clock.json" || fail clock
"$RE" cgroup-map -root /sys/fs/cgroup -out "$R/cgroup-map.json" || fail cgroup-map
BOOT=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['boot_epoch'])" "$R/clock.json")
CERR=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['error_ns'])" "$R/clock.json")
log "boot_epoch $BOOT error_ns $CERR"

log "## 2 target snapshot (read-only: docker ps/inspect, nothing started, stopped or created)"
if [ ${#NAMES[@]} -eq 0 ]; then
  mapfile -t NAMES < <(docker ps --format '{{.Names}}')
fi
INITIAL_TARGET_COUNT=${#NAMES[@]}
if [ "$INITIAL_TARGET_COUNT" -eq 0 ]; then
  log "no running containers found; this run will observe an empty population"
fi
{
  echo "["
  first=1
  for n in "${NAMES[@]:-}"; do
    [ -n "$n" ] || continue
    insp=$(docker inspect "$n" 2>/dev/null) || { log "target $n: docker inspect failed, skipping"; continue; }
    cid=$(echo "$insp" | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['Id'])")
    iid=$(echo "$insp" | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['Image'])")
    iref=$(echo "$insp" | python3 -c "import json,sys;d=json.load(sys.stdin)[0];print(d.get('Config',{}).get('Image') or d['Image'])")
    started=$(echo "$insp" | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['State']['StartedAt'])")
    [ "$first" = 1 ] || echo ","
    first=0
    printf '{"name":"%s","container_id":"%s","image_id":"%s","image_ref":"%s","started_at":"%s"}' "$n" "$cid" "$iid" "$iref" "$started"
    # A snapshot of what docker inspect reported before the collector ever
    # ran - not the collector's own registration result, see
    # target_registration_result below for that.
    tl target_snapshot container="$n" container_id="$cid" image_id="$iid" started_at="$started"
    log "target $n: id=$(echo "$cid" | cut -c1-12) image=$iid started_at=$started"
  done
  echo "]"
} > "$R/targets_initial.json"

CONTAINERS_ARG=()
if [ "$INITIAL_TARGET_COUNT" -gt 0 ]; then
  IFS=,; CONTAINERS_ARG=(-containers "${NAMES[*]}"); IFS=$' \t\n'
fi

# --- the safety watcher starts here, before the tracer exists: the compile and attach that
# follow are themselves capable of consuming CPU and filling the output filesystem, and a stop
# monitor that only starts afterwards cannot see any of it. It re-reads its targets file every
# sample, so the pids and cgroup below reach it as soon as they exist. ---
log "## 3 safety watcher (starts before anything it watches exists)"
write_targets
bash "$here/watch-run.sh" "$R" "$(dirname "$R")" "$TARGETS" "$STOPFILE" > "$R/watch.log" 2>&1 &
WATCHP=$!
sleep 0.3
if ! kill -0 "$WATCHP" 2>/dev/null; then
  fail "the safety monitor (watch-run.sh) failed to start; refusing to observe without it - see $R/watch.log"
fi
log "safety monitor started (pid $WATCHP)"
tl monitor_started pid="$WATCHP"

ATTACHED=""; ATTACH_COMPLETE_AT=""
TRACER_RECORD="$R/tracer_supervise.json"
if [ "$RUN_TRACER" = 1 ]; then
  log "## 4 tracer start via supervise ($BTSCRIPT), then attach confirmation and cgroup map - all before the window's own start is decided"
  BPF_EXE="$(command -v bpftrace)"
  "$RD" supervise "${TRACER_CGROUP_ARGS[@]}" -expect-exe "$BPF_EXE" -record "$TRACER_RECORD" -stop-request "$STOPFILE" \
    -grace "$SUPERVISE_GRACE" -deadline "$TRACER_DEADLINE_S" -unset-env "$BPF_UNSET_ENV" \
    -- "$BPF_EXE" "$BTSCRIPT" \
    > "$R/trace.txt" 2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$l"; done > "$R/trace.err") &
  TP=$!
  TRACER_STARTED=1
  write_targets
  sleep 2
  if bash "$RUN" attach-check "$R/trace.txt" 30 2>&1 | tee -a "$LOG" >/dev/null; then
    ATTACHED="-attached"; ATTACH_COMPLETE_AT=$(date -u +%FT%T.%NZ)
    log "attach check OK at $ATTACH_COMPLETE_AT"
  else
    log "attach check failed (run continues, recorded as not attached)"
  fi
  tl attach_check attached="${ATTACHED:+yes}" at="$ATTACH_COMPLETE_AT"
  log "## 4b initial cgroup table refresh (targets already running)"
  if bash "$RUN" register-cgroups "$R/cgroup-map.json" "$RE" 2>&1 | tee -a "$LOG" >/dev/null; then
    tl cgroup_refresh reason=initial result=success
  else
    tl cgroup_refresh reason=initial result=failure
    fail "initial cgroup-table registration failed; the tracer cannot attribute anything to a container without it"
  fi
fi

# --- start barrier: preparation is done, so the common window's own start is decided NOW (not
# before the attach-check that might have overrun it) and the collector is given it as its own
# -phase-base. LEAD_S is only what the collector's own startup needs; the run's own planned
# window (independent of any later generation splitting) is saved to run_window.json here. ---
WINDOW_START_EPOCH=$(( $(date -u +%s) + LEAD_S ))
WINDOW_START=$(date -u -d "@$WINDOW_START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
WINDOW_END_PLANNED_EPOCH=$((WINDOW_START_EPOCH + WINDOW))
WINDOW_END_PLANNED=$(date -u -d "@$WINDOW_END_PLANNED_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
printf '{"scheduled_start":"%s","scheduled_end":"%s"}\n' "$WINDOW_START" "$WINDOW_END_PLANNED" > "$R/run_window.json"
log "## 5 start barrier: preparation complete, window start $WINDOW_START (+${LEAD_S}s lead), planned end $WINDOW_END_PLANNED"
tl run_window_decided start="$WINDOW_START" end="$WINDOW_END_PLANNED"

COLLECTOR_RECORD="$R/collector_supervise.json"
log "## 6 collector via supervise (attach_running, restart tracking on), phase-base = $WINDOW_START"
"$RD" supervise "${COLLECTOR_CGROUP_ARGS[@]}" -expect-exe "$(readlink -f "$RD")" -record "$COLLECTOR_RECORD" -stop-request "$STOPFILE" \
  -grace "$SUPERVISE_GRACE" -deadline "$COLLECTOR_DEADLINE_S" \
  -- "$RD" collect -socket /var/run/docker.sock "${CONTAINERS_ARG[@]}" -case-variant prod -permission root -sync attach_running \
     -config-id "$CFG" -interval "$INTERVAL" -window "$WINDOW" -phase 0 -phase-base "$WINDOW_START" -replicate 1 \
     -track-restarts -restarts-file "$R/restarts.jsonl" -out-dir "$R/collect" "${LOAD_UNMEASURED_ARGS[@]}" \
  > "$R/collect.log" 2>&1 &
CP=$!
COLLECTOR_STARTED=1
write_targets

# collector-start time comes from the collector's own supervise record
# (started_at_wall), polled for briefly since the record's first, partial
# write happens asynchronously right after supervise verifies the child -
# not from a bash-side `date` taken at an approximate moment around
# backgrounding the job.
COLLECTOR_START="$(record_field "$COLLECTOR_RECORD" 5 started_at_wall)"
[ -n "$COLLECTOR_START" ] || COLLECTOR_START="$WINDOW_START"
tl collector_start pid="$CP" at="$COLLECTOR_START"
if [ "$RUN_TRACER" = 1 ] && [ -n "$ATTACH_COMPLETE_AT" ]; then
  tl effective_observation_start mode=events at="$ATTACH_COMPLETE_AT"
else
  tl effective_observation_start mode=procfs at="$COLLECTOR_START"
fi

READY_WAITED=0
while [ ! -s "$R/collect/ready.json" ] && [ "$READY_WAITED" -lt 10 ] && kill -0 "$CP" 2>/dev/null; do
  sleep 1; READY_WAITED=$((READY_WAITED + 1))
done
if [ -s "$R/collect/ready.json" ]; then
  REG_JSON=$(cat "$R/collect/ready.json")
  REG_LIST=$(echo "$REG_JSON" | python3 -c "import json,sys;d=json.load(sys.stdin);print(','.join(d.get('attach_running') or []))")
  REG_AT=$(echo "$REG_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('updated_at',''))")
  tl target_registration_result attached="$REG_LIST" at="$REG_AT"
  log "collector registration: attached=[$REG_LIST] at=$REG_AT"
else
  warn "the collector's ready.json did not appear within ${READY_WAITED}s; its actual registration result could not be recorded"
  tl target_registration_result attached="" at=""
fi

# --- the observation window is now open: from here, a stop is recorded and the run proceeds to
# the common stop-and-save path rather than aborting outright. ---
OBSERVING=1

# window_start checkpoint: waits out the remaining lead time, then reads cgroup-stat for both
# supervised cgroups at (as close as practical to) the exact instant the window itself opens.
# How far off that instant this actually landed is recorded rather than assumed to be zero: a
# run whose window never started when it was planned to is not directly comparable with one
# whose did. Skipped entirely under KL_PROD_ALLOW_UNMEASURED_LOAD=1, since there is no dedicated
# cgroup to read a checkpoint from in the first place.
NOW_EPOCH=$(date -u +%s)
[ "$NOW_EPOCH" -lt "$WINDOW_START_EPOCH" ] && sleep $((WINDOW_START_EPOCH - NOW_EPOCH))
WINDOW_START_DRIFT_S=$(( $(date -u +%s) - WINDOW_START_EPOCH ))
WINDOW_ESTABLISHED=1
if [ "$WINDOW_START_DRIFT_S" -gt "$WINDOW_START_TOLERANCE_S" ]; then
  WINDOW_ESTABLISHED=0
  warn "window start missed by ${WINDOW_START_DRIFT_S}s (tolerance ${WINDOW_START_TOLERANCE_S}s); this run's window-relative cgroup checkpoints are less exact than usual"
fi
tl window_established value="$WINDOW_ESTABLISHED" drift_s="$WINDOW_START_DRIFT_S"
if [ "$CGROOT_MADE" = 1 ]; then
  [ "$RUN_TRACER" = 1 ] && "$RD" cgroup-stat "$TRACER_CGROUP" > "$R/cgroup-tracer-wstart.json" 2>/dev/null
  "$RD" cgroup-stat "$COLLECTOR_CGROUP" > "$R/cgroup-collector-wstart.json" 2>/dev/null
fi

log "## 7 cgroup refresh loop (periodic + on every detected generation change)"
rm -f "$CGROUP_REFRESH_FAILED_FLAG"
(
  elapsed=0; last_restart_lines=0
  while kill -0 "$CP" 2>/dev/null; do
    sleep "$RESTART_POLL_SECONDS"
    elapsed=$((elapsed + RESTART_POLL_SECONDS))
    do_refresh=0; reason=""
    if [ -f "$R/restarts.jsonl" ]; then
      n=$(wc -l < "$R/restarts.jsonl" 2>/dev/null || echo 0)
      if [ "$n" -gt "$last_restart_lines" ]; then do_refresh=1; reason=restart; last_restart_lines=$n; fi
    fi
    if [ "$elapsed" -ge "$CGROUP_REFRESH_SECONDS" ]; then
      [ "$do_refresh" = 1 ] || reason=periodic
      do_refresh=1; elapsed=0
    fi
    if [ "$do_refresh" = 1 ] && [ "$RUN_TRACER" = 1 ]; then
      ts="$(date -u +%FT%T.%NZ)"
      out=$(bash "$RUN" register-cgroups "$R/cgroup-map.json" "$RE" 2>&1)
      rc=$?
      echo "$out" >> "$R/run.log"
      if [ "$rc" = 0 ]; then
        printf '{"ts":"%s","event":"cgroup_refresh","reason":"%s","result":"success"}\n' "$ts" "$reason" >> "$R/timeline.jsonl"
      else
        printf '{"ts":"%s","event":"cgroup_refresh","reason":"%s","result":"failure"}\n' "$ts" "$reason" >> "$R/timeline.jsonl"
        printf 'cgroup refresh (%s) failed at %s: %s\n' "$reason" "$ts" "$out" > "$CGROUP_REFRESH_FAILED_FLAG"
      fi
    fi
  done
) &
REFRESH_PID=$!

log "## 8 controller loop: waits for the window's own planned end or a reason to stop early"
STOP_REASON=""
while true; do
  now_epoch="$(date -u +%s)"
  if [ -s "$STOPFILE" ]; then STOP_REASON="$(cat "$STOPFILE")"; log "## early stop requested: $STOP_REASON"; break; fi
  if [ "$now_epoch" -ge "$WINDOW_END_PLANNED_EPOCH" ]; then STOP_REASON="window_elapsed"; break; fi
  if ! kill -0 "$WATCHP" 2>/dev/null; then
    # The safety monitor cannot legitimately exit before the common stop path below is ever
    # reached: watch-run.sh's own normal exit (status 0) requires BOTH the planned window end
    # AND the termination-confirmation file, and that file is never written before this
    # controller loop has already broken out of its own accord and reached cleanup_all (see
    # its own doc comment) - so at this point in the script, that file cannot exist yet. Its
    # disappearance here is therefore never this run finishing cleanly, whatever state the
    # tracer/collector happen to be in: an operator kill, a crash, or its own
    # watch_bound_reached "giving up" (exit 3, explicitly not to be read as a clean finish)
    # are the only ways it could have gone, and none of them says anything about whether the
    # tracer/collector actually terminated cleanly either - that confirmation only ever comes
    # from each one's own supervise record, read later in cleanup_all. Unconditional failure.
    log "## safety monitor (pid $WATCHP) is no longer running before the common stop path was ever reached; this is always a failure at this point in the run, regardless of the tracer/collector's own state"
    STOP_REASON="monitor_died"
    break
  fi
  sleep 1
done
STOPPED_EARLY=0; [ "$STOP_REASON" != "window_elapsed" ] && STOPPED_EARLY=1
log "## controller loop done: stop reason = $STOP_REASON"
if [ "$STOP_REASON" = "monitor_died" ]; then
  fail_step "safety monitor (watch-run.sh) is no longer running; its own normal exit requires both the planned window end and the termination-confirmation file, neither of which had happened yet at this point, so this is a run failure regardless of the tracer/collector's own state"
fi
tl stop_reason reason="$STOP_REASON" stopped_early="$STOPPED_EARLY"

# The window's own end checkpoints are taken FIRST, before this script writes its own stop
# request (stop_supervised, below, only writes one if none is already present) or begins the
# common stop-and-save path: the reading must reflect the window's own end, not whatever
# supervise does while winding the tracer/collector down. Both cgroups still exist regardless of
# whether the process inside them has already exited on its own (-keep-cgroup), but when one
# already has - the collector's normal case, if its own sample count finished before the
# window's own planned end - the reading is a post-exit snapshot rather than a live one, and
# that substitution is recorded rather than left looking the same as a genuinely live reading.
WINDOW_CLOSED_AT="$(date -u +%FT%T.%NZ)"
if [ "$CGROOT_MADE" = 1 ]; then
  if [ "$RUN_TRACER" = 1 ]; then
    "$RD" cgroup-stat "$TRACER_CGROUP" > "$R/cgroup-tracer-wend.json" 2>/dev/null
    { [ -n "$TP" ] && kill -0 "$TP" 2>/dev/null; } || tl cgroup_wend_substituted target=tracer reason=process_already_exited
  fi
  "$RD" cgroup-stat "$COLLECTOR_CGROUP" > "$R/cgroup-collector-wend.json" 2>/dev/null
  { [ -n "$CP" ] && kill -0 "$CP" 2>/dev/null; } || tl cgroup_wend_substituted target=collector reason=process_already_exited
fi
log "## 9 window closed at $WINDOW_CLOSED_AT (stop reason: $STOP_REASON, planned end $WINDOW_END_PLANNED)"

log "## 10 common stop path: confirming supervise has finished stopping the tracer/collector"
# cleanup_all IS the common stop path (stop_supervised, then - only once that is actually
# confirmed - stopping the monitor and removing every cgroup): calling it here directly,
# rather than duplicating its steps inline, is what makes the EXIT trap's own later call to
# the SAME function a genuine re-check rather than a second, independent implementation that
# could disagree with this one about what "done" means. Before the initial stop request is
# written, the stop reason this controller loop settled on is what supervise and watch-run.sh
# see; a request written earlier (by watch-run.sh itself, or by an operator signal) is left
# exactly as it was.
[ -s "$STOPFILE" ] || echo "$STOP_REASON" > "$STOPFILE"
cleanup_all

if [ -s "$CGROUP_REFRESH_FAILED_FLAG" ]; then
  warn "at least one periodic or restart-triggered cgroup refresh failed during the run: $(cat "$CGROUP_REFRESH_FAILED_FLAG")"
fi
rm -f "$CGROUP_REFRESH_FAILED_FLAG"

ACTUAL_END="$(date -u +%FT%T.%NZ)"

# The tracer's own real stop outcome comes from its own supervise record, checked the same way
# as the collector's (see check_supervise_stop) but with the tracer's own, different
# expectation: it is a failure for the tracer to ever exit on its own (stop_requested must be
# true), whereas the collector normally does exit on its own once its internal window's sample
# count is done. No stop time is ever fabricated: if the record has no exited_at_wall (it never
# does when status is stop_unconfirmed), -stopped-at is omitted from convert entirely rather
# than substituted with the window's own planned end, and the missing confirmed exit is itself
# what fails this step below.
TRACER_EXITED_AT=""
STOPPED_AT_FLAG=()
# Every check below that reads a supervise record as FINAL - the tracer/collector's own
# exit facts, and everything convert/scan/match do with them - only happens once CLEANED
# itself says the stop was actually confirmed and every cgroup actually removed. A stop that
# was not confirmed leaves the affected process's record possibly still being written to, and
# reading it now, or proceeding to convert/match at all, would be treating a run that did not
# finish cleanly as though its own logs were already complete.
if [ "$CLEANED" = 1 ]; then
  if [ "$RUN_TRACER" = 1 ]; then
    if [ -s "$TRACER_RECORD" ]; then
      TRACER_EXITED_AT=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('exited_at_wall') or '')" "$TRACER_RECORD" 2>/dev/null)
      if [ -n "$TRACER_EXITED_AT" ]; then
        STOPPED_AT_FLAG=(-stopped-at "$TRACER_EXITED_AT")
      else
        warn "tracer's supervise record has no exited_at_wall (its own termination was never confirmed); omitting -stopped-at from convert rather than substituting the window's own planned end"
      fi
      cs_out="$(check_supervise_stop "$TRACER_RECORD" tracer "$STOP_MODE")"; cs_rc=$?
      if read_confirmation_result "$cs_rc" "$cs_out"; then
        TRACER_FAILURE=""
      else
        TRACER_FAILURE="$RESULT_FAILURE"
      fi
      TRACER_NOTE="$RESULT_NOTE"
    else
      TRACER_FAILURE="its supervise record was never written at all"; TRACER_NOTE=""
    fi
    tl tracer_stop at="$TRACER_EXITED_AT" record="$TRACER_RECORD"
    [ -n "$TRACER_NOTE" ] && warn "tracer: $TRACER_NOTE"
    [ -n "$TRACER_FAILURE" ] && fail_step "tracer: $TRACER_FAILURE"
  fi

  # The collector's own success is judged from its own supervise record the same way, but
  # with the collector's own expectation: it is normal for it to exit on its own once its
  # internal window's sample count is done (stop_requested is not itself a failure signal
  # here, unlike for the tracer, which never stops on its own).
  if [ "$INITIAL_TARGET_COUNT" -gt 0 ]; then
    if [ -s "$COLLECTOR_RECORD" ]; then
      cs_out="$(check_supervise_stop "$COLLECTOR_RECORD" collector "$STOP_MODE")"; cs_rc=$?
      if read_confirmation_result "$cs_rc" "$cs_out"; then
        COLLECTOR_FAILURE=""
      else
        COLLECTOR_FAILURE="$RESULT_FAILURE"
      fi
      COLLECTOR_NOTE="$RESULT_NOTE"
      [ -n "$COLLECTOR_NOTE" ] && warn "collector: $COLLECTOR_NOTE"
      [ -n "$COLLECTOR_FAILURE" ] && fail_step "collector: $COLLECTOR_FAILURE"
    else
      fail_step "collector's own supervise record was never written at all"
    fi
  fi
fi

tl run_actual_end at="$ACTUAL_END" stop_reason="$STOP_REASON"

if [ "$CLEANED" != 1 ]; then
  log "## done (with failures): $R - stop was not confirmed and/or cleanup did not complete; skipping conversion and matching for this run rather than treating its logs as complete"
  exit 1
fi

mapfile -t OBS_FILES < <(find "$R/collect" -maxdepth 1 -name '*__*.json' 2>/dev/null | sort)
if [ ${#OBS_FILES[@]} -eq 0 ]; then
  if [ "$INITIAL_TARGET_COUNT" -eq 0 ]; then
    # An empty target population is not a failure by itself, but any failure recorded earlier
    # (a monitor that died, an unconfirmed stop, a cgroup that could not be removed) still
    # decides the exit status: the run joins the common verdict instead of reporting success.
    log "no observation record: the target population was empty from the start (not a failure by itself)"
    tl run_end observations=0 population=empty failed_steps="${#FAILED_STEPS[@]}" warnings="${#WARNINGS[@]}"
    if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
      log "## FAILED steps (${#FAILED_STEPS[@]}):"
      for s in "${FAILED_STEPS[@]}"; do log " - $s"; done
      log "## done (with failures): $R"
      exit 1
    fi
    log "## done: $R"
    exit 0
  fi
  fail_step "no observation record was produced although ${INITIAL_TARGET_COUNT} target(s) were named"
  log "## done (with failures): $R"
  exit 1
fi

EVENTS_ARGS=()
if [ "$RUN_TRACER" = 1 ]; then
  log "## 11 convert (planned window $WINDOW_START -> $WINDOW_END_PLANNED, tracer exit ${TRACER_EXITED_AT:-not confirmed})"
  if cat "$R/trace.txt" "$R/trace.err" | "$RE" convert -in - -cgroup-map "$R/cgroup-map.json" -config-id "$CFG" -script-version 3 -variant "$VARIANT" -sync attach_running $ATTACHED \
    -buffer-pages "$PAGES" -path-buffer 256 -boot-epoch "$BOOT" -clock-error-ns "$CERR" "${STOPPED_AT_FLAG[@]}" -stop-reason "$STOP_REASON" \
    -window-start "$WINDOW_START" -window-end "$WINDOW_END_PLANNED" -out "$R/events.jsonl" > "$R/convert.log" 2>&1
  then
    EVENTS_ARGS=(-events "$R/events.jsonl")
    log "events: $(wc -l < "$R/events.jsonl" 2>/dev/null || echo 0) lines"
    tl convert_done events_file="$R/events.jsonl" result=success window_start="$WINDOW_START" window_end="$WINDOW_END_PLANNED"
  else
    tail -5 "$R/convert.log" >> "$LOG"
    tl convert_done result=failure
    fail_step "converting the collected trace to events failed"
  fi
  cat "$R/convert.log" >> "$LOG" 2>/dev/null
fi

log "## 12 intel enrichment"
if [ -n "${KL_INTEL_SNAPSHOT:-}" ]; then INTEL_ARGS=(-intel-snapshot "$KL_INTEL_SNAPSHOT")
else INTEL_ARGS=(-intel-cache experiments/runtime-discovery/out/intel-cache -out-intel-snapshot "$R/intel.json"); fi

log "## 13 scan every observed image id and match each generation (findings only, no -all-packages, no fabricated GT-B)"
if [ -z "${DOCKER_CONFIG:-}" ]; then
  # Only created, and only ever removed, when this script's own run needs
  # one - a caller's own DOCKER_CONFIG (credentials, registry auth) is
  # never touched, chmod'd or deleted.
  OWN_DOCKER_CONFIG="$(mktemp -d)"
  export DOCKER_CONFIG="$OWN_DOCKER_CONFIG"
  chmod 755 "$OWN_DOCKER_CONFIG" 2>/dev/null
fi
IFS=' ' read -r -a TRIVY_CMD_ARR <<< "${KL_TRIVY_CMD:-trivy}"

for OBSF in "${OBS_FILES[@]}"; do
  base=$(basename "$OBSF" .json)
  CNAME=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['subject']['docker']['container_name'])" "$OBSF")
  IID=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['subject']['docker']['image_id'])" "$OBSF")
  IREF=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]))['subject']['docker'];print(d.get('image_ref') or d['image_id'])" "$OBSF")
  if [ -z "$IID" ]; then
    fail_step "generation $base: no image id on the observation record; scan and match skipped"
    continue
  fi

  SCAN_KEY=$(echo "$IID" | tr -d ':')
  SCAN="$R/scans/$SCAN_KEY.json"
  if [ ! -s "$SCAN" ]; then
    log "scanning $IID for $base (KL_TRIVY_CMD=${KL_TRIVY_CMD:-trivy})"
    if "${TRIVY_CMD_ARR[@]}" image --format json --scanners vuln --severity HIGH,CRITICAL "$IID" > "$SCAN.tmp" 2> "$R/scans/$SCAN_KEY.err"; then
      mv "$SCAN.tmp" "$SCAN"
      tl scan_done image_id="$IID" container="$CNAME" result=success
    else
      log "scan failed for $IID: $(tail -1 "$R/scans/$SCAN_KEY.err")"
      rm -f "$SCAN.tmp"
      tl scan_done image_id="$IID" container="$CNAME" result=failure
      fail_step "generation $base: Trivy scan of $IID failed"
      continue
    fi
  else
    tl scan_done image_id="$IID" container="$CNAME" result=cached
  fi

  CASEJSON="$R/case/$base.json"
  cat > "$CASEJSON" <<EOF
{"case_id": "prod-$base", "image": "$IREF", "description": "attach_running production observation; no ground truth declared; every verdict is derived from observation alone", "expected": []}
EOF

  mkdir -p "$R/csv_hc/$base"
  if "$RD" match -observation "$OBSF" -trivy "$SCAN" -case "$CASEJSON" "${EVENTS_ARGS[@]}" "${INTEL_ARGS[@]}" \
    -out-json "$R/match/$base.match_hc.json" -out-csv-dir "$R/csv_hc/$base" > "$R/match/$base.log" 2>&1
  then
    tail -3 "$R/match/$base.log" >> "$LOG"
    tl match_done container="$CNAME" record="$base" result=success

    python3 - "$OBSF" "$R/match/$base.match_hc.json" "$CNAME" "$base" <<'PY' >> "$R/timeline.jsonl"
import json, sys
obs_path, match_path, cname, base = sys.argv[1:5]
obs = json.load(open(obs_path))
aux = obs.get("auxiliary_inputs") or []
layout_times = [a["collected_at"] for a in aux if a.get("collected_at") and not a.get("invalid")]
first_layout = min(layout_times) if layout_times else None
try:
    m = json.load(open(match_path))
except (OSError, json.JSONDecodeError):
    m = {}
lang_evidence_times = []
for pv in m.get("packages", []):
    if pv.get("class") != "lang":
        continue
    for c in pv.get("confirmations", []):
        at = c.get("observed_at")
        if at:
            lang_evidence_times.append(at)
first_lang_evidence = min(lang_evidence_times) if lang_evidence_times else None
out = {
    "ts": obs.get("window", {}).get("scheduled_end") or "",
    "event": "first_evidence_summary",
    "container": cname,
    "record": base,
    "first_layout_reading": first_layout,
    "first_language_package_evidence": first_lang_evidence,
}
print(json.dumps(out))
PY
  else
    tail -5 "$R/match/$base.log" >> "$LOG"
    tl match_done container="$CNAME" record="$base" result=failure
    fail_step "generation $base: match failed"
  fi
done

log "## 14 folding restarts.jsonl into the timeline"
if [ -s "$R/restarts.jsonl" ]; then
  python3 - "$R/restarts.jsonl" <<'PY' >> "$R/timeline.jsonl"
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    ev = json.loads(line)
    out = {"ts": ev.get("detected_at", ""), "event": "generation_change"}
    out.update(ev)
    print(json.dumps(out))
PY
fi

tl run_end observations="${#OBS_FILES[@]}" failed_steps="${#FAILED_STEPS[@]}" warnings="${#WARNINGS[@]}"
if [ ${#WARNINGS[@]} -gt 0 ]; then
  log "## warnings (${#WARNINGS[@]}):"
  for w in "${WARNINGS[@]}"; do log " - $w"; done
fi
[ -n "$OWN_DOCKER_CONFIG" ] && rm -rf "$OWN_DOCKER_CONFIG" 2>/dev/null
if [ ${#FAILED_STEPS[@]} -gt 0 ]; then
  log "## FAILED steps (${#FAILED_STEPS[@]}):"
  for s in "${FAILED_STEPS[@]}"; do log " - $s"; done
  log "## done (with failures): $R"
  exit 1
fi
log "## done: $R"
