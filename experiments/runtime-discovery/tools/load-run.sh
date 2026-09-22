#!/usr/bin/env bash
# What: runs one load/overhead measurement for the coverage-validation cases (26-28), always
# joining a workload that is already running (attach_running), under one of three observation
# configurations that differ only in what is watching, never in what the workload itself does:
#   none    - no collector, no tracer: just the workload and the host-side web request loop
#   procfs  - the collector alone (no event collection)
#   events  - the collector plus a 512-page bpftrace tracer
#
# All process supervision (cgroup creation, starting the child INSIDE its cgroup from its
# very first instruction, verifying its actual exe/uid, forwarding a stop request through a
# bounded SIGINT/SIGTERM/SIGKILL sequence, enforcing a hard deadline, reading final cpu/mem
# counters, and confirming the child and its descendants have actually gone) is delegated to
# the Go `supervise` subcommand - this script's own job is deciding WHEN to start things,
# WHEN the common observation window opens and closes, and assembling the result; see
# experiments/runtime-discovery/supervise.go. cgroup readings this script takes directly (at
# the window's own start/end, not supervise's own before/after) go through the `cgroup-stat`
# subcommand the same way, and the cgroups themselves are removed by this script through
# `cgroup-remove` - children first, then their parent - once every final reading is in hand.
# That is why every supervised process here is started with -keep-cgroup: a collector whose
# own sampling loop finishes before the window's end must not take its cgroup, and with it
# the window-end counters, away with it.
#
# Three instants are kept apart and never collapsed into one:
#   the window's own PLANNED end (start + -window seconds),
#   the instant this run actually closed the window (a stop request, or the planned end),
#   and the tracer's own real exit time, read from its supervise record.
# The converter is given the planned window plus the tracer's own exit time, so a run that
# stopped early is reported as exactly that (stopped_early with the gap to the planned end)
# instead of appearing to have run its window out.
#
# Ordering: the safety watcher starts FIRST, before anything it might have to watch exists;
# the tracer then starts and its attachment and cgroup map are confirmed; and only once all
# of that preparation is done is the common observation window's own start decided (the
# start barrier). Deciding it up front instead would let a slow attach-check push the real
# start past it, leaving the collector with a phase base already in the past.
#
# Usage (from the repository root):
#   sudo bash experiments/runtime-discovery/tools/load-run.sh <case> [replicate] [config] [interval] [window]
#   case      = 26 | 27 | 28
#   replicate = 1, 2, ... (default 1)
#   config    = none | procfs | events (default procfs)
#   interval  = seconds between collector sample starts, default 30 (30 and 10 are the two
#               conditions in use; meaningless for config=none, which starts no collector)
#   window    = observation-window seconds, default 300
#
# Prerequisites: run as root (supervise creates cgroup v2 directories under
# /sys/fs/cgroup), bpftrace installed for config=events, Docker Engine's native daemon
# reachable at /var/run/docker.sock, and the runtime-discovery/runtime-events binaries
# built into experiments/runtime-discovery/out/.
#
# Output: experiments/runtime-discovery/out/<case>-load-<config>-<interval>-<window>-r<replicate>-attach_running/
# holding run.log, case.json, clock.json, cgroup-map.json (events only), container_id.txt,
# image_id.txt, fired_at.txt, gtb-raw/{usage,occurrences,operations,runtime-modules}.jsonl,
# trace.txt/trace.err/events.jsonl (events only), tracer_supervise.json/collector_supervise.json,
# cgroup-*-wstart.json/cgroup-*-wend.json (per-target cgroup-stat snapshots),
# cgroup-remove-*.json (the ordered child-then-parent cgroup removals), collect/ (procfs and
# events), web_timing.jsonl, watch.jsonl, stop_request.txt (only if the run stopped early),
# container.log, docker-top.txt, and load.json (this run's own overhead summary, written
# even after an early stop).
set -uo pipefail
cd "${KL_ROOT:-$(dirname "$0")/../../..}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./load-lib.sh
. "$here/load-lib.sh"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock
OWNER="${SUDO_USER:-$(id -un)}"
O=experiments/runtime-discovery/out; T=experiments/runtime-discovery/tools; B=$O/runtime-discovery; E=$O/runtime-events
RUN=experiments/runtime-discovery/cases/run.sh; CASES=experiments/runtime-discovery/cases
USAGE="Usage: sudo bash experiments/runtime-discovery/tools/load-run.sh <case> [replicate] [none|procfs|events] [interval] [window]"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
c="$1"; REP="${2:-1}"; CONFIG="${3:-procfs}"; IV="${4:-30}"; WIN="${5:-300}"
case "$c" in 26|27|28) ;; *) echo "load-run.sh only measures the coverage-validation cases: 26, 27 or 28" >&2; exit 2;; esac
case "$CONFIG" in none|procfs|events) ;; *) echo "config must be none, procfs or events" >&2; exit 2;; esac
case "$IV" in ''|*[!0-9]*) echo "interval must be a positive whole number of seconds" >&2; exit 2;; esac
case "$WIN" in ''|*[!0-9]*) echo "window must be a positive whole number of seconds" >&2; exit 2;; esac
[ "$IV" -gt 0 ] || { echo "interval must be a positive whole number of seconds" >&2; exit 2; }
[ "$WIN" -gt 0 ] || { echo "window must be a positive whole number of seconds" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "load-run: run as root (supervise creates cgroup v2 directories)" >&2; exit 1; }
CASEJSON=$CASES/$c.json; CONTAINER="case$c"
case "$c" in
  26) HEALTH_URL=http://127.0.0.1:18110/health;;
  27) HEALTH_URL=http://127.0.0.1:18111/health;;
  28) HEALTH_URL=http://127.0.0.1:18112/health;;
esac
case "$CONFIG" in
  none)   RUN_COLLECTOR=0; RUN_TRACER=0;;
  procfs) RUN_COLLECTOR=1; RUN_TRACER=0;;
  events) RUN_COLLECTOR=1; RUN_TRACER=1;;
esac
BT=experiments/runtime-events/bpftrace/runtime-events-nofilter-512p.bt
VARIANT=nofilter-512p; CFG_EVENTS=bpftrace-v2-nofilter-512p; CFG_PROCFS=none
DOCKER_CG=/sys/fs/cgroup/system.slice/docker.service
# bpftrace reads these from the environment; supervise removes them from the CHILD's own
# environment directly (-unset-env), rather than this script wrapping the command in `env
# -u ...`, so the process supervise starts, verifies and supervises is bpftrace itself.
BPF_UNSET_ENV=BPFTRACE_MAX_STRLEN,BPFTRACE_PERF_RB_PAGES,BPFTRACE_ON_STACK_LIMIT
SUPERVISE_GRACE="${KL_STOP_TIMEOUT_S:-15}"       # per-signal-stage wait supervise itself uses
SUPERVISE_WAIT_S="${KL_SUPERVISE_WAIT_S:-90}"    # how long this script waits for one supervise process to finish its own stop sequence
LEAD_S="${KL_WINDOW_LEAD_S:-5}"                  # seconds between the start barrier and the window's own start (the collector's own startup)
WINDOW_START_TOLERANCE_S="${KL_WINDOW_START_TOLERANCE_S:-2}"
PREP_BUDGET_S="${KL_PREP_BUDGET_S:-180}"         # allowance for tracer start + attach-check + cgroup map, for the tracer's own deadline
HARD_DEADLINE_GRACE="${KL_WATCH_HARD_DEADLINE_GRACE_S:-120}"
CGROUP_REMOVE_WAIT_S="${KL_CGROUP_REMOVE_WAIT_S:-30}"

RUNID="$c-load-$CONFIG-$IV-$WIN-r$REP-attach_running"
R="$O/$RUNID"
# $$ (this shell's own PID) makes the cgroup name unique to this specific invocation, not
# just to this run's identity: a earlier, incompletely torn down run under the same RUNID
# would otherwise leave a same-named cgroup that supervise's own cgroup creation (which
# fails if the directory already exists) would then simply fail against, rather than
# silently reusing its stale counters.
CGROOT="/sys/fs/cgroup/runtime-discovery-load-$RUNID-$$"

FREE_BYTES_LIMIT="${KL_WATCH_FREE_BYTES:-21474836480}" # 20 GiB, overridable to match watch-run.sh
mkdir -p "$O"
FREE_NOW="$(fs_free_bytes "$O" 2>/dev/null || true)"
if [ -n "$FREE_NOW" ] && [ "$FREE_NOW" -lt "$FREE_BYTES_LIMIT" ]; then
  echo "load-run: free space on $O's filesystem ($FREE_NOW bytes) is below the ${FREE_BYTES_LIMIT}-byte minimum; not starting" >&2
  exit 1
fi

rm -rf "$R"; mkdir -p "$R/collect" "$R/gtb-raw"; LOG=$R/run.log
log(){ echo "$(date -u +%FT%T.%NZ) $*" | tee -a "$LOG"; }
log "## case $c replicate $REP config $CONFIG interval $IV window $WIN sync attach_running -> $R"
STOPFILE="$R/stop_request.txt"
STOP_FAILURES="$R/stop_failures.txt"
# The watcher treats termination as undetermined until this file appears, and it is written
# in exactly one place: finish_or_hold's confirmed branch, after every supervision record
# has been checked and every one of them confirmed its child stopped. Nothing else creates
# it, and nothing reassigns this path.
CONFIRMED_FILE="$R/termination_confirmed.txt"

DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)
case "$DAEMON" in "") echo "docker daemon unreachable" >&2; rm -rf "$R"; exit 1;; *Desktop*) echo "docker socket belongs to Docker Desktop ($DAEMON); the measurement needs the native daemon" >&2; rm -rf "$R"; exit 1;; esac
if [ "$RUN_TRACER" = 1 ] && ! command -v bpftrace >/dev/null; then echo "bpftrace not installed" >&2; rm -rf "$R"; exit 1; fi

# --- OBSERVING gates the INT/TERM trap below: once the window is open, a signal writes a
# stop request and lets the main loop's own stop-and-save path run, exactly like any other
# stop condition (watch-run.sh's own, or the window's own planned end). Before that, the
# SAME signal aborts the run - but through the same common stop path, never by signalling a
# supervise process directly: a SIGKILL to a supervisor is the one thing that would leave
# the real bpftrace or collector running with nothing left to stop it.
OBSERVING=0
TP=""; CP=""; WATCHP=""; WEBP=""; ATTACHED_OK=0
CGROOT_MADE=0; CLEANED=0
# TERMINATION_OK is this run's own answer to "is everything this script started actually
# gone?", and it is NOT the same question as "did the supervise processes exit". A
# supervisor exits after writing its record whatever became of its child, so the child's own
# termination - and the emptiness of the cgroup it ran in - is only established by that
# record. While it is 0 nothing is torn down: the safety watcher keeps running, the cgroups
# and every artifact stay where they are, and this script exits non-zero saying why.
TERMINATION_OK=1; RESIDUAL_UNCONFIRMED=0
WINDOW_END_PLANNED_EPOCH=""
RESIDUAL_WATCH_S="${KL_RESIDUAL_WATCH_S:-1800}"  # how long the watcher keeps going after an unconfirmed termination
TRACER_CGROUP="$CGROOT/tracer"; COLLECTOR_CGROUP="$CGROOT/collector"
TARGETS="$R/watch_targets.txt"

# write_targets (re)publishes what watch-run.sh should be watching. It is written before the
# watcher starts (naming which processes this run WILL have, but with no pids yet) and
# rewritten as each one comes up, so the watcher is already running - and already enforcing
# the disk/space limits - during the tracer's own startup and attach, not only afterwards.
# expect_tracer/expect_collector are what stop the watcher from reading a preparation phase
# in which no pid exists yet as "everything has already finished"; min_until_epoch keeps it
# going to the window's own end even when the collector's last sample - and with it the
# collector itself - finished earlier, which for a 300s window at a 30s interval is about
# thirty seconds of the window that would otherwise go unwatched; and
# termination_confirmed_file is what the watcher waits for before believing that everything
# this run started has actually stopped, since a vanished supervisor says nothing about the
# descendants its child may have left. The rename is what makes each version appear whole:
# the watcher sources this file every sample.
write_targets(){
  local tracer_cg="-" trace_err="-" WATCH_UNTIL_EPOCH end now
  # The single absolute bound on watching: the window's own end once it is known, and an
  # allowance for the preparation plus the window before that, so a runner that dies at any
  # point - before it ever announced a pid, or while a supervisor is still lingering - still
  # leaves the watcher a finite life. A run held open because its termination could not be
  # confirmed extends the same bound rather than introducing a second one that could
  # disagree with it.
  now="$(date -u +%s)"
  end="$WINDOW_END_PLANNED_EPOCH"
  [ -n "$end" ] || end=$(( now + PREP_BUDGET_S + WIN ))
  WATCH_UNTIL_EPOCH=$(( end + RESIDUAL_WATCH_S ))
  if [ "$RESIDUAL_UNCONFIRMED" = 1 ] && [ $(( now + RESIDUAL_WATCH_S )) -gt "$WATCH_UNTIL_EPOCH" ]; then
    WATCH_UNTIL_EPOCH=$(( now + RESIDUAL_WATCH_S ))
  fi
  if [ "$RUN_TRACER" = 1 ]; then tracer_cg="$TRACER_CGROUP"; trace_err="$R/trace.err"; fi
  {
    printf 'expect_tracer=%q\n' "$RUN_TRACER"
    printf 'expect_collector=%q\n' "$RUN_COLLECTOR"
    printf 'tracer_pid=%q\n' "${TP:--}"
    printf 'collector_pid=%q\n' "${CP:--}"
    printf 'tracer_cgroup=%q\n' "$tracer_cg"
    printf 'trace_err=%q\n' "$trace_err"
    printf 'web_timing=%q\n' "$R/web_timing.jsonl"
    printf 'min_until_epoch=%q\n' "$WINDOW_END_PLANNED_EPOCH"
    printf 'residual_unconfirmed=%q\n' "$RESIDUAL_UNCONFIRMED"
    printf 'termination_confirmed_file=%q\n' "$CONFIRMED_FILE"
    printf 'watch_until_epoch=%q\n' "$WATCH_UNTIL_EPOCH"
  } > "$TARGETS.tmp"
  mv "$TARGETS.tmp" "$TARGETS"
}

# wait_for_supervisor waits for one supervise process to finish the bounded stop sequence it
# performs on its own child, escalating only as far as a SIGTERM of the SUPERVISOR (which
# makes it run that same sequence) - never a SIGKILL of it, which would abandon the real
# tracer or collector. A supervisor that still has not finished is recorded as a stop
# failure rather than papered over; the cgroup removal below then reports the cgroup as
# still populated, with its own reason, instead of the run appearing to have cleaned up.
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
    echo "$label supervise did not finish its stop sequence within $((SUPERVISE_WAIT_S * 2))s" >> "$STOP_FAILURES"
    return 1
  fi
  wait "$pid" 2>/dev/null
  log "$label supervise exit $?"
  return 0
}

# termination_state prints "confirmed", or "unconfirmed: <why>", for one supervised process,
# read from the record supervise itself wrote. This is a different question from whether the
# supervisor exited: a supervisor exits after writing that record whatever became of its
# child, so a stop that SIGKILL never confirmed, or a cgroup still holding a descendant, both
# leave a supervisor that exited cleanly behind a child that did not.
termination_state(){
  python3 -c '
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except (OSError, ValueError) as e:
    print("unconfirmed: the supervision record could not be read (%s)" % e); raise SystemExit
tc = r.get("termination_confirmed") or {}
if tc.get("measured") and tc.get("value"):
    print("confirmed"); raise SystemExit
print("unconfirmed: status=%s, %s" % (r.get("status"), tc.get("reason") or "the record carries no termination_confirmed field"))
' "$1" 2>/dev/null || echo "unconfirmed: the supervision record could not be read"
}

confirm_termination(){
  local label="$1" record="$2" state
  state="$(termination_state "$record")"
  if [ "$state" = confirmed ]; then return 0; fi
  log "$label: termination NOT confirmed ($state)"
  echo "$label: $state" >> "$STOP_FAILURES"
  return 1
}

# stop_supervised is the one stop path, used from the window's own end, from an operator
# signal (whether the window is open or not) and from the failure path: request the stop in
# the file every supervise process already polls, wait for each supervisor to finish, and
# then confirm from its own record that the CHILD is gone too. It returns non-zero unless
# every one of those is confirmed - and the caller is what must not tear anything down until
# it is.
stop_supervised(){
  local reason="$1" rc=0
  [ -n "$TP$CP" ] || return 0
  [ -s "$STOPFILE" ] || echo "$reason" >"$STOPFILE"
  if [ -n "$TP" ]; then
    wait_for_supervisor tracer "$TP" || rc=1
    confirm_termination tracer "$TRACER_RECORD" || rc=1
    TP=""
  fi
  if [ -n "$CP" ]; then
    wait_for_supervisor collector "$CP" || rc=1
    confirm_termination collector "$COLLECTOR_RECORD" || rc=1
    CP=""
  fi
  return "$rc"
}

# remove_cgroups removes what supervise deliberately left behind (-keep-cgroup): each
# child cgroup first, then their common parent, each attempt recorded as its own JSON file
# so a removal that could not happen is a stated fact with a reason, not a silent leftover.
remove_cgroups(){
  local path label
  for label in tracer collector; do
    case "$label" in tracer) path="$TRACER_CGROUP";; collector) path="$COLLECTOR_CGROUP";; esac
    [ -d "$path" ] || continue
    "$B" cgroup-remove -wait "$CGROUP_REMOVE_WAIT_S" "$path" > "$R/cgroup-remove-$label.json" 2>>"$LOG" \
      || log "cgroup-remove $label FAILED: $(cat "$R/cgroup-remove-$label.json" 2>/dev/null)"
  done
  if [ "$CGROOT_MADE" = 1 ] && [ -d "$CGROOT" ]; then
    "$B" cgroup-remove -wait "$CGROUP_REMOVE_WAIT_S" "$CGROOT" > "$R/cgroup-remove-parent.json" 2>>"$LOG" \
      || log "cgroup-remove parent FAILED: $(cat "$R/cgroup-remove-parent.json" 2>/dev/null)"
  fi
}

cleanup_all(){
  if [ "$CLEANED" = 0 ]; then
    CLEANED=1
    [ -n "$WEBP" ] && { stop_process "$WEBP" TERM 5 "web-probe loop" 2>&1 | tee -a "$LOG" >/dev/null; WEBP=""; }
    stop_supervised "runner_cleanup" || TERMINATION_OK=0
    finish_or_hold
    docker rm -f "$CONTAINER" >/dev/null 2>&1
  fi
  chown -R "$OWNER":"$OWNER" "$R" 2>/dev/null
}

# finish_or_hold is the single place that decides whether this run may be torn down. Only a
# confirmed termination of every supervised child lets the watcher be stopped and the cgroups
# removed; otherwise both are deliberately left running and in place - something this script
# started may still be consuming CPU and disk, which is exactly when a safety monitor is
# worth keeping, and a cgroup still holding a task cannot be removed anyway.
finish_or_hold(){
  if [ "$TERMINATION_OK" = 1 ]; then
    # Written only here, and only after every record was checked: this is what releases the
    # watcher, which otherwise treats termination as undetermined no matter what the pids
    # look like. Writing it before stopping the watcher also means a runner killed in the
    # next instant still leaves the watcher able to finish on its own.
    printf 'every supervised child confirmed stopped at %s\n' "$(date -u +%FT%T.%NZ)" > "$CONFIRMED_FILE"
    if [ ! -s "$CONFIRMED_FILE" ]; then
      # Writing it is the whole mechanism by which the watcher learns it may stop, so a
      # write that did not happen is a failure of this run, not a detail: without it the
      # watcher would keep going to its own bound with termination reading as undetermined,
      # while this script reported a clean finish.
      TERMINATION_OK=0
      log "## could not write the termination confirmation to $CONFIRMED_FILE"
      echo "the termination confirmation could not be written to $CONFIRMED_FILE" >> "$STOP_FAILURES"
    else
      [ -n "$WATCHP" ] && { stop_process "$WATCHP" TERM 5 "watch-run.sh" 2>&1 | tee -a "$LOG" >/dev/null; WATCHP=""; }
      remove_cgroups
      return 0
    fi
  fi
  RESIDUAL_UNCONFIRMED=1
  write_targets
  log "## termination unconfirmed: leaving the safety watcher (pid ${WATCHP:-none}) running for up to ${RESIDUAL_WATCH_S}s and leaving the cgroups under $CGROOT in place; every artifact stays in $R"
  log "## reasons: $(tr '\n' '; ' < "$STOP_FAILURES" 2>/dev/null)"
  return 1
}
fail(){ log "FAILED (setup): $*"; cleanup_all; exit 1; }
handle_signal(){
  local sig="$1"
  if [ "$OBSERVING" = 1 ]; then
    log "operator stop: received $sig during observation"
    echo "operator_stop_$sig" >"$STOPFILE"
  else
    log "received $sig during preparation; stopping everything already started through the common stop path"
    echo "operator_stop_${sig}_during_preparation" >"$STOPFILE"
    cleanup_all
    exit 130
  fi
}
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'cleanup_all' EXIT

cp "$CASEJSON" "$R/case.json"

log "## 1 clock"
"$E" clock -out "$R/clock.json" || fail clock
BOOT=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['boot_epoch'])"); CERR=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['error_ns'])")

if [ "$RUN_COLLECTOR" = 1 ] || [ "$RUN_TRACER" = 1 ]; then
  mkdir "$CGROOT" || fail "cgroup: cannot create $CGROOT (a leftover of the same name from an earlier, incompletely torn down run?)"
  CGROOT_MADE=1
fi

log "## 2 build and start the workload (attach_running: fired before anything observes it)"
bash "$RUN" build "$c" > "$R/build.log" 2>&1 || fail "build: $(tail -5 "$R/build.log")"
bash "$RUN" up "$c" > "$R/up.log" 2>&1 || fail "up: $(tail -2 "$R/up.log")"
docker inspect -f '{{.Id}}' "$CONTAINER" > "$R/container_id.txt"; docker inspect -f '{{.Image}}' "$CONTAINER" > "$R/image_id.txt"
log "container $(cut -c1-12 "$R/container_id.txt") image $(cat "$R/image_id.txt")"
bash "$RUN" fire-when-ready "$c" 900 2>&1 | tee -a "$LOG" || fail "fire-when-ready"
FIRED_AT=$(date -u +%FT%T.%NZ); echo "$FIRED_AT" >"$R/fired_at.txt"; log "fired at $FIRED_AT"
bash "$RUN" wait-after-lazy-phase "$c" 120 2>&1 | tee -a "$LOG" || fail "wait-after-lazy-phase"

# --- the safety watcher starts here, before the tracer exists: the compile and attach that
# follow are themselves capable of consuming CPU and filling the output filesystem, and a
# stop monitor that only starts afterwards cannot see any of it. It re-reads its targets
# file every sample, so the pids and cgroup below reach it as soon as they exist. ---
log "## 3 safety watcher (starts before anything it watches exists)"
write_targets
bash "$here/watch-run.sh" "$R" "$O" "$TARGETS" "$STOPFILE" >"$R/watch.log" 2>&1 &
WATCHP=$!

TRACER_RECORD="$R/tracer_supervise.json"
COLLECTOR_RECORD="$R/collector_supervise.json"
TRACER_DEADLINE_S=$(( PREP_BUDGET_S + LEAD_S + WIN + HARD_DEADLINE_GRACE ))
if [ "$RUN_TRACER" = 1 ]; then
  log "## 4 tracer start via supervise ($BT), then attach confirmation and cgroup map - all before the window's own start is decided"
  BPF_EXE="$(command -v bpftrace)"
  "$B" supervise -cgroup "$TRACER_CGROUP" -expect-exe "$BPF_EXE" -record "$TRACER_RECORD" -stop-request "$STOPFILE" \
    -grace "$SUPERVISE_GRACE" -deadline "$TRACER_DEADLINE_S" -allow-unmeasured -keep-cgroup -unset-env "$BPF_UNSET_ENV" \
    -- "$BPF_EXE" "$BT" \
    > "$R/trace.txt" 2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$l"; done > "$R/trace.err") &
  TP=$!
  write_targets
  sleep 2
  if bash "$RUN" attach-check "$R/trace.txt" 30 2>&1 | tee -a "$LOG"; then ATTACHED_OK=1; fi
  bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"
fi

# --- start barrier: preparation is done, so the common window's own start is decided NOW
# (not before the attach-check that might have overrun it) and the collector is given it as
# its own -phase-base. LEAD_S is only what the collector's own startup needs. ---
WINDOW_START_EPOCH=$(( $(date -u +%s) + LEAD_S ))
WINDOW_START=$(date -u -d "@$WINDOW_START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
WINDOW_END_PLANNED_EPOCH=$(( WINDOW_START_EPOCH + WIN ))
WINDOW_END_PLANNED=$(date -u -d "@$WINDOW_END_PLANNED_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
COLLECTOR_DEADLINE_S=$(( LEAD_S + WIN + HARD_DEADLINE_GRACE ))
log "## 5 start barrier: preparation complete, window start $WINDOW_START (+${LEAD_S}s lead), planned end $WINDOW_END_PLANNED"

if [ "$RUN_COLLECTOR" = 1 ]; then
  log "## 6 collector joins the running workload via supervise, phase-base = $WINDOW_START"
  CFGID="$CFG_PROCFS"
  [ "$RUN_TRACER" = 1 ] && CFGID="$CFG_EVENTS"
  "$B" supervise -cgroup "$COLLECTOR_CGROUP" -expect-exe "$(readlink -f "$B")" -record "$COLLECTOR_RECORD" -stop-request "$STOPFILE" \
    -grace "$SUPERVISE_GRACE" -deadline "$COLLECTOR_DEADLINE_S" -keep-cgroup \
    -- "$B" collect -socket /var/run/docker.sock -containers "$CONTAINER" -case-variant "$c" -permission root -sync attach_running -config-id "$CFGID" \
       -interval "$IV" -window "$WIN" -phase 0 -phase-base "$WINDOW_START" -replicate "$REP" -out-dir "$R/collect" \
    > "$R/collect.log" 2>&1 &
  CP=$!
  write_targets
fi

# --- the observation window is now open (from this point, a stop is recorded and saved
# rather than aborting the run outright). ---
OBSERVING=1

# window_start checkpoint: waits out the remaining lead time, then reads cgroup-stat for
# every target at (as close as practical to) the exact instant the window itself opens. How
# far off that instant this actually landed is recorded rather than assumed to be zero: a
# run whose window never started when it was planned to is not comparable with one whose did.
NOW_EPOCH=$(date -u +%s)
[ "$NOW_EPOCH" -lt "$WINDOW_START_EPOCH" ] && sleep $((WINDOW_START_EPOCH - NOW_EPOCH))
WINDOW_START_DRIFT_S=$(( $(date -u +%s) - WINDOW_START_EPOCH ))
WINDOW_ESTABLISHED=1
if [ "$WINDOW_START_DRIFT_S" -gt "$WINDOW_START_TOLERANCE_S" ]; then
  WINDOW_ESTABLISHED=0
  log "## window start missed by ${WINDOW_START_DRIFT_S}s (tolerance ${WINDOW_START_TOLERANCE_S}s); this run's window is recorded as not established and is excluded from comparisons"
fi
[ "$RUN_COLLECTOR" = 1 ] && "$B" cgroup-stat "$COLLECTOR_CGROUP" > "$R/cgroup-collector-wstart.json" 2>/dev/null
[ "$RUN_TRACER" = 1 ] && "$B" cgroup-stat "$TRACER_CGROUP" > "$R/cgroup-tracer-wstart.json" 2>/dev/null
"$B" cgroup-stat "$DOCKER_CG" > "$R/cgroup-docker-wstart.json" 2>/dev/null
# Trace output byte counts at the window's own start, so a rate can be computed from the
# DELTA between this and the window-end reading below over exactly the window's own
# duration - not from the trace file's own whole-lifetime size (which also carries the
# tracer's pre-window prep and post-window drain output) divided by the window seconds.
if [ "$RUN_TRACER" = 1 ]; then
  wc -c <"$R/trace.txt" 2>/dev/null > "$R/trace-stdout-wstart-bytes.txt" || echo 0 > "$R/trace-stdout-wstart-bytes.txt"
  wc -c <"$R/trace.err" 2>/dev/null > "$R/trace-stderr-wstart-bytes.txt" || echo 0 > "$R/trace-stderr-wstart-bytes.txt"
fi

log "## 7 window open: start $WINDOW_START, host-side web request loop until the planned end ($WINDOW_END_PLANNED) or a stop request"
web_probe_loop(){
  local planned="$WINDOW_START_EPOCH.0" end="$WINDOW_END_PLANNED_EPOCH.0" seq=0
  while awk -v p="$planned" -v e="$end" 'BEGIN{exit !(p<=e)}'; do
    [ -s "$STOPFILE" ] && return 0
    local now delay
    now="$(date -u +%s.%N)"
    delay="$(awk -v p="$planned" -v n="$now" 'BEGIN{d=p-n; if(d<0)d=0; printf "%.3f", d}')"
    while awk -v d="$delay" 'BEGIN{exit !(d>0.05)}'; do
      [ -s "$STOPFILE" ] && return 0
      sleep 0.5
      delay="$(awk -v d="$delay" 'BEGIN{d2=d-0.5; if(d2<0)d2=0; printf "%.3f", d2}')"
    done
    seq=$((seq + 1))
    local planned_ts t0 out curl_rc status ttotal latency_ms ok timeout_type
    planned_ts="$(date -u -d "@$planned" +%Y-%m-%dT%H:%M:%S.%NZ)"
    t0="$(date -u +%FT%T.%NZ)"
    out="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --connect-timeout 2 --max-time 4 "$HEALTH_URL" 2>>"$R/web_timing.err")"
    curl_rc=$?
    timeout_type="none"; status="null"; latency_ms="null"; ok=false
    if [ "$curl_rc" -eq 0 ]; then
      status="${out%% *}"; ttotal="${out##* }"
      latency_ms="$(awk -v t="$ttotal" 'BEGIN{printf "%.1f", t*1000}')"
      case "$status" in 2??|3??) ok=true;; esac
      status="\"$status\""
    else
      case "$curl_rc" in
        28) timeout_type="operation_timeout";;
        7)  timeout_type="connection_failed";;
        6)  timeout_type="resolve_failed";;
        52) timeout_type="empty_reply";;
        *)  timeout_type="curl_error_$curl_rc";;
      esac
    fi
    printf '{"planned_ts":"%s","ts":"%s","seq":%d,"status":%s,"latency_ms":%s,"ok":%s,"curl_exit":%d,"timeout_type":"%s"}\n' \
      "$planned_ts" "$t0" "$seq" "$status" "$latency_ms" "$ok" "$curl_rc" "$timeout_type" >>"$R/web_timing.jsonl"
    planned="$(awk -v p="$planned" 'BEGIN{printf "%.6f", p+5}')"
  done
}
web_probe_loop &
WEBP=$!

STOP_REASON=""
while true; do
  now_epoch="$(date -u +%s)"
  if [ -s "$STOPFILE" ]; then STOP_REASON="$(cat "$STOPFILE")"; log "## early stop requested: $STOP_REASON"; break; fi
  if [ "$now_epoch" -ge "$WINDOW_END_PLANNED_EPOCH" ]; then STOP_REASON="window_elapsed"; break; fi
  sleep 1
done
STOPPED_EARLY=0; [ "$STOP_REASON" != "window_elapsed" ] && STOPPED_EARLY=1

# The window's own end checkpoints are taken FIRST, before this script writes its own stop
# request: the reading must belong to the window, not to whatever the tracer and collector
# did while winding down. (The cgroups themselves survive either way - every supervise here
# runs with -keep-cgroup - but the counters would not still be the window's.)
WINDOW_END=$(date -u +%FT%T.%NZ)
[ "$RUN_COLLECTOR" = 1 ] && "$B" cgroup-stat "$COLLECTOR_CGROUP" > "$R/cgroup-collector-wend.json" 2>/dev/null
[ "$RUN_TRACER" = 1 ] && "$B" cgroup-stat "$TRACER_CGROUP" > "$R/cgroup-tracer-wend.json" 2>/dev/null
"$B" cgroup-stat "$DOCKER_CG" > "$R/cgroup-docker-wend.json" 2>/dev/null
if [ "$RUN_TRACER" = 1 ]; then
  wc -c <"$R/trace.txt" 2>/dev/null > "$R/trace-stdout-wend-bytes.txt" || echo 0 > "$R/trace-stdout-wend-bytes.txt"
  wc -c <"$R/trace.err" 2>/dev/null > "$R/trace-stderr-wend-bytes.txt" || echo 0 > "$R/trace-stderr-wend-bytes.txt"
fi
log "## 8 window closed at $WINDOW_END (stop reason: $STOP_REASON, planned end $WINDOW_END_PLANNED)"

stop_process "$WEBP" TERM 5 "web-probe loop" 2>&1 | tee -a "$LOG" >/dev/null; WEBP=""

# The tracer/collector's own stop (SIGINT->SIGTERM->SIGKILL with bounded waits) is entirely
# supervise's own job, driven by the stop-request file stop_supervised writes; this script
# only confirms each supervisor finished doing it.
stop_supervised "$STOP_REASON" || TERMINATION_OK=0

# Every final reading is now in hand. Only if every supervised CHILD has been confirmed gone
# - not merely its supervisor - does this stop the watcher and remove the cgroups this run
# created, children first and then the parent they share.
finish_or_hold

bash "$RUN" fixture-check "$c" > "$R/fixture-check.log" 2>&1 && log "fixture-check OK" || log "fixture-check FAILED (non-fatal): $(tail -1 "$R/fixture-check.log")"
DUMP_LOGS_OK=1
bash "$RUN" dump-logs "$c" "$R/gtb-raw" 2>&1 | tee -a "$LOG" || { log "dump-logs FAILED (non-fatal after window open; workload timing will read as not_measured)"; DUMP_LOGS_OK=0; }
mv "$R/gtb-raw/$c.usage.jsonl" "$R/gtb-raw/usage.jsonl" 2>/dev/null
mv "$R/gtb-raw/$c.occurrences.jsonl" "$R/gtb-raw/occurrences.jsonl" 2>/dev/null
mv "$R/gtb-raw/$c.operations.jsonl" "$R/gtb-raw/operations.jsonl" 2>/dev/null
mv "$R/gtb-raw/$c.runtime-modules.jsonl" "$R/gtb-raw/runtime-modules.jsonl" 2>/dev/null
[ -s "$R/gtb-raw/usage.jsonl" ] || { log "usage.jsonl missing or empty for case $c (non-fatal after window open)"; DUMP_LOGS_OK=0; }
[ -s "$R/gtb-raw/occurrences.jsonl" ] || { log "occurrences.jsonl missing or empty for case $c (non-fatal after window open)"; DUMP_LOGS_OK=0; }
[ -s "$R/gtb-raw/operations.jsonl" ] || { log "operations.jsonl missing or empty for case $c (non-fatal after window open)"; DUMP_LOGS_OK=0; }
[ -s "$R/gtb-raw/runtime-modules.jsonl" ] || { log "runtime-modules.jsonl missing or empty for case $c (non-fatal after window open)"; DUMP_LOGS_OK=0; }
docker logs "$CONTAINER" > "$R/container.log" 2>&1; docker top "$CONTAINER" -eo pid,ppid,user,args > "$R/gtb-raw/docker-top.txt" 2>&1
bash "$RUN" down "$c" >/dev/null 2>&1

# The tracer's own real stop time comes from supervise's own record - never from whatever
# wall-clock instant this script happens to reach after dump-logs/down finish. It is given
# to the converter as -stopped-at against the PLANNED window end, which is what makes an
# early stop show up as stopped_early with the gap to the end it never reached; a converter
# given the instant the window was actually closed instead would see every run, early or
# not, as having run to its end. A tracer whose own termination was never confirmed reports
# no exit time at all, and that absence is carried through rather than filled in.
TRACER_EXITED_AT=""
if [ "$RUN_TRACER" = 1 ] && [ -s "$TRACER_RECORD" ]; then
  TRACER_EXITED_AT="$(python3 -c "import json;print(json.load(open('$TRACER_RECORD')).get('exited_at_wall') or '')" 2>/dev/null)"
fi

EVENTS_JSONL=""
if [ "$RUN_TRACER" = 1 ] && [ -s "$R/trace.txt" ]; then
  log "## 9 convert (planned window $WINDOW_START..$WINDOW_END_PLANNED, tracer exit ${TRACER_EXITED_AT:-not recorded})"
  ATTACHED_FLAG=""; [ "$ATTACHED_OK" = 1 ] && ATTACHED_FLAG="-attached"
  STOPPED_AT_FLAG=(); [ -n "$TRACER_EXITED_AT" ] && STOPPED_AT_FLAG=(-stopped-at "$TRACER_EXITED_AT")
  cat "$R/trace.txt" "$R/trace.err" | "$E" convert -in - -cgroup-map "$R/cgroup-map.json" -config-id "$CFG_EVENTS" -script-version 3 -variant "$VARIANT" -sync attach_running $ATTACHED_FLAG \
    -buffer-pages 512 -path-buffer 256 -boot-epoch "$BOOT" -clock-error-ns "$CERR" "${STOPPED_AT_FLAG[@]}" -stop-reason "$STOP_REASON" \
    -window-start "$WINDOW_START" -window-end "$WINDOW_END_PLANNED" -out "$R/events.jsonl" 2>&1 | tee -a "$LOG" \
    || log "convert FAILED (non-fatal): events will read as not_measured"
  [ -s "$R/events.jsonl" ] && EVENTS_JSONL="$R/events.jsonl"
fi

log "## 10 load.json"
OBS=""
[ "$RUN_COLLECTOR" = 1 ] && OBS=$(ls "$R"/collect/*__*.json 2>/dev/null | head -1)
export KLR_R="$R" KLR_RUN_ID="$RUNID" KLR_CASE="$c" KLR_CONFIG="$CONFIG" KLR_INTERVAL="$IV" KLR_WINDOW="$WIN" KLR_REPLICATE="$REP"
export KLR_HEALTH_URL="$HEALTH_URL" KLR_FIRED_AT="$FIRED_AT" KLR_WINDOW_START="$WINDOW_START" KLR_WINDOW_END="$WINDOW_END"
export KLR_WINDOW_END_PLANNED="$WINDOW_END_PLANNED" KLR_TRACER_EXITED_AT="$TRACER_EXITED_AT"
export KLR_WINDOW_ESTABLISHED="$WINDOW_ESTABLISHED" KLR_WINDOW_START_DRIFT_S="$WINDOW_START_DRIFT_S"
export KLR_WINDOW_START_TOLERANCE_S="$WINDOW_START_TOLERANCE_S"
export KLR_RUN_COLLECTOR="$RUN_COLLECTOR" KLR_RUN_TRACER="$RUN_TRACER" KLR_ATTACHED_OK="$ATTACHED_OK"
export KLR_STOPPED_EARLY="$STOPPED_EARLY" KLR_STOP_REASON="$STOP_REASON" KLR_DUMP_LOGS_OK="$DUMP_LOGS_OK"
export KLR_TRACER_RECORD="$TRACER_RECORD" KLR_COLLECTOR_RECORD="$COLLECTOR_RECORD"
export KLR_TRACER_CGROUP="$TRACER_CGROUP" KLR_COLLECTOR_CGROUP="$COLLECTOR_CGROUP"
export KLR_CGROUP_TRACER_WSTART="$R/cgroup-tracer-wstart.json" KLR_CGROUP_TRACER_WEND="$R/cgroup-tracer-wend.json"
export KLR_CGROUP_COLLECTOR_WSTART="$R/cgroup-collector-wstart.json" KLR_CGROUP_COLLECTOR_WEND="$R/cgroup-collector-wend.json"
export KLR_CGROUP_DOCKER_WSTART="$R/cgroup-docker-wstart.json" KLR_CGROUP_DOCKER_WEND="$R/cgroup-docker-wend.json"
export KLR_TRACE_STDOUT_WSTART="$R/trace-stdout-wstart-bytes.txt" KLR_TRACE_STDOUT_WEND="$R/trace-stdout-wend-bytes.txt"
export KLR_TRACE_STDERR_WSTART="$R/trace-stderr-wstart-bytes.txt" KLR_TRACE_STDERR_WEND="$R/trace-stderr-wend-bytes.txt"
export KLR_OBS="$OBS" KLR_EVENTS_JSONL="$EVENTS_JSONL"
export KLR_CONTAINER_ID_FILE="$R/container_id.txt" KLR_IMAGE_ID_FILE="$R/image_id.txt"
export KLR_STOP_FAILURES_FILE="$STOP_FAILURES"
python3 "$T/load_run_assemble.py" | tee -a "$LOG"

log "## done: $R (stopped_early=$STOPPED_EARLY reason=$STOP_REASON window_established=$WINDOW_ESTABLISHED)"
if [ "$TERMINATION_OK" != 1 ]; then
  log "## FAILED: this run could not confirm that everything it started has stopped. Nothing was torn down; see $STOP_FAILURES and the supervise records in $R."
  exit 1
fi
