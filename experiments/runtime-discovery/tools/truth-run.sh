#!/usr/bin/env bash
# What: obtains independent ground truth for one coverage-validation case
# (26, 27, or 28) by running the exact same image as an ordinary
# measurement run, under strace instead of plainly, from a freshly
# created container through the same up -> fire -> window -> stop
# sequence tools/case-run.sh uses.
#
# Usage (from the repository root):
#   bash experiments/runtime-discovery/tools/truth-run.sh <case> [replicate] [window seconds]
#   case      = 26 | 27 | 28
#   replicate = 1 (default)
#   window    = 900 (default) - the longest planned observation window, so
#               one truth run's log is a superset covering every shorter
#               window a measurement run of the same image might use
#
# This is a dedicated run, never reused as a measurement run: strace
# changes timing and scheduling, which is why it is kept out of the runs
# tools/case-run.sh produces (see the case definitions' own fixture_notes).
# The container it starts is created fresh and removed at the end; nothing
# here restarts or reuses a container from an earlier run, so the write
# layer a measurement run being compared against this one sees starts
# empty every time.
#
# Output: experiments/runtime-discovery/out/<case>-truth-r<replicate>/,
# containing:
#   image_id.txt, container_id.txt      - identity, for comparison against
#                                          a measurement run of the same case
#   ready_at.txt, fired_at.txt, stopped_at.txt - the firing procedure's own
#                                        timing (ready_at and fired_at are
#                                        the same instant here: see "wait
#                                        for readiness and fire" below)
#   varlog/                             - a copy of the container's whole
#                                          /var/log, taken after a graceful
#                                          stop (so any exit-time dump a
#                                          program writes on SIGTERM is
#                                          included): usage.jsonl,
#                                          occurrences.jsonl,
#                                          operations.jsonl,
#                                          runtime-modules.jsonl, and (under
#                                          strace) strace/trace.<pid> per
#                                          traced process
#   run.log                             - this script's own log
#
# The copy is taken with `docker cp` rather than through host procfs: it
# needs no root, and it works on a container that has already been
# stopped (its writable layer is retained until removal), which a
# procfs-based read cannot do once the container's PID is gone.
set -uo pipefail
cd "${KL_ROOT:-$(dirname "$0")/../../..}"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock

O=experiments/runtime-discovery/out
RUN=experiments/runtime-discovery/cases/run.sh
USAGE="Usage: bash experiments/runtime-discovery/tools/truth-run.sh <case> [replicate] [window seconds]"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
c="$1"; REP="${2:-1}"; WINDOW="${3:-900}"
case "$c" in 26 | 27 | 28) ;; *) echo "unsupported case $c (truth-run.sh covers the coverage-validation cases only)" >&2; exit 2;; esac
CONTAINER="case$c"

R="$O/$c-truth-r$REP"
rm -rf "$R"; mkdir -p "$R"
LOG="$R/run.log"
log() { echo "$(date -u +%FT%T.%NZ) $*" | tee -a "$LOG"; }

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1; }
fail() { log "FAILED: $*"; cleanup; exit 1; }
trap 'cleanup' EXIT

log "## truth run: case $c replicate $REP window ${WINDOW}s -> $R"
DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)
case "$DAEMON" in "") fail "docker daemon unreachable";; *Desktop*) fail "docker socket belongs to Docker Desktop ($DAEMON); the measurement needs the native daemon";; esac

# A fresh container every time: reusing one across runs would carry over
# whatever an earlier run's operational loop or lazy loads already did,
# which is exactly the write-layer state the added identity rule requires
# starting clean.
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

log "## 1 build and start under TRACE_MODE=1 (same image the case defines)"
KL_TRACE_MODE=1 bash "$RUN" up "$c" >"$R/up.log" 2>&1 || fail "up: $(tail -2 "$R/up.log")"
docker inspect -f '{{.Id}}' "$CONTAINER" >"$R/container_id.txt"
docker inspect -f '{{.Image}}' "$CONTAINER" >"$R/image_id.txt"
log "container $(cut -c1-12 "$R/container_id.txt") image $(cat "$R/image_id.txt")"

log "## 2 wait for readiness and fire"
# A fixed short sleep here is not enough: under strace, the workload's own
# startup (importing its language runtime's whole startup-group package
# set, in the coverage-validation cases) can take far longer than it does
# plainly, and firing before the workload has reached its own blocking
# read of the signalling pipe would either race it or simply block this
# script until it gets there anyway, with nothing recorded about how long
# that took. fire-when-ready retries the real signal, bounded by 900
# seconds total, until the workload is actually ready to receive it — the
# moment that succeeds is both this run's readiness and its firing, so the
# two are recorded together.
bash "$RUN" fire-when-ready "$c" 900 2>&1 | tee -a "$LOG" || fail "fire-when-ready"
FIRED_AT="$(date -u +%FT%T.%NZ)"
echo "$FIRED_AT" >"$R/ready_at.txt"
echo "$FIRED_AT" >"$R/fired_at.txt"
log "ready and fired at $FIRED_AT"

log "## 3 window (${WINDOW}s): the operational loop and any lazy triggers run on their own schedule"
sleep "$WINDOW"

log "## 4 graceful stop (lets an exit-time runtime-modules dump run) and copy /var/log"
STOPPED_AT="$(date -u +%FT%T.%NZ)"
docker stop -t 20 "$CONTAINER" >/dev/null 2>&1 || log "docker stop reported a non-zero exit; continuing to copy what exists"
echo "$STOPPED_AT" >"$R/stopped_at.txt"
mkdir -p "$R/varlog"
docker cp "$CONTAINER:/var/log/." "$R/varlog" 2>&1 | tee -a "$LOG" || fail "docker cp"
docker rm -f "$CONTAINER" >/dev/null 2>&1

log "## done: $R"
for f in usage.jsonl occurrences.jsonl operations.jsonl runtime-modules.jsonl; do
	n="$(wc -l <"$R/varlog/$f" 2>/dev/null || echo 0)"
	log "varlog/$f: $n line(s)"
done
n="$(find "$R/varlog/strace" -type f 2>/dev/null | wc -l)"
log "varlog/strace: $n trace file(s)"
