#!/usr/bin/env bash
# What: runs several case-run.sh/attribution-control-run.sh measurements back to back from a plan file.
# Usage: sudo bash experiments/runtime-discovery/tools/case-batch.sh <plan file>
#   Each plan line: <case> <replicate> <sync> <pages> [interval] [window]  (interval and window default to 30 and
#   300 seconds, as in case-run.sh; case 23, 24, 23+24, 23+host route to attribution-control-run.sh instead, whose
#   third field is pages, not sync). See tools/plans/example.txt and tools/plans/coverage-main.txt.
# Prerequisites: same as case-run.sh and attribution-control-run.sh (run as root, bpftrace, the
# native Docker Engine daemon, and the runtime-discovery/runtime-events binaries built).
set -uo pipefail
cd "$(dirname "$0")/../../.."
USAGE="Usage: sudo bash experiments/runtime-discovery/tools/case-batch.sh <plan file>"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
PLAN="$1"; LOGF=experiments/runtime-discovery/out/case-batch-$(date -u +%Y%m%dT%H%M%SZ).log
# Run from a snapshot of the runner scripts: bash reads a script incrementally, so editing one while a run is in
# progress corrupts that run. Editing the originals during a batch is therefore safe for the batch.
export KL_ROOT="$PWD"; SNAP=$(mktemp -d); cp experiments/runtime-discovery/tools/case-run.sh experiments/runtime-discovery/tools/attribution-control-run.sh experiments/runtime-discovery/tools/gtb.py experiments/runtime-discovery/tools/gtb_case.py "$SNAP"/
while read -r c rep sync pages iv win; do
  [ -z "$c" ] && continue; case "$c" in \#*) continue;; esac
  iv="${iv:-30}"; win="${win:-300}"
  echo "$(date -u +%FT%TZ) === $c $rep $sync $pages $iv $win" | tee -a "$LOGF"
  case "$c" in
    23|24|23+24|23+host) bash "$SNAP/attribution-control-run.sh" "$c" "$rep" "$pages" > /dev/null 2>&1; R=$(ls -td experiments/runtime-discovery/out/23*-root-*-r$rep-* 2>/dev/null | head -1);;
    *) bash "$SNAP/case-run.sh" "$c" "$rep" "$sync" "$pages" "$iv" "$win" > /dev/null 2>&1; R=$(ls -td experiments/runtime-discovery/out/$c-root-$iv-$win-p0-r$rep-$sync-* 2>/dev/null | head -1);;
  esac
  { grep -E "^.*(FAILED|## done|occurrence_capture|attribution|series:|drops|capture exec)" "$R/run.log" | tail -8; } | tee -a "$LOGF"
done < "$PLAN"
chown -R "${SUDO_USER:-$(id -un)}":"${SUDO_USER:-$(id -un)}" experiments/runtime-discovery/out
echo "$(date -u +%FT%TZ) === batch done: $LOGF" | tee -a "$LOGF"
