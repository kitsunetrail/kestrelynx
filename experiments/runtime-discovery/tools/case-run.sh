#!/usr/bin/env bash
# What: runs one measurement for cases 13-22 (case 23/24 use attribution-control-run.sh):
#   clock + cgroup table -> tracer -> attach check -> collector with the target pre-registered ->
#   container -> cgroup refresh -> wait ready -> fire -> window -> stop tracer -> logs out ->
#   tear down -> scan by image id -> convert -> GT-B -> match.
# Usage (from the repository root):
#   sudo bash experiments/runtime-discovery/tools/case-run.sh <case> [replicate] [sync] [pages]
#   case  = 13 14 15 16 17 18 19 20 21 22
#   sync  = startup (default: observe first, fire afterwards) | attach_running (fire first, observe a running workload)
#   pages = 64 (default) | 256 (event buffer pages) | none (no event collection: sampling and method A only)
# Prerequisites: run as root, bpftrace installed (unless pages=none), Docker Engine's native
# daemon (not Docker Desktop) reachable at /var/run/docker.sock, and the runtime-discovery and
# runtime-events binaries built into experiments/runtime-discovery/out/.
set -uo pipefail
cd "${KL_ROOT:-$(dirname "$0")/../../..}"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock
OWNER="${SUDO_USER:-$(id -un)}"
O=experiments/runtime-discovery/out; T=experiments/runtime-discovery/tools; B=$O/runtime-discovery; E=$O/runtime-events
RUN=experiments/runtime-discovery/cases/run.sh; CASES=experiments/runtime-discovery/cases
USAGE="Usage: sudo bash experiments/runtime-discovery/tools/case-run.sh <case> [replicate] [startup|attach_running] [64|256|512|none]"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
c="$1"; REP="${2:-1}"; SYNC="${3:-startup}"; PAGES="${4:-64}"; IV=30; WIN=300
case "$c" in 13|14|15|16|17|18|19|20|21|22) ;; *) echo "unsupported case $c" >&2; exit 2;; esac
case "$SYNC" in startup|attach_running) ;; *) echo "sync must be startup or attach_running" >&2; exit 2;; esac
# Case 16 (the no-cache condition) has no definition of its own: it shares
# case 15's, built with a different Dockerfile build-arg by run.sh.
CASEJSON=$CASES/$c.json; [ "$c" = 16 ] && CASEJSON=$CASES/15.json
V="$c"; CONTAINER="case$c"
case "$PAGES" in
  64)   BT=experiments/runtime-events/bpftrace/runtime-events-nofilter.bt; VARIANT=nofilter; CFG=bpftrace-v2-nofilter-64p; TAG=nofilter64p;;
  256)  BT=experiments/runtime-events/bpftrace/runtime-events-nofilter-256p.bt; VARIANT=nofilter-256p; CFG=bpftrace-v2-nofilter-256p; TAG=nofilter256p;;
  512)  BT=experiments/runtime-events/bpftrace/runtime-events-nofilter-512p.bt; VARIANT=nofilter-512p; CFG=bpftrace-v2-nofilter-512p; TAG=nofilter512p;;
  none) BT=""; VARIANT=""; CFG=none; TAG=noevents;;
  *) echo "pages must be 64, 256, 512 or none" >&2; exit 2;;
esac
R=$O/$V-root-$IV-$WIN-p0-r$REP-$SYNC-$TAG
rm -rf "$R"; mkdir -p "$R/collect" "$R/gtb-raw"; LOG=$R/run.log
log(){ echo "$(date -u +%FT%T.%NZ) $*" | tee -a "$LOG"; }
TP=""; CP=""
cleanup(){ [ -n "$TP" ] && kill -INT "$TP" 2>/dev/null; [ -n "$CP" ] && kill "$CP" 2>/dev/null; docker rm -f "$CONTAINER" >/dev/null 2>&1; chown -R "$OWNER":"$OWNER" "$R" 2>/dev/null; }
fail(){ log "FAILED: $*"; cleanup; exit 1; }
trap 'cleanup' EXIT
log "## case $c replicate $REP sync $SYNC pages $PAGES config $CFG -> $R"
DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null); case "$DAEMON" in "") fail "docker daemon unreachable";; *Desktop*) fail "docker socket belongs to Docker Desktop ($DAEMON); the measurement needs the native daemon";; esac
[ -z "$BT" ] || command -v bpftrace >/dev/null || fail "bpftrace not installed"
cp "$CASEJSON" "$R/case.json"
# Intel (KEV/EPSS) enrichment: reuse a saved snapshot when KL_INTEL_SNAPSHOT names one
# (for reproducing an earlier classification), otherwise look up live through a local
# cache and save what this run used, so a later run can reproduce it.
if [ -n "${KL_INTEL_SNAPSHOT:-}" ]; then INTEL_ARGS=(-intel-snapshot "$KL_INTEL_SNAPSHOT")
else INTEL_ARGS=(-intel-cache experiments/runtime-discovery/out/intel-cache -out-intel-snapshot "$R/intel.json"); fi

log "## 1 clock and cgroup table"
"$E" clock -out "$R/clock.json" || fail clock
"$E" cgroup-map -root /sys/fs/cgroup -out "$R/cgroup-map.json" || fail cgroup-map
BOOT=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['boot_epoch'])"); CERR=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['error_ns'])")
log "boot_epoch $BOOT error_ns $CERR"

ATTACHED=""
start_tracer(){
  [ -n "$BT" ] || return 0
  log "## tracer start ($BT)"
  env -u BPFTRACE_MAX_STRLEN -u BPFTRACE_PERF_RB_PAGES -u BPFTRACE_ON_STACK_LIMIT bpftrace "$BT" > "$R/trace.txt" 2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$l"; done > "$R/trace.err") &
  TP=$!; sleep 3
  if bash "$RUN" attach-check "$R/trace.txt" 30 2>&1 | tee -a "$LOG"; then ATTACHED="-attached"; else log "attach check failed (run continues, recorded as not attached)"; fi
}
up_case(){
  bash "$RUN" up "$c" > "$R/up.log" 2>&1 || fail "up: $(tail -2 "$R/up.log")"
  docker inspect -f '{{.Id}}' "$CONTAINER" > "$R/container_id.txt"; docker inspect -f '{{.Image}}' "$CONTAINER" > "$R/image_id.txt"
  log "container $(cut -c1-12 "$R/container_id.txt") image $(cat "$R/image_id.txt")"
}

if [ "$SYNC" = startup ]; then
  start_tracer
  log "## 2 collector with the target pre-registered"
  COLLECT_START=$(date -u +%FT%TZ)
  "$B" collect -socket /var/run/docker.sock -expect "$CONTAINER" -expect-timeout 300 -ready-file "$R/collect/ready.json" -case-variant "$V" -permission root -sync startup -config-id "$CFG" \
    -interval $IV -window $WIN -phase 0 -replicate "$REP" -out-dir "$R/collect" > "$R/collect.log" 2>&1 &
  CP=$!; sleep 2
  log "## 3 container up, cgroup refresh, wait ready"
  up_case
  [ -z "$BT" ] || bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"
  RID=$(bash "$RUN" ready-run-id "$R/collect/ready.json" 120 "$COLLECT_START" 2>>"$LOG") || fail "ready-run-id: $(tail -2 "$LOG")"
  bash "$RUN" wait-ready "$R/collect/ready.json" "$RID" 300 2>&1 | tee -a "$LOG" || fail "wait-ready"
  log "## 4 fire"
  FIRED_AT=$(date -u +%FT%T.%NZ); bash "$RUN" fire "$c" 2>&1 | tee -a "$LOG"; log "fired at $FIRED_AT"
else
  log "## 2 container up and fired first (attach_running)"
  up_case
  FIRED_AT=$(date -u +%FT%T.%NZ); bash "$RUN" fire "$c" 2>&1 | tee -a "$LOG"; log "fired at $FIRED_AT"; sleep 20
  start_tracer
  [ -z "$BT" ] || bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"
  log "## 3 collector joins the running workload"
  "$B" collect -socket /var/run/docker.sock -containers "$CONTAINER" -case-variant "$V" -permission root -sync attach_running -config-id "$CFG" \
    -interval $IV -window $WIN -phase 0 -replicate "$REP" -out-dir "$R/collect" > "$R/collect.log" 2>&1 &
  CP=$!
fi

log "## 5 window ($WIN s): waiting for the collector"
wait "$CP"; CRC=$?; CP=""; log "collector exit $CRC"; tail -2 "$R/collect.log" | tee -a "$LOG"
OBS=$(ls "$R"/collect/*__*.json 2>/dev/null | head -1); [ -n "$OBS" ] || fail "no observation record"
WSTART=$(python3 -c "import json;print(json.load(open('$OBS'))['window']['scheduled_start'])")
WEND=$(python3 -c "import json;print(json.load(open('$OBS'))['window']['scheduled_end'])")
SLEEP=$(python3 -c "
from datetime import datetime,timezone,timedelta
s='$WEND'.replace('Z','+00:00')
if '.' in s:
    head,rest=s.split('.',1); frac=rest[:6]; tz=rest.lstrip('0123456789'); s=f'{head}.{frac:0<6}{tz}'
end=datetime.fromisoformat(s)+timedelta(seconds=30); print(max(0,int((end-datetime.now(timezone.utc)).total_seconds())+1))")
log "window scheduled_end $WEND; sleeping $SLEEP s"; sleep "$SLEEP"

log "## 6 stop tracer, refresh cgroups, copy logs, tear down"
STOP=""
if [ -n "$TP" ]; then kill -INT "$TP"; wait "$TP" 2>/dev/null; TRC=$?; STOP=$(date -u +%FT%T.%NZ); TP=""; sleep 1; log "tracer stopped rc=$TRC at $STOP"; bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"; fi
bash "$RUN" fixture-check "$c" > "$R/fixture-check.log" 2>&1 && log "fixture-check OK" || log "fixture-check FAILED: $(tail -1 "$R/fixture-check.log")"
bash "$RUN" dump-logs "$c" "$R/gtb-raw" 2>&1 | tee -a "$LOG" || fail "dump-logs"
mv "$R/gtb-raw/$c.usage.jsonl" "$R/gtb-raw/usage.jsonl" 2>/dev/null; mv "$R/gtb-raw/$c.occurrences.jsonl" "$R/gtb-raw/occurrences.jsonl" 2>/dev/null
docker logs "$CONTAINER" > "$R/container.log" 2>&1; docker top "$CONTAINER" -eo pid,ppid,user,args > "$R/gtb-raw/docker-top.txt" 2>&1
bash "$RUN" down "$c" >/dev/null 2>&1
log "usage $(wc -l < "$R/gtb-raw/usage.jsonl") lines, occurrences $(wc -l < "$R/gtb-raw/occurrences.jsonl") lines"
if [ -n "$BT" ]; then log "trace lines $(wc -l < "$R/trace.txt")"; grep "^@" "$R/trace.txt" | tee -a "$LOG"; cut -d" " -f2- "$R/trace.err" | sort | uniq -c | sort -rn | head -3 | tee -a "$LOG"; fi

log "## 7 scan by image id (cached per image id)"
IID=$(cat "$R/image_id.txt"); SK=$(echo "$IID" | cut -c8-19)
if command -v trivy >/dev/null 2>&1; then TRIVY=trivy
elif [ -x "$HOME/.local/bin/trivy" ]; then TRIVY="$HOME/.local/bin/trivy"
else TRIVY="/home/$OWNER/.local/bin/trivy"; fi
mkdir -p $O/scans
# Trivy reads ~/.docker/config.json and fails on a credential helper this host does not have; point it at an empty config.
export DOCKER_CONFIG=$(mktemp -d); chmod 755 "$DOCKER_CONFIG"
if [ ! -s "$O/scans/$V.trivy_all.json" ] || [ "$(cat $O/scans/$V.image_id.txt 2>/dev/null)" != "$IID" ]; then
  runuser -u "$OWNER" -- "$TRIVY" image --format json --scanners vuln -o "$O/scans/$V.trivy_all.json" "$IID" > "$R/scan.log" 2>&1 || fail "trivy all: $(tail -1 "$R/scan.log")"
  runuser -u "$OWNER" -- "$TRIVY" image --format json --scanners vuln --severity HIGH,CRITICAL -o "$O/scans/$V.trivy_hc.json" "$IID" >> "$R/scan.log" 2>&1 || fail "trivy hc: $(tail -1 "$R/scan.log")"
  echo "$IID" > $O/scans/$V.image_id.txt
fi
cp $O/scans/$V.trivy_all.json "$R/trivy_all.json"; cp $O/scans/$V.trivy_hc.json "$R/trivy_hc.json"
log "scan: $(python3 -c "import json;d=json.load(open('$R/trivy_hc.json'));print(sum(len(r.get('Vulnerabilities',[])) for r in d['Results']),'HC findings;', [ (r['Type'],len(r.get('Vulnerabilities',[]))) for r in d['Results']])")"

EVENTS=""
if [ -n "$BT" ]; then
  log "## 8 convert"
  cat "$R/trace.txt" "$R/trace.err" | "$E" convert -in - -cgroup-map "$R/cgroup-map.json" -config-id "$CFG" -script-version 3 -variant "$VARIANT" -sync "$SYNC" $ATTACHED \
    -buffer-pages "$PAGES" -path-buffer 256 -boot-epoch "$BOOT" -clock-error-ns "$CERR" -stopped-at "$STOP" -window-start "$WSTART" -window-end "$WEND" -out "$R/events.jsonl" 2>&1 | tee -a "$LOG"
  EVENTS="-events $R/events.jsonl"
  python3 - "$R" <<'PY' | tee -a "$LOG"
import json,sys,collections
R=sys.argv[1]; ev=[json.loads(l) for l in open(f'{R}/events.jsonl') if l.strip()]
recs=[e for e in ev if e.get('record')=='event']; cid=open(f'{R}/container_id.txt').read().strip()
mine=[e for e in recs if e.get('container_id')==cid]
print('events', len(recs), dict(collections.Counter(e['event'] for e in recs)), '| this container:', len(mine), dict(collections.Counter(e['event'] for e in mine)))
print('exec paths in this container:', dict(collections.Counter(e.get('path') for e in mine if e['event']=='exec').most_common(8)))
print('open paths in this container (top 8):', collections.Counter(e.get('path') for e in mine if e['event']=='open').most_common(8))
tr=[e for e in ev if e.get('record')=='events_trailer']; print('drops', {k:v for k,v in (tr[0]['drops'].items() if tr else []) if k!='unmeasured'})
PY
fi

log "## 9 GT-B and match"
IMG=$(python3 -c "import json;print(json.load(open('$R/case.json'))['image'])"); [ "$c" = 16 ] && IMG=kl-case16
python3 "$T/gtb_case.py" "$R" "$IMG" 2>&1 | tee -a "$LOG"
mkdir -p "$R/csv_hc" "$R/csv_all"
"$B" match -observation "$OBS" -trivy "$R/trivy_hc.json" -case "$R/case.json" -gtb "$R/gtb.json" $EVENTS "${INTEL_ARGS[@]}" -out-json "$R/match_hc.json" -out-csv-dir "$R/csv_hc" 2>&1 | tail -3 | tee -a "$LOG"
"$B" match -observation "$OBS" -trivy "$R/trivy_all.json" -case "$R/case.json" -gtb "$R/gtb.json" $EVENTS "${INTEL_ARGS[@]}" -out-json "$R/match_all.json" -out-csv-dir "$R/csv_all" 2>&1 | tail -3 | tee -a "$LOG"
python3 - "$R" <<'PY' | tee -a "$LOG"
import csv,json,sys
R=sys.argv[1]; m=json.load(open(f'{R}/match_hc.json'))
r=m.get('occurrence_capture',{}); a=m.get('attribution',{})
print('occurrence_capture: rule', r.get('match_rule'), '| exec', r.get('exec'), '| load', r.get('load'), '| excluded', r.get('excluded'), '| uncaptured', r.get('uncaptured'))
print('attribution:', json.dumps(a, default=str)[:700])
# The series table's own JSON keeps target_finding, confirmed and the two
# rates nested under each series' "overall" object, not on the series
# itself, and keeps neither event_state nor collection_complete there at
# all — so reading them off the top-level series entries the way this once
# did comes back None every time. The CSV row is already flattened to the
# columns wanted here, so it is read from there instead.
fields=('series','confirmed','target_finding','confirmed_pkg','target_pkg',
        'event_state','collection_complete','unconditional_rate','conditional_rate')
with open(f'{R}/csv_hc/series.csv', newline='') as f:
    for row in csv.DictReader(f):
        if row.get('classification') in ('overall','delta'):
            print('series:', {k:row.get(k) for k in fields})
print('series_deltas:', json.dumps(m.get('series_deltas'), default=str)[:400])
PY
tail -2 "$R/csv_hc/series.csv" | tee -a "$LOG"
python3 experiments/runtime-discovery/tools/record.py "$R" > /dev/null 2>&1 && log "record.md written" || log "record.md not written"
log "## done: $R"
