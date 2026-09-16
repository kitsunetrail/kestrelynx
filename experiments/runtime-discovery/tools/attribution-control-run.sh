#!/usr/bin/env bash
# What: runs the attribution-control measurement (cases 23/24): confirms that observed
# occurrences are attributed to the right container (or correctly left/flagged unattributed)
# under four conditions.
# Usage (from the repository root):
#   sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh <condition> [replicate] [pages]
#   condition = a (case 23 alone) | b (case 24 alone) | ab (both at once) |
#               host (case 23 running while the host runs the same program)
#   pages = 256 (default) | 512
# The fourth condition keeps case 23 under observation so that a host run attributed to it can be detected;
# with no container observed, nothing could be attributed wrongly in the first place.
# Prerequisites: run as root, bpftrace installed, the native Docker Engine daemon (not Docker
# Desktop) reachable at /var/run/docker.sock, /usr/bin/curl on the host (condition "host" only),
# and the runtime-discovery/runtime-events binaries built into experiments/runtime-discovery/out/.
set -uo pipefail
cd "${KL_ROOT:-$(dirname "$0")/../../..}"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock
OWNER="${SUDO_USER:-$(id -un)}"
O=experiments/runtime-discovery/out; T=experiments/runtime-discovery/tools; B=$O/runtime-discovery; E=$O/runtime-events
RUN=experiments/runtime-discovery/cases/run.sh; CASES=experiments/runtime-discovery/cases
USAGE="Usage: sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh <23|24|23+24|23+host> [replicate] [256|512]"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
COND="$1"; REP="${2:-1}"; PAGES="${3:-256}"; IV=30; WIN=300
# CS holds the bare case numbers run.sh's up/down/fire/fixture-check/dump-logs
# take; "case$c" is the actual Docker container name for each.
case "$COND" in 23) CS="23";; 24) CS="24";; 23+24) CS="23 24";; 23+host) CS="23";; *) echo "condition must be 23, 24, 23+24 or 23+host" >&2; exit 2;; esac
case "$PAGES" in 256) BT=experiments/runtime-events/bpftrace/runtime-events-nofilter-256p.bt; VARIANT=nofilter-256p; CFG=bpftrace-v2-nofilter-256p; TAG=nofilter256p;; 512) BT=experiments/runtime-events/bpftrace/runtime-events-nofilter-512p.bt; VARIANT=nofilter-512p; CFG=bpftrace-v2-nofilter-512p; TAG=nofilter512p;; *) echo "pages must be 256 or 512" >&2; exit 2;; esac
V="$COND"
R=$O/$V-root-$IV-$WIN-p0-r$REP-startup-$TAG
rm -rf "$R"; mkdir -p "$R/collect" "$R/gtb-raw"; LOG=$R/run.log
log(){ echo "$(date -u +%FT%T.%NZ) $*" | tee -a "$LOG"; }
TP=""; CP=""; HP=""
cleanup(){ [ -n "$TP" ] && kill -INT "$TP" 2>/dev/null; [ -n "$CP" ] && kill "$CP" 2>/dev/null; [ -n "$HP" ] && kill "$HP" 2>/dev/null; for c in case23 case24; do docker rm -f "$c" >/dev/null 2>&1; done; chown -R "$OWNER":"$OWNER" "$R" 2>/dev/null; }
fail(){ log "FAILED: $*"; cleanup; exit 1; }
trap 'cleanup' EXIT
log "## attribution control condition $COND (cases: $CS) replicate $REP pages $PAGES config $CFG -> $R"
command -v bpftrace >/dev/null || fail "bpftrace not installed"
DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null); case "$DAEMON" in "") fail "docker daemon unreachable";; *Desktop*) fail "docker socket belongs to Docker Desktop ($DAEMON); the measurement needs the native daemon";; esac

[ "$COND" != 23+host ] || [ -x /usr/bin/curl ] || fail "/usr/bin/curl is not on the host"
# The shared attribution-control definition (23.json and 24.json are the
# same content with a different case_id); gtb.json is one file combining
# both containers' logs, so either works as the label here.
cp "$CASES/23.json" "$R/case.json"
# Intel (KEV/EPSS) enrichment: reuse a saved snapshot when KL_INTEL_SNAPSHOT names one
# (for reproducing an earlier classification), otherwise look up live through a local
# cache and save what this run used, so a later run can reproduce it.
if [ -n "${KL_INTEL_SNAPSHOT:-}" ]; then INTEL_ARGS=(-intel-snapshot "$KL_INTEL_SNAPSHOT")
else INTEL_ARGS=(-intel-cache experiments/runtime-discovery/out/intel-cache -out-intel-snapshot "$R/intel.json"); fi

log "## 1 clock and cgroup table"
"$E" clock -out "$R/clock.json" || fail clock
"$E" cgroup-map -root /sys/fs/cgroup -out "$R/cgroup-map.json" || fail cgroup-map
BOOT=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['boot_epoch'])"); CERR=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['error_ns'])")

log "## 2 tracer"
env -u BPFTRACE_MAX_STRLEN -u BPFTRACE_PERF_RB_PAGES -u BPFTRACE_ON_STACK_LIMIT bpftrace "$BT" > "$R/trace.txt" 2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$l"; done > "$R/trace.err") &
TP=$!; sleep 3
ATTACHED=""; if bash "$RUN" attach-check "$R/trace.txt" 30 2>&1 | tee -a "$LOG"; then ATTACHED="-attached"; else log "attach check failed (recorded as not attached)"; fi

log "## 3 collector with the targets pre-registered"
COLLECT_START=$(date -u +%FT%TZ); EXPECT=$(for c in $CS; do echo -n "case$c,"; done | sed 's/,$//')
"$B" collect -socket /var/run/docker.sock -expect "$EXPECT" -expect-timeout 300 -ready-file "$R/collect/ready.json" -case-variant "$V" -permission root -sync startup -config-id "$CFG" \
  -interval $IV -window $WIN -phase 0 -replicate "$REP" -out-dir "$R/collect" > "$R/collect.log" 2>&1 &
CP=$!; sleep 2

log "## 4 containers up, cgroup refresh, wait ready"
for c in $CS; do bash "$RUN" up "$c" > "$R/up-case$c.log" 2>&1 || fail "up case$c: $(tail -2 "$R/up-case$c.log")"; docker inspect -f '{{.Id}}' "case$c" > "$R/container_id-case$c.txt"; done
docker inspect -f '{{.Image}}' "case${CS%% *}" > "$R/image_id.txt"
bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"
RID=$(bash "$RUN" ready-run-id "$R/collect/ready.json" 120 "$COLLECT_START" 2>>"$LOG") || fail "ready-run-id: $(tail -2 "$LOG")"
bash "$RUN" wait-ready "$R/collect/ready.json" "$RID" 300 2>&1 | tee -a "$LOG" || fail "wait-ready"

log "## 5 fire"
for c in $CS; do bash "$RUN" fire "$c" 2>&1 | tee -a "$LOG"; done
if [ "$COND" = 23+host ]; then
  log "host control: /usr/bin/curl every 5 s for 50 iterations, outside any container"
  bash "$RUN" host-run "$R/gtb-raw/host.occurrences.jsonl" 50 5 > "$R/host-run.log" 2>&1 &
  HP=$!
fi

log "## 6 window ($WIN s)"
wait "$CP"; CRC=$?; CP=""; log "collector exit $CRC"
OBS_LIST=$(ls "$R"/collect/*__*.json 2>/dev/null); [ -n "$OBS_LIST" ] || fail "no observation record"
OBS1=$(echo "$OBS_LIST" | head -1)
WSTART=$(python3 -c "import json;print(json.load(open('$OBS1'))['window']['scheduled_start'])"); WEND=$(python3 -c "import json;print(json.load(open('$OBS1'))['window']['scheduled_end'])")
SLEEP=$(python3 -c "
from datetime import datetime,timezone,timedelta
s='$WEND'.replace('Z','+00:00')
if '.' in s:
    head,rest=s.split('.',1); frac=rest[:6]; tz=rest.lstrip('0123456789'); s=f'{head}.{frac:0<6}{tz}'
end=datetime.fromisoformat(s)+timedelta(seconds=30); print(max(0,int((end-datetime.now(timezone.utc)).total_seconds())+1))")
log "window $WSTART .. $WEND; sleeping $SLEEP s"; sleep "$SLEEP"
[ -z "$HP" ] || { wait "$HP" 2>/dev/null; HP=""; log "host control finished: $(wc -l < "$R/gtb-raw/host.occurrences.jsonl") runs"; }

log "## 7 stop tracer, copy logs, tear down"
kill -INT "$TP"; wait "$TP" 2>/dev/null; TRC=$?; STOP=$(date -u +%FT%T.%NZ); TP=""; sleep 1; log "tracer stopped rc=$TRC at $STOP"
bash "$RUN" register-cgroups "$R/cgroup-map.json" "$E" 2>&1 | tee -a "$LOG"
for c in $CS; do bash "$RUN" fixture-check "$c" >> "$R/fixture-check.log" 2>&1 && log "fixture-check case$c OK" || log "fixture-check case$c FAILED"; bash "$RUN" dump-logs "$c" "$R/gtb-raw" 2>&1 | tee -a "$LOG" || fail "dump-logs case$c"; docker logs "case$c" > "$R/container-case$c.log" 2>&1; done
for c in case23 case24; do docker rm -f "$c" >/dev/null 2>&1; done
# one combined ground truth: every container's own log, plus the host control's occurrences
cat $(for c in $CS; do echo "$R/gtb-raw/$c.usage.jsonl"; done) > "$R/gtb-raw/usage.jsonl"
cat $(for c in $CS; do echo "$R/gtb-raw/$c.occurrences.jsonl"; done) $( [ -s "$R/gtb-raw/host.occurrences.jsonl" ] && echo "$R/gtb-raw/host.occurrences.jsonl" ) > "$R/gtb-raw/occurrences.jsonl"
log "occurrences: $(wc -l < "$R/gtb-raw/occurrences.jsonl") (host: $( [ -s "$R/gtb-raw/host.occurrences.jsonl" ] && wc -l < "$R/gtb-raw/host.occurrences.jsonl" || echo 0 ))"
grep "^@" "$R/trace.txt" | tee -a "$LOG"; cut -d" " -f2- "$R/trace.err" | sort | uniq -c | sort -rn | head -3 | tee -a "$LOG"

log "## 8 scan (same image as case 13; reuse when the image id matches)"
IID=$(cat "$R/image_id.txt"); export DOCKER_CONFIG=$(mktemp -d); chmod 755 "$DOCKER_CONFIG"
if command -v trivy >/dev/null 2>&1; then TRIVY=trivy
elif [ -x "$HOME/.local/bin/trivy" ]; then TRIVY="$HOME/.local/bin/trivy"
else TRIVY="/home/$OWNER/.local/bin/trivy"; fi
if [ "$(cat $O/scans/13.image_id.txt 2>/dev/null)" = "$IID" ]; then cp $O/scans/13.trivy_all.json "$R/trivy_all.json"; cp $O/scans/13.trivy_hc.json "$R/trivy_hc.json"; log "scan reused from case 13"
else
  runuser -u "$OWNER" -- "$TRIVY" image --format json --scanners vuln -o "$R/trivy_all.json" "$IID" > "$R/scan.log" 2>&1 || fail "trivy all: $(tail -1 "$R/scan.log")"
  runuser -u "$OWNER" -- "$TRIVY" image --format json --scanners vuln --severity HIGH,CRITICAL -o "$R/trivy_hc.json" "$IID" >> "$R/scan.log" 2>&1 || fail "trivy hc: $(tail -1 "$R/scan.log")"
fi

log "## 9 convert"
cat "$R/trace.txt" "$R/trace.err" | "$E" convert -in - -cgroup-map "$R/cgroup-map.json" -config-id "$CFG" -script-version 3 -variant "$VARIANT" -sync startup $ATTACHED \
  -buffer-pages "$PAGES" -path-buffer 256 -boot-epoch "$BOOT" -clock-error-ns "$CERR" -stopped-at "$STOP" -window-start "$WSTART" -window-end "$WEND" -out "$R/events.jsonl" 2>&1 | tee -a "$LOG"
python3 - "$R" <<'PY' | tee -a "$LOG"
import json,sys,collections,glob
R=sys.argv[1]; ev=[json.loads(l) for l in open(f'{R}/events.jsonl') if l.strip()]; recs=[e for e in ev if e.get('record')=='event']
ids={open(f).read().strip():f.split('container_id-')[1][:-4] for f in glob.glob(f'{R}/container_id-*.txt')}
print('exec curl/git by attributed container:', {ids.get(k,k[:12] if k else 'none'):v for k,v in collections.Counter(e.get('container_id','') for e in recs if e['event']=='exec' and (e.get('path') or '').endswith(('/curl','/git'))).items()})
tr=[e for e in ev if e.get('record')=='events_trailer']; d=tr[0]['drops'] if tr else {}; print('drops', {k:d.get(k) for k in ('lost_events','enter_exit_unmatched','enter_exit_unmatched_boundary','map_overflow','unmeasured')})
PY

log "## 10 GT-B and match (one match per observed container, against the combined ground truth)"
python3 "$T/gtb_case.py" "$R" kl-case13 2>&1 | tee -a "$LOG"
for OBS in $OBS_LIST; do
  c=$(basename "$OBS" | cut -d_ -f1); mkdir -p "$R/csv_hc-$c"
  "$B" match -observation "$OBS" -trivy "$R/trivy_hc.json" -case "$R/case.json" -gtb "$R/gtb.json" -events "$R/events.jsonl" "${INTEL_ARGS[@]}" -out-json "$R/match_hc-$c.json" -out-csv-dir "$R/csv_hc-$c" 2>&1 | tail -1 | tee -a "$LOG"
  python3 - "$R" "$c" <<'PY' | tee -a "$LOG"
import json,sys
R,c=sys.argv[1],sys.argv[2]; m=json.load(open(f'{R}/match_hc-{c}.json'))
print(f'[{c}] capture exec', m['occurrence_capture']['exec'], '| excluded', m['occurrence_capture'].get('excluded'))
print(f'[{c}] attribution', {k:m['attribution'].get(k) for k in ('match_rule','cross_container_evaluable','attributed_events','misattributed','misattribution_rate','logged_occurrences','correctly_attributed','correct_attribution_rate','from_other_container','from_host','excluded')})
PY
done
log "## done: $R"
