#!/usr/bin/env bash
# What: dry-run-parses every bpftrace script, then attaches the nofilter one, causes known
# events in a container that stays alive while the cgroup table is refreshed, and runs the
# converter, to confirm end-to-end tracing works before a real measurement.
# Usage (from the repository root): sudo bash experiments/runtime-discovery/tools/check-tracing.sh
# Prerequisites: run as root, bpftrace (and bpftool) installed, and the native Docker Engine
# daemon (not Docker Desktop) reachable at /var/run/docker.sock.
set -uo pipefail
cd "$(dirname "$0")/../../.."
OWNER="${SUDO_USER:-$(id -un)}"
O=experiments/runtime-discovery/out; E=experiments/runtime-events; B=$O/runtime-events; S=$O/check-tracing
rm -rf "$S"; mkdir -p "$S"; log(){ echo "$(date -u +%FT%TZ) $*" | tee -a "$S/smoke.log"; }
log "## versions"
DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null); case "$DAEMON" in "") echo "docker daemon unreachable" >&2; exit 2;; *Desktop*) echo "docker socket belongs to Docker Desktop ($DAEMON); the check needs the native daemon" >&2; exit 2;; esac
if ! command -v bpftrace >/dev/null; then log "bpftrace is not installed. Install it first: sudo apt-get install -y bpftrace bpftool"; exit 2; fi
bpftrace --version 2>&1 | tee -a "$S/smoke.log"; bpftool version 2>&1 | head -1 | tee -a "$S/smoke.log"
log "## parse and load check (dry run) of every script"
for f in "$E"/bpftrace/*.bt; do n=$(basename "$f")
  if env -u BPFTRACE_MAX_STRLEN -u BPFTRACE_PERF_RB_PAGES -u BPFTRACE_ON_STACK_LIMIT bpftrace -v --dry-run "$f" > "$S/$n.dryrun.out" 2>&1; then log "$n: dry-run OK"; else log "$n: DRY_RUN_FAILED: $(grep -m1 -i "error" "$S/$n.dryrun.out")"; fi
done
log "## clock + cgroup table"
"$B" clock -out "$S/clock.json" && python3 -c "import json;d=json.load(open('$S/clock.json'));print('boot_epoch',d['boot_epoch'],'error_ns',d['error_ns'])" | tee -a "$S/smoke.log"
"$B" cgroup-map -root /sys/fs/cgroup -out "$S/cgroup-map.json" && log "cgroup entries: $(python3 -c "import json;print(len(json.load(open('$S/cgroup-map.json'))['entries']))")"
log "## start the container first (it stays alive while the tracer runs)"
docker rm -f s2smoke >/dev/null 2>&1; docker run -d --name s2smoke alpine:3.20 sleep 120 > /dev/null && log "container started: $(docker inspect -f '{{.Id}}' s2smoke | cut -c1-12)"
"$B" cgroup-map -root /sys/fs/cgroup -merge "$S/cgroup-map.json" -out "$S/cgroup-map.json" && log "cgroup table refreshed with the container present: docker scopes = $(python3 -c "import json;print(sum(1 for e in json.load(open('$S/cgroup-map.json'))['entries'] if 'docker-' in e['path']))")"
log "## start tracer (nofilter) for a short window"
START=$(date -u +%FT%T.%NZ)
bpftrace "$E/bpftrace/runtime-events-nofilter.bt" > "$S/trace.txt" 2> >(while IFS= read -r l; do printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$l"; done > "$S/trace.err") &
TP=$!; sleep 3
log "## attach check"
ATTACHED=""; if bash experiments/runtime-discovery/cases/run.sh attach-check "$S/trace.txt" 20 2>&1 | tee -a "$S/smoke.log"; then ATTACHED="-attached"; fi
log "## known events inside the container (exec + open)"
docker exec s2smoke sh -c 'cat /etc/os-release > /dev/null; ls /usr/lib > /dev/null; /bin/echo done' 2>&1 | tee -a "$S/smoke.log"
sleep 2; STOP=$(date -u +%FT%T.%NZ); kill -INT $TP; wait $TP 2>/dev/null; RC=$?; sleep 1; log "tracer stopped rc=$RC at $STOP"
"$B" cgroup-map -root /sys/fs/cgroup -merge "$S/cgroup-map.json" -out "$S/cgroup-map.json"
docker rm -f s2smoke >/dev/null 2>&1
log "trace lines: $(wc -l < "$S/trace.txt")  stderr lines: $(wc -l < "$S/trace.err")"; grep -m2 "^E|" "$S/trace.txt" | tee -a "$S/smoke.log"; grep "^@" "$S/trace.txt" | tee -a "$S/smoke.log"; cut -d" " -f2- "$S/trace.err" | sort | uniq -c | sort -rn | head -4 | tee -a "$S/smoke.log"
log "## convert"
cat "$S/trace.txt" "$S/trace.err" | "$B" convert -in - -cgroup-map "$S/cgroup-map.json" -config-id bpftrace-v2-nofilter-64p -sync attach_running $ATTACHED -buffer-pages 64 -path-buffer 256 -script-version 3 -variant nofilter \
  -boot-epoch "$(python3 -c "import json;print(json.load(open('$S/clock.json'))['boot_epoch'])")" -clock-error-ns "$(python3 -c "import json;print(json.load(open('$S/clock.json'))['error_ns'])")" \
  -stopped-at "$STOP" -window-start "$START" -window-end "$STOP" -out "$S/events.jsonl" 2>&1 | tee -a "$S/smoke.log"
python3 - "$S" <<'PY' | tee -a "$S/smoke.log"
import json,sys,collections
S=sys.argv[1]; ev=[json.loads(l) for l in open(f'{S}/events.jsonl') if l.strip()]
recs=[e for e in ev if e.get('record')=='event']
print('events', len(recs), dict(collections.Counter(e['event'] for e in recs)))
print('attribution', dict(collections.Counter(e.get('attribution') for e in recs)))
print('pid/tid zero', sum(1 for e in recs if not e.get('pid') or not e.get('tid')))
att=[e for e in recs if e.get('attribution')=='container']
print('attributed to the smoke container:', len(att), 'exec among them:', sum(1 for e in att if e['event']=='exec'))
for e in att[:5]: print('  ', e['event'], e.get('path'), e.get('pid'), e.get('container_id','')[:12])
opens=[e for e in att if e['event']=='open']
print('open paths in container (top 5)', collections.Counter(e.get('path') or e.get('raw_path') for e in opens).most_common(5))
tr=[e for e in ev if e.get('record')=='events_trailer']; print('drops', tr[0]['drops'] if tr else None)
PY
chown -R "$OWNER":"$OWNER" "$S"; log "## done"
