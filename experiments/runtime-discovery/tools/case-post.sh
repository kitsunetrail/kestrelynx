#!/usr/bin/env bash
# What: re-runs GT-B construction and match against saved run directories for cases 13-24
# (after a post-processing change), without repeating the measurement itself.
# Usage: bash experiments/runtime-discovery/tools/case-post.sh <run dir>...
#   (default: every case-13..24 run directory with a collect record)
# Prerequisites: the runtime-discovery/runtime-events binaries built into
# experiments/runtime-discovery/out/, python3, and (for a run missing a scan) trivy with the
# image still present in the native Docker Engine daemon.
set -uo pipefail
cd "$(dirname "$0")/../../.."
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock
OWNER="${SUDO_USER:-$(id -un)}"
O=experiments/runtime-discovery/out; T=experiments/runtime-discovery/tools; B=$O/runtime-discovery
DIRS=("$@")
if [ ${#DIRS[@]} -eq 0 ]; then
  for p in 13 14 15 16 17 18 19 20 21 22 "23+24" "23+host" 23 24; do
    for d in $O/$p-root-*-r*-*; do [ -d "$d/collect" ] && DIRS+=("$d"); done
  done
fi
for R in "${DIRS[@]}"; do
  R=${R%/}; OBS=$(ls "$R"/collect/*__*.json 2>/dev/null | head -1); [ -n "$OBS" ] || { echo "== $(basename "$R"): no observation"; continue; }
  # Intel (KEV/EPSS) enrichment: reuse a saved snapshot when KL_INTEL_SNAPSHOT names one
  # (for reproducing an earlier classification), otherwise look up live through a local
  # cache and save what this run used, so a later run can reproduce it.
  if [ -n "${KL_INTEL_SNAPSHOT:-}" ]; then INTEL_ARGS=(-intel-snapshot "$KL_INTEL_SNAPSHOT")
  else INTEL_ARGS=(-intel-cache experiments/runtime-discovery/out/intel-cache -out-intel-snapshot "$R/intel.json"); fi
  c=$(python3 -c "import json;print(json.load(open('$OBS'))['subject']['docker']['name'] if 'name' in json.load(open('$OBS'))['subject'].get('docker',{}) else '')" 2>/dev/null)
  IMG=$(python3 -c "import json;print(json.load(open('$R/case.json'))['image'])"); case "$(basename "$R")" in 16-*) IMG=kl-case16;; esac
  # scan by image id when the run has none (cached per image id under out/scans)
  V=$(basename "$R" | sed 's/-root-.*//'); IID=$(cat "$R/image_id.txt" 2>/dev/null)
  # the coverage-validation cases evaluate every bundled package, not only the ones with findings
  ALLPKG=""; LISTALL=""; case "$V" in 26|27|28) ALLPKG="-all-packages"; LISTALL="--list-all-pkgs";; esac
  # a coverage case whose saved report predates --list-all-pkgs is scanned again, so every bundled package is in it
  if [ -n "$LISTALL" ] && [ -s "$R/trivy_all.json" ] && ! grep -q '"Packages"' "$R/trivy_all.json"; then rm -f "$R/trivy_hc.json" "$R/trivy_all.json" "$O/scans/$V.image_id.txt"; fi
  if [ ! -s "$R/trivy_hc.json" ] && [ -n "$IID" ]; then
    export DOCKER_CONFIG=$(mktemp -d)
    if command -v trivy >/dev/null 2>&1; then TRIVY=trivy
    elif [ -x "$HOME/.local/bin/trivy" ]; then TRIVY="$HOME/.local/bin/trivy"
    else TRIVY="/home/$OWNER/.local/bin/trivy"; fi
    mkdir -p $O/scans
    if [ -n "$LISTALL" ] && [ -s "$O/scans/$V.trivy_all.json" ] && ! grep -q '"Packages"' "$O/scans/$V.trivy_all.json"; then rm -f "$O/scans/$V.image_id.txt"; fi
    if [ ! -s "$O/scans/$V.trivy_all.json" ] || [ "$(cat $O/scans/$V.image_id.txt 2>/dev/null)" != "$IID" ]; then
      "$TRIVY" image --format json --scanners vuln $LISTALL -o "$O/scans/$V.trivy_all.json" "$IID" > "$R/scan.log" 2>&1 || { echo "   scan failed: $(tail -1 "$R/scan.log")"; continue; }
      "$TRIVY" image --format json --scanners vuln $LISTALL --severity HIGH,CRITICAL -o "$O/scans/$V.trivy_hc.json" "$IID" >> "$R/scan.log" 2>&1 || { echo "   scan failed: $(tail -1 "$R/scan.log")"; continue; }
      echo "$IID" > $O/scans/$V.image_id.txt
    fi
    cp $O/scans/$V.trivy_all.json "$R/trivy_all.json"; cp $O/scans/$V.trivy_hc.json "$R/trivy_hc.json"; echo "   scanned $V"
  fi
  # convert when the run has a trace but no events (the run stopped before conversion), or when RECONVERT=1 forces it
  if { [ ! -s "$R/events.jsonl" ] || [ "${RECONVERT:-0}" = 1 ]; } && [ -s "$R/trace.txt" ]; then
    SYNC=$(basename "$R" | grep -o "startup\|attach_running"); TAG=$(basename "$R" | sed 's/.*-\(nofilter[0-9]*p\).*/\1/')
    case "$TAG" in nofilter64p) VARIANT=nofilter; PAGES=64; CFG=bpftrace-v2-nofilter-64p;; nofilter256p) VARIANT=nofilter-256p; PAGES=256; CFG=bpftrace-v2-nofilter-256p;; nofilter512p) VARIANT=nofilter-512p; PAGES=512; CFG=bpftrace-v2-nofilter-512p;; *) echo "   unknown tag $TAG"; continue;; esac
    BOOT=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['boot_epoch'])"); CERR=$(python3 -c "import json;print(json.load(open('$R/clock.json'))['error_ns'])")
    STOP=$(grep -o "tracer stopped rc=[0-9]* at [^ ]*" "$R/run.log" | tail -1 | awk '{print $NF}'); WSTART=$(python3 -c "import json;print(json.load(open('$OBS'))['window']['scheduled_start'])"); WEND=$(python3 -c "import json;print(json.load(open('$OBS'))['window']['scheduled_end'])")
    ATT=""; grep -q "attach-check OK" "$R/run.log" && ATT="-attached"
    cat "$R/trace.txt" "$R/trace.err" | $O/runtime-events convert -in - -cgroup-map "$R/cgroup-map.json" -config-id "$CFG" -script-version "$(grep -m1 "^V|" "$R/trace.txt" | cut -d"|" -f2)" -variant "$VARIANT" -sync "$SYNC" $ATT \
      -buffer-pages "$PAGES" -path-buffer 256 -boot-epoch "$BOOT" -clock-error-ns "$CERR" -stopped-at "$STOP" -window-start "$WSTART" -window-end "$WEND" -out "$R/events.jsonl" 2>&1 | tail -1
    echo "   converted ($(grep -c '"record": *"event"\|"record":"event"' "$R/events.jsonl") events)"
  fi
  EVENTS=""; [ -s "$R/events.jsonl" ] && EVENTS="-events $R/events.jsonl"
  echo "== $(basename "$R") image $IMG $( [ -n "$EVENTS" ] && echo with-events || echo no-events)"
  python3 "$T/gtb_case.py" "$R" "$IMG" 2>&1 | tail -3
  # one match per observed container (the attribution control's combined run observes two); single-container runs keep the plain csv_hc/match_hc names
  NOBS=$(ls "$R"/collect/*__*.json | wc -l)
  for OBSF in "$R"/collect/*__*.json; do
    if [ "$NOBS" -gt 1 ]; then cn=$(basename "$OBSF" | cut -d_ -f1); SUF="-$cn"; else SUF=""; fi
    mkdir -p "$R/csv_hc$SUF" "$R/csv_all$SUF"
    "$B" match -observation "$OBSF" -trivy "$R/trivy_hc.json" -case "$R/case.json" -gtb "$R/gtb.json" $EVENTS "${INTEL_ARGS[@]}" $ALLPKG -out-json "$R/match_hc$SUF.json" -out-csv-dir "$R/csv_hc$SUF" 2>&1 | tail -1
    "$B" match -observation "$OBSF" -trivy "$R/trivy_all.json" -case "$R/case.json" -gtb "$R/gtb.json" $EVENTS "${INTEL_ARGS[@]}" $ALLPKG -out-json "$R/match_all$SUF.json" -out-csv-dir "$R/csv_all$SUF" 2>&1 | tail -1
    python3 - "$R" "$SUF" <<'PY2'
import csv,sys,json
R,SUF=sys.argv[1],sys.argv[2]
rows=[r for r in csv.DictReader(open(f'{R}/csv_hc{SUF}/series.csv')) if r.get('classification') in ('overall','delta')]
for r in rows: print('  ', SUF or '', r['series'], {k:r.get(k) for k in ('confirmed','target_finding','confirmed_pkg','target_pkg','event_state','collection_complete','unconditional_rate','conditional_rate','tp','fp','tn','fn')})
g=list(csv.DictReader(open(f'{R}/csv_hc{SUF}/gt_b.csv')))[0]; print('   gt_b', {k:g.get(k) for k in ('population','undetermined','coverage','tp','fp','tn','fn')})
m=json.load(open(f'{R}/match_hc{SUF}.json')); oc=m.get('occurrence_capture',{}); a=m.get('attribution',{}); print('   capture exec', oc.get('exec',{}).get('rate'), 'load', oc.get('load',{}).get('rate'), 'rule', oc.get('match_rule'), '| attribution', a.get('correct_attribution_rate'), 'host', a.get('host_occurrences'), a.get('host_left_unattributed'), a.get('host_misattributed_occurrences'))
PY2
  done
done
