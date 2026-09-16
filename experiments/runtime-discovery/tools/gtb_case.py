#!/usr/bin/env python3
"""Build the GT-B input for one run directory (cases 13-24: the read-only-mapping/
event-evidence series).

Usage: gtb_case.py <run_dir> <image>
Inputs:  <run_dir>/gtb-raw/usage.jsonl, <run_dir>/gtb-raw/occurrences.jsonl
Runs gtb.py (in this same directory) for the ownership part (usage_log kind), then adds
occurrences and clock_base. Writes <run_dir>/gtb.json.

No pid_map is written here: matching falls back to comparing each event's
namespace-scoped process and thread numbers directly against the
occurrence's own, which is decidable without a correspondence table at all.
"""
import json, os, subprocess, sys
run, image = sys.argv[1].rstrip('/'), sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
r = subprocess.run([sys.executable, f'{here}/gtb.py', run, image, 'usage_log'], capture_output=True, text=True)
sys.stdout.write(r.stdout); sys.stderr.write(r.stderr)
if r.returncode != 0: sys.exit(r.returncode)
gtb = json.load(open(f'{run}/gtb.json'))
occ = []
for line in open(f'{run}/gtb-raw/occurrences.jsonl'):
    line = line.strip()
    if line: occ.append(json.loads(line))
gtb['occurrences'] = occ
gtb['clock_base'] = ('occurrence ts: CLOCK_REALTIME read inside the container (date -u, nanoseconds); '
                     'events: CLOCK_MONOTONIC converted to realtime with the boot_epoch and error_ns from runtime-events clock')
json.dump(gtb, open(f'{run}/gtb.json', 'w'), indent=1)
kinds = {}
for o in occ: kinds[o['kind']] = kinds.get(o['kind'], 0) + 1
print(f'{run}: occurrences={len(occ)} {kinds} ok={sum(1 for o in occ if o.get("ok"))}')
