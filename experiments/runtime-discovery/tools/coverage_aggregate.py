#!/usr/bin/env python3
"""Collects every coverage.json under out/ (cases 26-28) into one table.

Usage: coverage_aggregate.py [out dir]   (default experiments/runtime-discovery/out)
Writes: <out dir>/AGGREGATE-coverage.md and <out dir>/AGGREGATE-coverage.csv

One row per measurement run and category, with the S0/S1/S2 recall, the
false-positive count, the S2 false-negative count with its primary
causes, the supplementary window recall, and the run's own event state
and hold status. The table is the input to the results write-up; the
per-run coverage.md files keep the package-level detail.
"""
import csv
import glob
import json
import os
import re
import sys

SERIES = ('S0', 'S1', 'S2')


def run_fields(run_dir):
    m = re.match(r'(\d+)-root-(\d+)-(\d+)-p(\d+)-r(\d+)-(startup|attach_running)-(\S+)$', os.path.basename(run_dir))
    if not m:
        return None
    return {'run': os.path.basename(run_dir), 'case': m.group(1), 'interval': int(m.group(2)),
            'window': int(m.group(3)), 'phase': int(m.group(4)), 'replicate': int(m.group(5)),
            'sync': m.group(6), 'tag': m.group(7)}


def pct(x):
    return 'N/A' if x is None else f'{round(x * 100)}%'


def rows_for(run_dir):
    path = os.path.join(run_dir, 'coverage.json')
    if not os.path.exists(path):
        return []
    fields = run_fields(run_dir)
    if fields is None:
        return []
    cov = json.load(open(path))
    hold = cov.get('hold') or (cov.get('all') or {}).get('hold')
    variant = cov.get('all') or {}
    out = []
    if hold or not variant.get('categories'):
        out.append({**fields, 'category': '-', 'used': '', 'unused': '', 'S0': '', 'S1': '', 'S2': '',
                    'fp': '', 'fn_S2': '', 'causes': '', 'window_recall': '', 'event_state': variant.get('event_state', ''),
                    'hold': cov.get('hold_reason') or variant.get('hold_reason') or 'hold'})
        return out
    for cat, row in sorted(variant['categories'].items()):
        s = row['series']
        causes = s['S2'].get('miss_cause_counts') or {}
        out.append({**fields, 'category': cat, 'used': row['used_count'], 'unused': row['unused_count'],
                    'S0': pct(s['S0']['recall']), 'S1': pct(s['S1']['recall']), 'S2': pct(s['S2']['recall']),
                    'fp': max(s[k]['fp'] for k in SERIES), 'fn_S2': s['S2']['fn'],
                    'causes': ', '.join(f'{k} {v}' for k, v in sorted(causes.items()) if v),
                    'window_recall': pct((s['S2'].get('window') or {}).get('recall')),
                    'event_state': variant.get('event_state', ''), 'hold': ''})
    return out


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else 'experiments/runtime-discovery/out'
    rows = []
    for run_dir in sorted(glob.glob(os.path.join(out_dir, '2[678]-root-*'))):
        rows.extend(rows_for(run_dir))
    rows.sort(key=lambda r: (r['case'], r['sync'] != 'startup', -r['window'], -r['interval'], r['phase'], r['tag'], r['replicate'], r['category']))
    cols = ['run', 'case', 'sync', 'interval', 'window', 'phase', 'replicate', 'tag', 'category', 'used', 'unused',
            'S0', 'S1', 'S2', 'fp', 'fn_S2', 'causes', 'window_recall', 'event_state', 'hold']
    with open(os.path.join(out_dir, 'AGGREGATE-coverage.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)
    with open(os.path.join(out_dir, 'AGGREGATE-coverage.md'), 'w') as f:
        f.write('# Coverage validation: all scored runs\n\n')
        f.write('| ' + ' | '.join(cols) + ' |\n|' + ' --- |' * len(cols) + '\n')
        for r in rows:
            f.write('| ' + ' | '.join(str(r[c]) for c in cols) + ' |\n')
    print(f'{len(rows)} rows -> {out_dir}/AGGREGATE-coverage.md')


if __name__ == '__main__':
    main()
