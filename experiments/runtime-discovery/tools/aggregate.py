#!/usr/bin/env python3
"""Aggregate every V-series run (event-evidence conditions) into summary tables (per run,
never merged across conditions).

Usage (from the repository root): python3 tools/aggregate.py
Reads each run directory's series.csv/event_drops.csv/occurrence_capture.csv/attribution.csv/gt_b.csv
under experiments/runtime-discovery/out/ and writes experiments/runtime-discovery/out/AGGREGATE-events.md.
"""
import csv, glob, os, re

O = 'experiments/runtime-discovery/out'

# Cases 13-24 (the read-only-mapping/event-evidence series), including the
# attribution control's combined-condition run directories (23+24, 23+host).
CASE_PREFIXES = ('13', '14', '15', '16', '17', '18', '19', '20', '21', '22',
                  '23+24', '23+host', '23', '24')

def run_dirs():
    return sorted(d for d in glob.glob(f'{O}/*-root-*')
                  if os.path.isdir(d) and os.path.basename(d).split('-root-')[0] in CASE_PREFIXES)

def containers(run):
    """Return [(tag, csv_dir), ...] for a run: tag is None for a plain match_hc.json/csv_hc
    layout, or the container name (case23/case24) for a match_hc-<tag>.json/csv_hc-<tag> layout."""
    files = sorted(glob.glob(f'{run}/match_hc*.json'))
    plain = f'{run}/match_hc.json'
    if files == [plain]:
        return [(None, f'{run}/csv_hc')]
    out = []
    for f in files:
        mo = re.match(re.escape(run) + r'/match_hc-(.+)\.json$', f)
        if mo:
            tag = mo.group(1)
            out.append((tag, f'{run}/csv_hc-{tag}'))
    return out

def label(run, tag):
    return f'{os.path.basename(run)}::{tag}' if tag else os.path.basename(run)

def csvrows(csv_dir, name):
    f = f'{csv_dir}/{name}'
    if not os.path.exists(f):
        return None
    with open(f) as fh:
        return list(csv.DictReader(fh))

def run_failed_log(run):
    f = f'{run}/run.log'
    if not os.path.exists(f):
        return False
    with open(f, errors='replace') as fh:
        return any(' FAILED:' in line for line in fh)

L = []
P = L.append
missing = []   # (run, tag, reason)
obs = []       # (run, tag, csv_dir) for every readable observation

for run in run_dirs():
    conds = containers(run)
    failed_log = run_failed_log(run)
    if not conds:
        missing.append((run, None, 'match_hc*.json が無い'))
    for tag, csv_dir in conds:
        if failed_log:
            # the run stopped before its own post-processing, and the
            # results here come from a later re-processing of its saved
            # inputs: worth a note, but not a missing result
            missing.append((run, tag, 'run.log に FAILED 記録あり(保存入力から再処理済み)'))
        obs.append((run, tag, csv_dir))

# ---- 表1: run 一覧 ----
P('# V系 集計\n')
P('## 表1 run 一覧\n')
P('| run | case_variant | sync | config_id | rep | event_state | lost_events | enter_exit_unmatched | partial_events | '
  'S0 confirmed/target | S1 confirmed/target | S2 confirmed/target | S2 無条件率 | S2 条件付き率 | '
  'S0→S1 delta(findings/pkg) | S1→S2 delta(findings/pkg) |')
P('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
for run, tag, csv_dir in obs:
    series = csvrows(csv_dir, 'series.csv')
    drops = csvrows(csv_dir, 'event_drops.csv')
    if series is None or drops is None:
        missing.append((run, tag, 'series.csv/event_drops.csv が無い'))
        continue
    d = drops[0]
    def overall(s):
        for r in series:
            if r['series'] == s and r['classification'] == 'overall':
                return r
        return None
    def delta(s):
        for r in series:
            if r['series'] == s and r['classification'] == 'delta':
                return r
        return None
    s0, s1, s2 = overall('S0'), overall('S1'), overall('S2')
    d01, d12 = delta('S0->S1'), delta('S1->S2')
    if not (s0 and s1 and s2):
        missing.append((run, tag, 'series.csv に S0/S1/S2 overall 行が無い'))
        continue
    P(f"| {label(run, tag)} | {d['case_variant']} | {d['sync']} | {d['config_id']} | {d['replicate']} | "
      f"{d['event_state']} | {d['lost_events']} | {d.get('enter_exit_unmatched', 'N/A')} | {d.get('partial_events', 'N/A')} | "
      f"{s0['confirmed']}/{s0['target_finding']} | {s1['confirmed']}/{s1['target_finding']} | {s2['confirmed']}/{s2['target_finding']} | "
      f"{s2['unconditional_rate']} | {s2['conditional_rate']} | "
      f"{(d01['confirmed'] if d01 else 'N/A')}/{(d01['confirmed_pkg'] if d01 else 'N/A')} | "
      f"{(d12['confirmed'] if d12 else 'N/A')}/{(d12['confirmed_pkg'] if d12 else 'N/A')} |")

# ---- 表2: 発生単位の捕捉率 ----
P('\n## 表2 発生単位の捕捉率\n')
P('| run | exec eligible | exec one_to_one | exec rate | exec undecidable | '
  'load eligible | load with_evidence | load rate | real_open | '
  'excluded cache_hit | excluded failed | excluded outside_window | tolerance_ms | match_rule |')
P('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
for run, tag, csv_dir in obs:
    rows = csvrows(csv_dir, 'occurrence_capture.csv')
    if rows is None:
        missing.append((run, tag, 'occurrence_capture.csv が無い'))
        continue
    r = rows[0]
    real_open = 'N/A(na)' if r.get('real_open_rate') == 'N/A' and r.get('real_open_occurrences') == '0' else r.get('real_open_rate')
    P(f"| {label(run, tag)} | {r['exec_eligible']} | {r['exec_one_to_one']} | {r['exec_rate']} | {r['exec_undecidable']} | "
      f"{r['load_eligible']} | {r['load_with_evidence']} | {r['load_rate']} | {real_open} | "
      f"{r['excluded_cache_hit']} | {r['excluded_failed']} | {r['excluded_outside_window']} | {r['tolerance_ms']} | {r['match_rule']} |")

# ---- 表3: 帰属 ----
# ホスト側の列は attribution.csv に出る（列が無い古い出力は N/A）。
P('\n## 表3 帰属\n')
P('| run | logged_occurrences | correctly_attributed | correct_attribution_rate | '
  'host_occurrences | host_misattributed_occurrences | host_left_unattributed | host_unobserved | '
  'from_host | misattribution_rate | cross_container_evaluable |')
P('|---|---|---|---|---|---|---|---|---|---|---|')
for run, tag, csv_dir in obs:
    rows = csvrows(csv_dir, 'attribution.csv')
    if rows is None:
        missing.append((run, tag, 'attribution.csv が無い'))
        continue
    r = rows[0]
    P(f"| {label(run, tag)} | {r['logged_occurrences']} | {r['correctly_attributed']} | {r['correct_attribution_rate']} | "
      f"{r.get('host_occurrences', 'N/A')} | {r.get('host_misattributed_occurrences', 'N/A')} | {r.get('host_left_unattributed', 'N/A')} | {r.get('host_unobserved', 'N/A')} | "
      f"{r['from_host']} | {r['misattribution_rate']} | {r.get('cross_container_evaluable', 'N/A')} |")

# ---- 表4: 正解データ（GT-B） ----
P('\n## 表4 正解データ（GT-B）\n')
P('| run | population | coverage | tp | fp | tn | fn | fnr | undetermined |')
P('|---|---|---|---|---|---|---|---|---|')
for run, tag, csv_dir in obs:
    rows = csvrows(csv_dir, 'gt_b.csv')
    if rows is None:
        missing.append((run, tag, 'gt_b.csv が無い'))
        continue
    r = rows[0]
    P(f"| {label(run, tag)} | {r['population']} | {r['coverage']} | {r['tp']} | {r['fp']} | {r['tn']} | {r['fn']} | {r['fnr']} | {r['undetermined']} |")

# ---- 表5: バッファと取りこぼし ----
# 同じ case_variant/sync の run を隣接させ、buffer_pages 順に並べる（列で 64/256/512 を突き合わせるのではなく、
# 存在する buffer_pages だけを行として並べる。組が揃わない run もそのまま出す）。
P('\n## 表5 バッファと取りこぼし\n')
P('| group(case_variant/sync) | run | buffer_pages | lost_events | events_after_filter | event_state |')
P('|---|---|---|---|---|---|')
group_rows = []
for run, tag, csv_dir in obs:
    rows = csvrows(csv_dir, 'event_drops.csv')
    if rows is None:
        continue
    r = rows[0]
    group_rows.append((r['case_variant'], r['sync'], int(r['buffer_pages']) if r['buffer_pages'].isdigit() else -1, label(run, tag), r))
for cv, sync, bp, lab, r in sorted(group_rows, key=lambda x: (x[0], x[1], x[2])):
    P(f"| {cv}/{sync} | {lab} | {r['buffer_pages']} | {r['lost_events']} | {r['events_after_filter']} | {r['event_state']} |")

# ---- 不成立・欠損の run ----
P('\n## 不成立・欠損の run\n')
if missing:
    P('| run | container | 理由 |')
    P('|---|---|---|')
    for run, tag, reason in missing:
        P(f"| {os.path.basename(run)} | {tag or ''} | {reason} |")
else:
    P('（無し）')

open(f'{O}/AGGREGATE-events.md', 'w').write('\n'.join(L) + '\n')
print(f'wrote {O}/AGGREGATE-events.md ({len(L)} lines), {len(obs)} observations, {len(missing)} missing/failed entries')
