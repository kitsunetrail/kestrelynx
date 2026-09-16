#!/usr/bin/env python3
"""Build a run record (markdown) from a run directory for cases 13-24 (the
read-only-mapping/event-evidence series).

Usage: record.py <run_dir>
Reads: <run_dir>/case.json, <run_dir>/collect/*.json (observation), <run_dir>/match_hc*.json,
       <run_dir>/run.log. A run with more than one match_hc-<tag>.json (attribution
       control, cases 23/24) gets one section per container, sharing the run-level header.
Writes <run_dir>/record.md and prints it.
"""
import glob, json, os, re, sys

run = sys.argv[1].rstrip('/')
out = []
P = out.append


def pct(x):
    return 'N/A' if x is None or (isinstance(x, (int, float)) and x < 0) else f'{x:.4f}'


def containers(run):
    """[(tag, match_path, csv_dir), ...]; tag is None for a plain match_hc.json/csv_hc layout."""
    files = sorted(glob.glob(f'{run}/match_hc*.json'))
    plain = f'{run}/match_hc.json'
    if files == [plain]:
        return [(None, plain, f'{run}/csv_hc')]
    result = []
    for f in files:
        mo = re.match(re.escape(run) + r'/match_hc-(.+)\.json$', f)
        if mo:
            tag = mo.group(1)
            result.append((tag, f, f'{run}/csv_hc-{tag}'))
    return result


def obs_file(run, tag):
    files = [f for f in glob.glob(f'{run}/collect/*.json')
             if not f.endswith('manifest.json') and not f.endswith('ready.json')]
    if tag:
        files = [f for f in files if os.path.basename(f).startswith(f'{tag}__')]
    return files[0] if files else None


case = json.load(open(f'{run}/case.json'))
runlog = open(f'{run}/run.log', errors='replace').read() if os.path.exists(f'{run}/run.log') else ''
boot_epoch_line = next((l for l in runlog.splitlines() if 'boot_epoch' in l), None)

conds = containers(run)

P(f"## run: {os.path.basename(run)}\n")
P(f"- case_id: {case.get('case_id')}（image: {case.get('image')}）")
if not conds:
    P('\n（match_hc*.json が見つからないため、以降のセクションは生成できない）\n')
    open(f'{run}/record.md', 'w').write('\n'.join(out) + '\n')
    print('\n'.join(out))
    raise SystemExit(0)

# run キーはどの container でも共通のはずなので最初の match から取る
first_match = json.load(open(conds[0][1]))
rk = first_match.get('run_key') or {}
P(f"- runキー: permission={rk.get('permission')} / interval={rk.get('interval_seconds')} / "
  f"window={rk.get('window_seconds')} / phase={rk.get('phase_seconds')} / replicate={rk.get('replicate')} / "
  f"sync={rk.get('sync')} / config_id={rk.get('config_id')}")
if boot_epoch_line:
    P(f"- 環境: run.log 記載の boot_epoch 行: {boot_epoch_line.strip()}")
else:
    P("- 環境: run.log に boot_epoch の記載なし（省略）")
if ' FAILED:' in runlog:
    P("- run.log 注記: FAILED を含む行がある（trivy 等の一部ステップが失敗した記録。match/csv データの有無は各セクション参照）")

for tag, match_path, csv_dir in conds:
    m = json.load(open(match_path))
    P(f"\n### container: {tag or '(単一)'}\n")

    of = obs_file(run, tag)
    if of:
        c = json.load(open(of))
        w = c.get('window', {})
        P(f"- 観測窓: {w.get('scheduled_start')} → {w.get('scheduled_end')}（samples {len(w.get('samples', []))} 回）")
    else:
        P("- 観測窓: collect/*.json が見つからない")

    ec = m.get('event_collection') or {}
    ed = m.get('event_drops') or {}
    P(f"- イベント収集: version={ec.get('version')} / variant={ec.get('filter')} / buffer_pages={ec.get('buffer_pages')} / "
      f"method={ec.get('method')} / attached={ec.get('attached')}")
    P(f"- drops: lost_events={ed.get('lost_events')} / enter_exit_unmatched={ed.get('enter_exit_unmatched')} / "
      f"enter_exit_unmatched_boundary={ed.get('enter_exit_unmatched_boundary')} / partial_events={ed.get('partial_events')}")
    P(f"- event_state: {m.get('event_state')}")

    oc = m.get('occurrence_capture') or {}
    ex = oc.get('exec') or {}
    ld = oc.get('load') or {}
    ro = oc.get('real_open') or {}
    P(f"- 発生単位の捕捉 exec: eligible={ex.get('eligible')} / one_to_one={ex.get('one_to_one')} / "
      f"rate={pct(ex.get('rate'))} / undecidable={ex.get('undecidable')}")
    P(f"- 発生単位の捕捉 load: eligible={ld.get('eligible')} / with_evidence={ld.get('with_evidence')} / rate={pct(ld.get('rate'))}")
    P(f"- 発生単位の捕捉 real_open: na={ro.get('na')} / occurrences={ro.get('occurrences')} / rate={pct(ro.get('rate'))}")

    at = m.get('attribution') or {}
    P(f"- 帰属: logged_occurrences={at.get('logged_occurrences')} / correctly_attributed={at.get('correctly_attributed')} / "
      f"correct_attribution_rate={pct(at.get('correct_attribution_rate'))} / from_host={at.get('from_host')} / "
      f"misattribution_rate={pct(at.get('misattribution_rate'))} / cross_container_evaluable={at.get('cross_container_evaluable')}")
    P("  - host_occurrences / host_misattributed_occurrences / host_left_unattributed / host_unobserved: N/A（現行スキーマに列が無い）")

    P("\n#### S0/S1/S2（overall）と delta\n")
    P("| series | target_finding | confirmed | 無条件率 | 条件付き率 |")
    P("|---|---|---|---|---|")
    for s in m.get('series') or []:
        ov = s.get('overall') or {}
        P(f"| {s.get('series')} | {ov.get('finding_denominator')} | {ov.get('finding_confirmed')} | "
          f"{pct(ov.get('unconditional_rate'))} | {pct(ov.get('conditional_rate'))} |")
    P("\n| delta | findings | packages |")
    P("|---|---|---|")
    for d in m.get('series_deltas') or []:
        if d.get('available'):
            # findings/packages はゼロのとき省略されている（0 として扱う）
            findings, packages = d.get('findings', 0), d.get('packages', 0)
        else:
            findings = packages = f"N/A（{d.get('reason', '')}）"
        P(f"| {d.get('from')}→{d.get('to')} | {findings} | {packages} |")

    g = m.get('gt_b') or {}
    P(f"\n- GT-B: population={g.get('population')} / undetermined={g.get('undetermined_pairs')} / "
      f"coverage={pct(g.get('coverage'))} / tp={g.get('TP')} / fp={g.get('FP')} / tn={g.get('TN')} / fn={g.get('FN')} / "
      f"fnr={pct(g.get('fnr'))}")

txt = '\n'.join(out) + '\n'
open(f'{run}/record.md', 'w').write(txt)
print(txt)
