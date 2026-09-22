#!/usr/bin/env python3
"""Aggregates match's G4 additional-judgement ranking (baseline vs.
runtime-evidence-adjusted act-now/watch order) across every scored run
under out/, and cross-references coverage.py's own S2 misses to see
whether a missed package's own Finding ever leaves its baseline rank.

Usage: coverage_rank.py [out dir]   (default experiments/runtime-discovery/out)
Writes: <out dir>/AGGREGATE-rank.md and <out dir>/AGGREGATE-rank.csv

Definitions
-----------
"none" (rendered "Runtime info absent") is g4.go's own BaselineRank order:
priority/severity/package/vulnID only, computed once per priority bucket
and never dependent on any runtime evidence (see g4.go's baselineLess).
Since it never differs between series, this tool reports it as one
reference row per (run, variant, priority) instead of comparing it against
itself.

"S0"/"S2" are the two series match.go's own computeG4 call sites actually
produce (see match.go, the loop building result.G4): only the sampling
stage's own path-resolution evidence (S0) and the fully-joined S0+mapping+
event evidence (S2) ever feed the additional-judgement ranking — S1 is
never one of g4's series values. This tool reports whatever series a run's
own g4 array carries rather than assuming S0/S1/S2 are all present, and
this file's own aggregation over 30 real runs found only S0 and S2, never
S1, in every one of them.

Columns
-------
total_findings       - g4[].total_findings for this (series, priority):
                        how many Findings the priority bucket holds.
rank_changed_count   - g4[].rank_changed_count: how many of the top 20
                        adjusted-order rows sit at a different position
                        than their own BaselineRank. This is already the
                        run's own "diff from Runtime info absent" figure,
                        since BaselineRank IS the no-runtime-info order;
                        it is repeated under vs_no_runtime_rank_changed so
                        the comparison the design calls for has its own
                        named column instead of relying on a reader to
                        know rank_changed_count already means that.
top20_promoted       - among the top 20 adjusted-order rows, how many have
                        AdjustedRank < BaselineRank (moved to an earlier,
                        more urgent position than the no-runtime-info
                        order gave them).
labeled_count        - g4[].labeled_count: how many Findings in this
                        entire priority bucket meet the "confirmed in use,
                        published to the world, and privileged" label
                        match.go's G4Result already defines. This is a
                        bucket-wide count, not a top-20 one: computeG4
                        counts every row that qualifies while it walks the
                        adjusted order, regardless of whether that row
                        also made the top 20 stored in Top20.
missed_pkg_findings  - the count this run's own coverage.json S2 misses
                        would carry into this priority bucket: for every
                        (name, version) coverage.json's S2 pass listed as
                        a miss (present in one of that variant's own
                        categories' series.S2.misses), this sums that
                        package's own priorities[priority] count from
                        match's packages[] (looked up by name and
                        version, never a re-derivation of coverage.py's
                        own miss causes). The same figure for every series
                        row in a given (run, variant, priority), since it
                        is a ground-truth fact independent of which
                        series' ranking is being read.
missed_pkg_in_top20   - of the Findings missed_pkg_findings' packages
                        carry, how many actually appear in this series'
                        own top 20 adjusted-order rows (matched by
                        name+version). A missed package rarely makes the
                        top 20 at all, since it was never confirmed and
                        adjustedLess always sorts confirmed rows first —
                        this is the denominator the next two columns'
                        numerators are out of. g4 only ever stores the
                        top 20 rows of each ranking, so a missed Finding
                        outside that window has no recorded rank at all;
                        see missed_pkg_outside_top20.
missed_pkg_rank_unchanged - of missed_pkg_in_top20, how many sit at
                        exactly their own BaselineRank (AdjustedRank ==
                        BaselineRank). This is the narrow "literally
                        unchanged" reading.
missed_pkg_not_promoted  - of missed_pkg_in_top20, how many were NOT
                        lifted to an earlier, more urgent position
                        (AdjustedRank >= BaselineRank) — this includes
                        both the rank_unchanged rows above AND rows that
                        were pushed to a LATER position by some other
                        Finding's promotion displacing them. A missed
                        package is never Confirmed, so it structurally
                        cannot benefit from the additional rule's
                        promotion (which sorts confirmed rows first); it
                        can still move to a numerically higher rank
                        purely because something else moved past it, and
                        conflating that displacement with "unchanged"
                        would undercount how many missed Findings were
                        never promoted.
missed_pkg_outside_top20 - missed_pkg_findings minus missed_pkg_in_top20:
                        how many of the missed Findings this tool cannot
                        rank at all, because g4 never stored a rank for
                        them outside its own top 20. computeG4's own
                        output never carries the full ranking, so this
                        count is reported on its own rather than folded
                        into "not promoted" — a Finding outside the top
                        20 could just as easily have been demoted or left
                        exactly where the baseline put it, and this tool
                        has no way to tell which.
false_promotions     - among the top 20 adjusted-order rows for this
                        (series, priority), how many both (a) moved to an
                        earlier position than their own BaselineRank
                        (AdjustedRank < BaselineRank, a promotion) and (b)
                        name a (package, version) this run's own
                        coverage.json lists as a false positive for this
                        series (a package the additional rule confirmed
                        that the ground truth says was never actually
                        used). The false positive is first narrowed to
                        the ones that actually carry a Finding in THIS
                        priority bucket (packages[].priorities[priority]
                        > 0, the same lookup missed_pkg_findings uses):
                        a false positive whose own package has no watch
                        Finding at all can never appear in watch's own
                        top 20 no matter what, and must not make an
                        otherwise-fully-determined act_now row read as
                        'N/A' just because that OTHER bucket's own top 20
                        does not mention it. This is 0 whenever no false
                        positive carries a Finding in this priority
                        bucket at all (the actual case in every one of
                        the 30 real runs this tool has been run against —
                        see coverage.json's own series[*].fp). When one
                        does, but its own (name, version) never appears
                        anywhere in this bucket's own top 20, whether it
                        was promoted cannot be read off this run's g4
                        output (which, again, only stores the top 20), so
                        the value is 'N/A' rather than a count that would
                        silently exclude it.

The detail table has one row per (run, variant, series-or-"none",
priority). The summary table groups runs that share every field except
their replicate number (case, sync, interval, window, phase, tag) and
reports whether every replicate agrees on all of the numeric columns
above, so a difference between two supposedly-identical runs is visible
at a glance rather than requiring a manual diff of the detail rows.
"""
import csv
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from coverage_aggregate import run_fields  # noqa: E402  (reuse the run-name parser)

PRIORITIES = ('act_now', 'watch')
NUMERIC_COLS = ('total_findings', 'rank_changed_count', 'top20_promoted',
                 'labeled_count', 'missed_pkg_findings', 'missed_pkg_in_top20',
                 'missed_pkg_rank_unchanged', 'missed_pkg_not_promoted',
                 'missed_pkg_outside_top20', 'false_promotions')


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def collect_s2_misses(cov_variant):
    """The set of (name, version) pairs coverage.json's own S2 pass
    listed as a miss, across every category this variant scored - a
    package can only appear in one category's used-set, so no dedup
    logic beyond a plain set is needed."""
    misses = set()
    for row in (cov_variant.get('categories') or {}).values():
        for m in (row.get('series', {}).get('S2', {}).get('misses') or []):
            misses.add((m.get('name'), m.get('version')))
    return misses


def collect_false_positives(cov_variant, series):
    """The set of (name, version) pairs coverage.json's own pass for the
    given series listed as a false positive, across every category this
    variant scored - the ground-truth-confirmed-unused packages a
    promotion into the top 20 must never rest on."""
    fps = set()
    for row in (cov_variant.get('categories') or {}).values():
        for m in (row.get('series', {}).get(series, {}).get('false_positives') or []):
            fps.add((m.get('name'), m.get('version')))
    return fps


def fps_with_findings_in_priority(fp_keys, packages_idx, priority):
    """The subset of fp_keys that actually carry at least one Finding in
    the given priority bucket (packages[].priorities[priority] > 0). A
    false positive whose own package has no Finding in this bucket at
    all could never appear in this bucket's own top 20 ranking no matter
    what evidence it was confirmed by, so it must never make an
    act_now-only false positive look unresolvable for watch (or the
    reverse) just because the OTHER bucket's own top 20 does not mention
    it."""
    out = set()
    for key in fp_keys:
        for pv in packages_idx.get(key, []):
            if (pv.get('priorities') or {}).get(priority, 0) > 0:
                out.add(key)
                break
    return out


def index_packages(match_json):
    """(name, installed_version) -> list of packages[] entries. A run's
    own package list has no duplicate (name, version) key in the 30 real
    runs this tool was built against, but the index still collects a list
    per key rather than overwriting, so a future run that does carry one
    still sums every matching entry's priorities instead of silently
    dropping one of them."""
    idx = {}
    for pv in match_json.get('packages') or []:
        key = (pv.get('package'), pv.get('installed_version'))
        idx.setdefault(key, []).append(pv)
    return idx


def missed_priority_counts(missed_keys, packages_idx):
    """priority -> Finding count, summed over every missed (name,
    version) package's own priorities[priority] map. A miss whose
    (name, version) is not present in packages[] at all (the scan never
    listed a PackageVerdict for it) contributes 0, since there is no
    Finding to count."""
    counts = {p: 0 for p in PRIORITIES}
    for key in missed_keys:
        for pv in packages_idx.get(key, []):
            prios = pv.get('priorities') or {}
            for p in PRIORITIES:
                counts[p] += prios.get(p, 0)
    return counts


def g4_by_series_priority(match_json):
    """(series, priority) -> G4Result dict, for every entry this run's
    own g4 array actually carries (never assumed to be S0/S1/S2 x
    act_now/watch/low in full)."""
    out = {}
    for g in match_json.get('g4') or []:
        out[(g.get('series'), g.get('priority'))] = g
    return out


def rows_for_run(run_dir):
    """One row per (variant, series-or-'none', priority) for this run
    directory, or [] when the run has no g4/coverage data to read (a
    coverage.json in hold state, or a variant whose match file/coverage
    section is missing)."""
    fields = run_fields(run_dir)
    if fields is None:
        return []
    cov = load_json(os.path.join(run_dir, 'coverage.json'))
    if cov is None:
        return []
    out = []
    for variant, match_name in (('all', 'match_all.json'), ('hc', 'match_hc.json')):
        match_json = load_json(os.path.join(run_dir, match_name))
        cov_variant = cov.get(variant) or {}
        hold = cov.get('hold') or cov_variant.get('hold')
        if match_json is None or hold or not cov_variant.get('categories'):
            continue
        missed_keys = collect_s2_misses(cov_variant)
        packages_idx = index_packages(match_json)
        missed_counts = missed_priority_counts(missed_keys, packages_idx)
        g4_index = g4_by_series_priority(match_json)
        series_seen = sorted({s for (s, _p) in g4_index})

        for prio in PRIORITIES:
            # The reference row: g4.go's own BaselineRank order, i.e. what
            # act-now/watch would look like with no runtime evidence at
            # all. total_findings/missed_pkg_findings are read from
            # whichever series entry exists (they do not vary by series);
            # every promotion-related column is N/A, matching the
            # design's own template for this row.
            any_g4 = next((g4_index[k] for k in g4_index if k[1] == prio), None)
            out.append({
                **fields, 'variant': variant, 'series': 'none', 'priority': prio,
                'total_findings': any_g4['total_findings'] if any_g4 else 'N/A',
                'rank_changed_count': 0, 'top20_promoted': 0,
                'labeled_count': 'N/A',
                'vs_no_runtime_rank_changed': 0,
                'missed_pkg_findings': missed_counts[prio],
                'missed_pkg_in_top20': 'N/A', 'missed_pkg_rank_unchanged': 'N/A',
                'missed_pkg_not_promoted': 'N/A', 'missed_pkg_outside_top20': 'N/A',
                'false_promotions': 'N/A',
            })

            for series in series_seen:
                g = g4_index.get((series, prio))
                if g is None:
                    continue
                top20 = g.get('top20') or []
                top20_promoted = sum(1 for r in top20 if r['adjusted_rank'] < r['baseline_rank'])

                missed_rows = [r for r in top20 if (r['package'], r['installed_version']) in missed_keys]
                missed_in_top20 = len(missed_rows)
                missed_rank_unchanged = sum(1 for r in missed_rows if r['adjusted_rank'] == r['baseline_rank'])
                missed_not_promoted = sum(1 for r in missed_rows if r['adjusted_rank'] >= r['baseline_rank'])
                missed_outside_top20 = missed_counts[prio] - missed_in_top20

                fp_keys = fps_with_findings_in_priority(
                    collect_false_positives(cov_variant, series), packages_idx, prio)
                if not fp_keys:
                    false_promotions = 0
                else:
                    top20_keys = {(r['package'], r['installed_version']) for r in top20}
                    if not fp_keys <= top20_keys:
                        # At least one false-positive package's own Finding
                        # never appears anywhere in the stored top 20, so
                        # whether it was promoted cannot be read off this
                        # run's g4 output at all.
                        false_promotions = 'N/A'
                    else:
                        false_promotions = sum(
                            1 for r in top20
                            if (r['package'], r['installed_version']) in fp_keys
                            and r['adjusted_rank'] < r['baseline_rank'])

                out.append({
                    **fields, 'variant': variant, 'series': series, 'priority': prio,
                    'total_findings': g['total_findings'],
                    'rank_changed_count': g['rank_changed_count'],
                    'top20_promoted': top20_promoted,
                    'labeled_count': g['labeled_count'],
                    'vs_no_runtime_rank_changed': g['rank_changed_count'],
                    'missed_pkg_findings': missed_counts[prio],
                    'missed_pkg_in_top20': missed_in_top20,
                    'missed_pkg_rank_unchanged': missed_rank_unchanged,
                    'missed_pkg_not_promoted': missed_not_promoted,
                    'missed_pkg_outside_top20': missed_outside_top20,
                    'false_promotions': false_promotions,
                })
    return out


def summarize(rows):
    """Group rows sharing every field except replicate, and report
    whether every replicate agrees on all of NUMERIC_COLS. condition_key
    excludes 'replicate' and 'run' on purpose: those are exactly the two
    fields expected to differ between repeats of the same condition."""
    groups = {}
    for r in rows:
        key = (r['case'], r['sync'], r['interval'], r['window'], r['phase'], r['tag'],
               r['variant'], r['series'], r['priority'])
        groups.setdefault(key, []).append(r)
    summary = []
    for key, group in sorted(groups.items()):
        (case, sync, interval, window, phase, tag, variant, series, priority) = key
        replicates = sorted({r['replicate'] for r in group})
        values = {}
        consistent = True
        for col in NUMERIC_COLS:
            distinct = sorted({r[col] for r in group}, key=str)
            if len(distinct) == 1:
                values[col] = distinct[0]
            else:
                values[col] = 'DIFFERS:' + '/'.join(str(v) for v in distinct)
                consistent = False
        summary.append({
            'case': case, 'sync': sync, 'interval': interval, 'window': window, 'phase': phase, 'tag': tag,
            'variant': variant, 'series': series, 'priority': priority,
            'replicates': ','.join(str(r) for r in replicates),
            'consistent': 'yes' if consistent else 'no',
            **values,
        })
    return summary


def write_csv(path, rows, cols):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_markdown(path, detail_rows, summary_rows, detail_cols, summary_cols):
    with open(path, 'w') as f:
        f.write('# G4 ranking aggregate: runtime-evidence rank comparison\n\n')
        f.write('## Case x start-condition summary (replicate agreement)\n\n')
        f.write('| ' + ' | '.join(summary_cols) + ' |\n|' + ' --- |' * len(summary_cols) + '\n')
        for r in summary_rows:
            f.write('| ' + ' | '.join(str(r[c]) for c in summary_cols) + ' |\n')
        f.write('\n## Run x series x priority detail\n\n')
        f.write('| ' + ' | '.join(detail_cols) + ' |\n|' + ' --- |' * len(detail_cols) + '\n')
        for r in detail_rows:
            f.write('| ' + ' | '.join(str(r[c]) for c in detail_cols) + ' |\n')


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else 'experiments/runtime-discovery/out'
    rows = []
    for run_dir in sorted(glob.glob(os.path.join(out_dir, '2[678]-root-*'))):
        rows.extend(rows_for_run(run_dir))
    rows.sort(key=lambda r: (r['case'], r['sync'] != 'startup', -r['window'], -r['interval'],
                              r['phase'], r['tag'], r['replicate'], r['variant'],
                              r['priority'], r['series'] != 'none', r['series']))

    detail_cols = ['run', 'case', 'sync', 'interval', 'window', 'phase', 'replicate', 'tag',
                   'variant', 'series', 'priority'] + list(NUMERIC_COLS) + ['vs_no_runtime_rank_changed']
    write_csv(os.path.join(out_dir, 'AGGREGATE-rank.csv'), rows, detail_cols)

    summary_rows = summarize(rows)
    summary_cols = ['case', 'sync', 'interval', 'window', 'phase', 'tag', 'variant', 'series',
                     'priority', 'replicates', 'consistent'] + list(NUMERIC_COLS)
    write_markdown(os.path.join(out_dir, 'AGGREGATE-rank.md'), rows, summary_rows, detail_cols, summary_cols)
    print(f'{len(rows)} detail rows, {len(summary_rows)} summary rows -> {out_dir}/AGGREGATE-rank.md')


if __name__ == '__main__':
    main()
