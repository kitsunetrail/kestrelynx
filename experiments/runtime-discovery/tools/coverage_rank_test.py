#!/usr/bin/env python3
"""Unit tests for coverage_rank.py's aggregation of match's G4 ranking
output against coverage.py's own S2 misses - small synthetic
match_all.json/coverage.json fixtures on disk, no real 30-run data. Run
with:

  python3 -m unittest discover -s tools -p 'coverage_rank_test.py'
  python3 tools/coverage_rank_test.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage_rank


def ranked(package, version, baseline_rank, adjusted_rank, rank_changed, class_='os'):
    return {'package': package, 'class': class_, 'installed_version': version, 'vuln_id': 'CVE-0',
            'baseline_rank': baseline_rank, 'adjusted_rank': adjusted_rank, 'rank_changed': rank_changed,
            'confirmed': False, 'exposure': 'unknown', 'high_privilege': False, 'labeled': False}


def g4(series, priority, total, top20, rank_changed_count=0, labeled_count=0, na=False):
    return {'series': series, 'priority': priority, 'na': na, 'total_findings': total,
            'top20': top20, 'rank_changed_count': rank_changed_count, 'labeled_count': labeled_count}


def pkg(name, version, priorities, class_='os'):
    return {'package': name, 'class': class_, 'installed_version': version, 'priorities': priorities}


def miss(name, version, cause='mapping_not_supported'):
    return {'ecosystem': 'os', 'name': name, 'version': version, 'cause': cause, 'detail': '', 'tags': []}


def false_positive(name, version):
    return {'ecosystem': 'os', 'name': name, 'version': version}


def write_run(tmp, run_name, match_all=None, match_hc=None, coverage=None):
    run_dir = os.path.join(tmp, run_name)
    os.makedirs(run_dir, exist_ok=True)
    if match_all is not None:
        with open(os.path.join(run_dir, 'match_all.json'), 'w') as f:
            json.dump(match_all, f)
    if match_hc is not None:
        with open(os.path.join(run_dir, 'match_hc.json'), 'w') as f:
            json.dump(match_hc, f)
    if coverage is not None:
        with open(os.path.join(run_dir, 'coverage.json'), 'w') as f:
            json.dump(coverage, f)
    return run_dir


RUN_NAME = '27-root-30-900-p0-r1-startup-nofilter512p'


class RowsForRunTests(unittest.TestCase):
    def test_basic_aggregation_with_a_missed_package_in_top20(self):
        # "curl" is a used, unconfirmed package: it is an S2 miss, it
        # carries one act_now Finding, and its own top20 row shows no
        # rank change (baseline == adjusted) - exactly the "runtime
        # evidence never promoted it" case this tool exists to surface.
        top20_s0 = [ranked('curl', '8.14.1', 3, 3, False), ranked('openssl', '3.0.15', 0, 0, True)]
        top20_s2 = [ranked('curl', '8.14.1', 3, 3, False), ranked('openssl', '3.0.15', 0, 0, True)]
        match_all = {
            'packages': [
                pkg('curl', '8.14.1', {'act_now': 1}),
                pkg('openssl', '3.0.15', {'act_now': 1}),
            ],
            'g4': [
                g4('S0', 'act_now', 2, top20_s0, rank_changed_count=1, labeled_count=0),
                g4('S2', 'act_now', 2, top20_s2, rank_changed_count=1, labeled_count=0),
            ],
        }
        coverage = {
            'all': {
                'categories': {
                    'resident_os': {
                        'series': {
                            'S0': {'misses': [miss('curl', '8.14.1')]},
                            'S1': {'misses': [miss('curl', '8.14.1')]},
                            'S2': {'misses': [miss('curl', '8.14.1')]},
                        },
                    },
                },
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)

        by_series = {(r['series'], r['priority']): r for r in rows if r['variant'] == 'all'}
        self.assertEqual(by_series[('none', 'act_now')]['missed_pkg_findings'], 1)
        self.assertEqual(by_series[('none', 'act_now')]['rank_changed_count'], 0)
        self.assertEqual(by_series[('none', 'act_now')]['false_promotions'], 'N/A')

        s0 = by_series[('S0', 'act_now')]
        self.assertEqual(s0['total_findings'], 2)
        self.assertEqual(s0['missed_pkg_findings'], 1)
        self.assertEqual(s0['missed_pkg_in_top20'], 1)
        self.assertEqual(s0['missed_pkg_rank_unchanged'], 1)  # curl: baseline(3) == adjusted(3)
        self.assertEqual(s0['missed_pkg_not_promoted'], 1)  # adjusted(3) >= baseline(3)
        self.assertEqual(s0['missed_pkg_outside_top20'], 0)
        self.assertEqual(s0['top20_promoted'], 0)  # openssl's adjusted(0) == baseline(0): not a promotion
        self.assertEqual(s0['false_promotions'], 0)

    def test_a_demoted_missed_package_counts_as_not_promoted_but_not_rank_unchanged(self):
        # A missed package whose
        # own Finding is DEMOTED (pushed to a later, numerically higher
        # rank by some other Finding's promotion) is not "rank unchanged"
        # (its adjusted rank differs from its baseline rank), but it was
        # certainly never promoted either - conflating the two would have
        # reported 0 "not promoted" for a Finding that plainly was not.
        top20 = [
            ranked('libgnutls30', '3.7.9', 1, 0, True, class_='os'),  # promoted past qs
            ranked('qs', '6.7.0', 0, 1, True, class_='lang'),  # demoted: baseline 0 -> adjusted 1
        ]
        match_all = {
            'packages': [pkg('libgnutls30', '3.7.9', {'act_now': 1}, class_='os'),
                         pkg('qs', '6.7.0', {'act_now': 1}, class_='lang')],
            'g4': [g4('S2', 'act_now', 2, top20, rank_changed_count=2, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'node': {'series': {
            'S2': {'misses': [miss('qs', '6.7.0')], 'false_positives': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'act_now')
        self.assertEqual(s2['missed_pkg_in_top20'], 1)
        self.assertEqual(s2['missed_pkg_rank_unchanged'], 0)
        self.assertEqual(s2['missed_pkg_not_promoted'], 1)
        self.assertEqual(s2['missed_pkg_outside_top20'], 0)

    def test_a_promoted_row_counts_as_top20_promoted(self):
        top20 = [ranked('openssl', '3.0.15', 5, 0, True)]  # moved from rank 5 to rank 0: promoted
        match_all = {
            'packages': [pkg('openssl', '3.0.15', {'watch': 1})],
            'g4': [g4('S0', 'watch', 1, top20, rank_changed_count=1, labeled_count=0),
                   g4('S2', 'watch', 1, top20, rank_changed_count=1, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S0': {'misses': []}, 'S1': {'misses': []}, 'S2': {'misses': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s0 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S0' and r['priority'] == 'watch')
        self.assertEqual(s0['top20_promoted'], 1)
        self.assertEqual(s0['missed_pkg_findings'], 0)
        self.assertEqual(s0['missed_pkg_in_top20'], 0)

    def test_na_priority_produces_a_zero_row_without_crashing(self):
        match_all = {
            'packages': [],
            'g4': [g4('S0', 'act_now', 0, [], na=True), g4('S2', 'act_now', 0, [], na=True)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S0': {'misses': []}, 'S1': {'misses': []}, 'S2': {'misses': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s0 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S0' and r['priority'] == 'act_now')
        self.assertEqual(s0['total_findings'], 0)
        self.assertEqual(s0['top20_promoted'], 0)
        self.assertEqual(s0['missed_pkg_in_top20'], 0)

    def test_priority_entirely_absent_from_g4_reports_baseline_as_na_and_no_series_rows(self):
        # g4 here only ever reports act_now - a run whose scan carries no
        # watch-priority Finding at all is a real possibility, and the
        # aggregator must not assume every priority is always present.
        match_all = {
            'packages': [],
            'g4': [g4('S0', 'act_now', 0, []), g4('S2', 'act_now', 0, [])],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S0': {'misses': []}, 'S1': {'misses': []}, 'S2': {'misses': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        watch_rows = [r for r in rows if r['variant'] == 'all' and r['priority'] == 'watch']
        self.assertEqual(len(watch_rows), 1)  # only the "none" reference row
        self.assertEqual(watch_rows[0]['series'], 'none')
        self.assertEqual(watch_rows[0]['total_findings'], 'N/A')
        self.assertEqual(watch_rows[0]['missed_pkg_findings'], 0)

    def test_missed_package_with_no_matching_packageverdict_counts_as_zero(self):
        # coverage.json names a miss whose (name, version) is not in
        # packages[] at all - the bundled package never got a
        # PackageVerdict from the scan, so there is no Finding to count.
        match_all = {'packages': [], 'g4': [g4('S0', 'act_now', 0, []), g4('S2', 'act_now', 0, [])]}
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S0': {'misses': [miss('ghost', '1.0')]},
            'S1': {'misses': [miss('ghost', '1.0')]},
            'S2': {'misses': [miss('ghost', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        none_row = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'none' and r['priority'] == 'act_now')
        self.assertEqual(none_row['missed_pkg_findings'], 0)

    def test_missed_package_outside_the_top_20_is_counted_but_not_ranked(self):
        # "curl" has a Finding coverage.json's own priorities say belongs
        # to act_now, but the g4 top20 for this run never mentions it at
        # all (it never made the cut) - g4 simply has no rank recorded
        # for it, and that has to show up as its own count rather than
        # silently being read as "unchanged" or "not promoted".
        top20 = [ranked('openssl', '3.0.15', 0, 0, False)]
        match_all = {
            'packages': [pkg('curl', '8.14.1', {'act_now': 1}), pkg('openssl', '3.0.15', {'act_now': 1})],
            'g4': [g4('S2', 'act_now', 2, top20, rank_changed_count=0, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [miss('curl', '8.14.1')], 'false_positives': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'act_now')
        self.assertEqual(s2['missed_pkg_findings'], 1)
        self.assertEqual(s2['missed_pkg_in_top20'], 0)
        self.assertEqual(s2['missed_pkg_rank_unchanged'], 0)
        self.assertEqual(s2['missed_pkg_not_promoted'], 0)
        self.assertEqual(s2['missed_pkg_outside_top20'], 1)

    def test_a_false_positive_package_promoted_into_top20_is_counted(self):
        # A
        # confirmed-but-actually-unused package (coverage.json's own
        # false_positives for this series) that computeG4's additional
        # rule lifted out of its baseline rank.
        top20 = [ranked('evil', '1.0', 5, 0, True)]  # promoted from rank 5 to rank 0
        match_all = {
            'packages': [pkg('evil', '1.0', {'watch': 1})],
            'g4': [g4('S2', 'watch', 1, top20, rank_changed_count=1, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': [false_positive('evil', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'watch')
        self.assertEqual(s2['false_promotions'], 1)

    def test_a_false_positive_package_not_promoted_is_not_counted(self):
        top20 = [ranked('evil', '1.0', 0, 0, False)]  # present, but never moved
        match_all = {
            'packages': [pkg('evil', '1.0', {'watch': 1})],
            'g4': [g4('S2', 'watch', 1, top20, rank_changed_count=0, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': [false_positive('evil', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'watch')
        self.assertEqual(s2['false_promotions'], 0)

    def test_a_false_positive_outside_top20_is_not_determinable(self):
        # "evil" is a false positive for this series, but its own Finding
        # never appears in the top 20 at all - whether it was promoted is
        # simply not something this run's g4 output can answer.
        top20 = [ranked('other', '1.0', 0, 0, False)]
        match_all = {
            'packages': [pkg('evil', '1.0', {'watch': 1}), pkg('other', '1.0', {'watch': 1})],
            'g4': [g4('S2', 'watch', 2, top20, rank_changed_count=0, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': [false_positive('evil', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'watch')
        self.assertEqual(s2['false_promotions'], 'N/A')

    def test_no_false_positives_at_all_is_a_confident_zero(self):
        top20 = [ranked('openssl', '3.0.15', 0, 0, False)]
        match_all = {
            'packages': [pkg('openssl', '3.0.15', {'watch': 1})],
            'g4': [g4('S2', 'watch', 1, top20, rank_changed_count=0, labeled_count=0)],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        s2 = next(r for r in rows if r['variant'] == 'all' and r['series'] == 'S2' and r['priority'] == 'watch')
        self.assertEqual(s2['false_promotions'], 0)

    def test_a_false_positive_with_only_watch_findings_never_blocks_act_now(self):
        # A false positive
        # ("evil") that carries only a watch Finding must not make the
        # OTHER bucket, act_now, read as unresolvable just because evil
        # is absent from act_now's own top 20 - it was never going to be
        # there since it holds no act_now Finding at all. act_now must
        # come out a confident 0. watch, where evil actually has a
        # Finding and was promoted, must come out 1.
        match_all = {
            'packages': [pkg('evil', '1.0', {'watch': 1}), pkg('other', '1.0', {'act_now': 1})],
            'g4': [
                g4('S2', 'act_now', 1, [ranked('other', '1.0', 0, 0, False)],
                   rank_changed_count=0, labeled_count=0),
                g4('S2', 'watch', 1, [ranked('evil', '1.0', 5, 0, True)],
                   rank_changed_count=1, labeled_count=0),
            ],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': [false_positive('evil', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        by_prio = {r['priority']: r for r in rows if r['variant'] == 'all' and r['series'] == 'S2'}
        self.assertEqual(by_prio['act_now']['false_promotions'], 0)
        self.assertEqual(by_prio['watch']['false_promotions'], 1)

    def test_a_watch_only_false_positive_missing_from_watchs_own_top20_is_na(self):
        # Same watch-only false positive as above, but this time its own
        # Finding never appears in watch's own top 20 either - genuinely
        # undeterminable, so watch itself must read 'N/A' (act_now is
        # unaffected either way, since evil never carried an act_now
        # Finding to begin with).
        match_all = {
            'packages': [pkg('evil', '1.0', {'watch': 1}), pkg('other', '1.0', {'act_now': 1, 'watch': 1})],
            'g4': [
                g4('S2', 'act_now', 1, [ranked('other', '1.0', 0, 0, False)],
                   rank_changed_count=0, labeled_count=0),
                g4('S2', 'watch', 1, [ranked('other', '1.0', 0, 0, False)],
                   rank_changed_count=0, labeled_count=0),
            ],
        }
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S2': {'misses': [], 'false_positives': [false_positive('evil', '1.0')]}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        by_prio = {r['priority']: r for r in rows if r['variant'] == 'all' and r['series'] == 'S2'}
        self.assertEqual(by_prio['act_now']['false_promotions'], 0)
        self.assertEqual(by_prio['watch']['false_promotions'], 'N/A')

    def test_hold_coverage_produces_no_rows(self):
        match_all = {'packages': [], 'g4': []}
        coverage = {'hold': 'no baseline', 'all': {}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        self.assertEqual(rows, [])

    def test_missing_coverage_json_produces_no_rows(self):
        match_all = {'packages': [], 'g4': []}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, RUN_NAME, match_all=match_all)
            rows = coverage_rank.rows_for_run(run_dir)
        self.assertEqual(rows, [])

    def test_unrecognized_run_directory_name_produces_no_rows(self):
        match_all = {'packages': [], 'g4': []}
        coverage = {'all': {'categories': {'resident_os': {'series': {
            'S0': {'misses': []}, 'S1': {'misses': []}, 'S2': {'misses': []}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_run(tmp, 'not-a-recognized-run-name', match_all=match_all, coverage=coverage)
            rows = coverage_rank.rows_for_run(run_dir)
        self.assertEqual(rows, [])


class SummarizeTests(unittest.TestCase):
    def _row(self, replicate, **overrides):
        base = {'run': f'r{replicate}', 'case': '27', 'sync': 'startup', 'interval': 30, 'window': 900,
                'phase': 0, 'replicate': replicate, 'tag': 'nofilter512p', 'variant': 'all', 'series': 'S0',
                'priority': 'act_now', 'total_findings': 2, 'rank_changed_count': 1, 'top20_promoted': 0,
                'labeled_count': 0, 'missed_pkg_findings': 1, 'missed_pkg_in_top20': 1,
                'missed_pkg_rank_unchanged': 1, 'missed_pkg_not_promoted': 1,
                'missed_pkg_outside_top20': 0, 'false_promotions': 0}
        base.update(overrides)
        return base

    def test_identical_replicates_are_consistent(self):
        rows = [self._row(1), self._row(2)]
        summary = coverage_rank.summarize(rows)
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]['consistent'], 'yes')
        self.assertEqual(summary[0]['replicates'], '1,2')
        self.assertEqual(summary[0]['total_findings'], 2)

    def test_differing_replicates_are_flagged_with_both_values(self):
        rows = [self._row(1), self._row(2, total_findings=3)]
        summary = coverage_rank.summarize(rows)
        self.assertEqual(summary[0]['consistent'], 'no')
        self.assertEqual(summary[0]['total_findings'], 'DIFFERS:2/3')
        # a column that DID agree stays a plain value, not swept into "no"
        self.assertEqual(summary[0]['rank_changed_count'], 1)


class HelperTests(unittest.TestCase):
    def test_collect_s2_misses_reads_only_the_s2_series(self):
        cov_variant = {'categories': {
            'a': {'series': {'S0': {'misses': [miss('x', '1')]}, 'S2': {'misses': [miss('y', '1')]}}},
            'b': {'series': {'S2': {'misses': [miss('z', '2')]}}},
        }}
        self.assertEqual(coverage_rank.collect_s2_misses(cov_variant), {('y', '1'), ('z', '2')})

    def test_missed_priority_counts_sums_across_matching_packages(self):
        idx = {('curl', '1'): [pkg('curl', '1', {'act_now': 2, 'watch': 1})]}
        counts = coverage_rank.missed_priority_counts({('curl', '1')}, idx)
        self.assertEqual(counts, {'act_now': 2, 'watch': 1})

    def test_g4_by_series_priority_indexes_every_entry(self):
        match_json = {'g4': [g4('S0', 'act_now', 1, []), g4('S2', 'watch', 5, [])]}
        idx = coverage_rank.g4_by_series_priority(match_json)
        self.assertEqual(set(idx), {('S0', 'act_now'), ('S2', 'watch')})


if __name__ == '__main__':
    unittest.main()
