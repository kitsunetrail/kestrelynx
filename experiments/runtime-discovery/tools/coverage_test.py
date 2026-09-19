#!/usr/bin/env python3
"""Unit tests for the pure functions in coverage.py: PackageVerdict-key
resolution (now three-part: ecosystem/name/version), confirmed-set
building, category assignment, the priority-ordered miss-cause
classifier, and the end-to-end compute() against small synthetic
match/truth structures - no Docker, no real match_hc.json/match_all.json.
Run with:

  python3 -m unittest discover -s tools -p 'coverage_test.py'
  python3 tools/coverage_test.py
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coverage


def pv(package, ecosystem, class_='lang', verdict='confirmed', s1=None, s2=None,
       factor='', s1_factor=None, s2_factor=None, observation_state='observed', version='1.0',
       confirmations=None):
    result = {
        'package': package, 'ecosystem': ecosystem, 'class': class_,
        'verdict': verdict, 's1_verdict': s1 or verdict, 's2_verdict': s2 or s1 or verdict,
        'factor': factor, 's1_factor': s1_factor if s1_factor is not None else factor,
        's2_factor': s2_factor if s2_factor is not None else (s1_factor if s1_factor is not None else factor),
        'observation_state': observation_state, 'installed_version': version,
    }
    if confirmations is not None:
        result['confirmations'] = confirmations
    return result


def used_entry(ecosystem, name, version, subjects=None, **extra):
    e = {'ecosystem': ecosystem, 'name': name, 'version': version, 'subjects': subjects or []}
    e.update(extra)
    return e


class ConfirmedKeyTests(unittest.TestCase):
    def test_python_name_is_pep503_normalized(self):
        key = coverage.confirmed_key(pv('Flask_Package', 'python-pkg', version='3.0.3'))
        self.assertEqual(key, ('python', 'flask-package', '3.0.3'))

    def test_os_ecosystem_maps_directly(self):
        key = coverage.confirmed_key(pv('curl', 'os', class_='os', version='8.14.1'))
        self.assertEqual(key, ('os', 'curl', '8.14.1'))

    def test_jar_maps_to_java(self):
        key = coverage.confirmed_key(pv('org.slf4j:slf4j-api', 'jar', version='2.0.13'))
        self.assertEqual(key, ('java', 'org.slf4j:slf4j-api', '2.0.13'))

    def test_unrecognized_ecosystem_without_os_class_is_out_of_scope(self):
        key = coverage.confirmed_key(pv('golang.org/x/text', 'gobinary'))
        self.assertIsNone(key)

    def test_missing_ecosystem_falls_back_to_class_os(self):
        key = coverage.confirmed_key({'package': 'libc6', 'class': 'os', 'verdict': 'confirmed',
                                       'installed_version': '2.41'})
        self.assertEqual(key, ('os', 'libc6', '2.41'))


class BuildConfirmedSetsTests(unittest.TestCase):
    def test_s0_s1_s2_progression(self):
        match_json = {'packages': [
            pv('requests', 'python-pkg', verdict='unobserved', s1='unobserved', s2='confirmed', version='2.32.3'),
            pv('flask', 'python-pkg', verdict='confirmed', version='3.0.3'),
        ]}
        sets, present = coverage.build_confirmed_sets(match_json)
        self.assertNotIn(('python', 'requests', '2.32.3'), sets['S0'])
        self.assertNotIn(('python', 'requests', '2.32.3'), sets['S1'])
        self.assertIn(('python', 'requests', '2.32.3'), sets['S2'])
        self.assertIn(('python', 'flask', '3.0.3'), sets['S0'])
        self.assertIn(('python', 'requests', '2.32.3'), present)

    def test_different_versions_of_the_same_name_are_distinct_keys(self):
        match_json = {'packages': [
            pv('ms', 'node-pkg', verdict='confirmed', version='2.1.3'),
        ]}
        sets, _present = coverage.build_confirmed_sets(match_json)
        self.assertIn(('node', 'ms', '2.1.3'), sets['S0'])
        self.assertNotIn(('node', 'ms', '2.0.0'), sets['S0'])


class CategoryAssignmentTests(unittest.TestCase):
    def test_os_used_with_both_subjects(self):
        entry = used_entry('os', 'libc6', '2.41', subjects=['resident', 'short_lived'])
        self.assertEqual(set(coverage.categories_for_used(entry)), {'resident_os', 'short_lived_os'})

    def test_os_used_short_lived_only(self):
        entry = used_entry('os', 'curl', '8.14.1', subjects=['short_lived'])
        self.assertEqual(coverage.categories_for_used(entry), ['short_lived_os'])

    def test_lang_used_is_its_own_ecosystem(self):
        entry = used_entry('python', 'flask', '3.0.3')
        self.assertEqual(coverage.categories_for_used(entry), ['python'])

    def test_os_unused_belongs_to_both_categories(self):
        entry = {'ecosystem': 'os', 'name': 'gzip', 'version': '1.0'}
        self.assertEqual(set(coverage.categories_for_unused(entry)), {'resident_os', 'short_lived_os'})

    def test_lang_unused_is_its_own_ecosystem(self):
        entry = {'ecosystem': 'java', 'name': 'com.google.guava:guava', 'version': '33.2.1-jre'}
        self.assertEqual(coverage.categories_for_unused(entry), ['java'])


class ClassifyMissTests(unittest.TestCase):
    def base_ctx(self, **overrides):
        ctx = {
            'window_start_rel': 0.0, 'window_end_rel': 300.0,
            'captured_paths': {}, 'failures': [], 'has_event_drops': False,
            'interval_seconds': 30, 'identified_loss_window': None,
            'measurement_op_intervals': {},
        }
        ctx.update(overrides)
        return ctx

    def test_used_before_window(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=-20.0, last_seen_s=-15.0)
        cause, _detail, tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, None, 'S2', self.base_ctx())
        self.assertEqual(cause, 'used_before_window')
        self.assertEqual(tags, [])

    def test_short_lived_use_only_applies_to_s0(self):
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 10, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['osops_curl'], subjects=['short_lived'])
        # 'paired': True is what makes this a genuine exec~exit span
        # (from THIS measurement run's own usage.jsonl) rather than a
        # merely-recorded operation timestamp - see
        # _measurement_retention_interval.
        intervals_raw = [{'op': 'osops_curl', 'start': op_start, 'end': op_start + timedelta(seconds=0.05),
                           'paired': True}]
        sample_times = [op_start - timedelta(seconds=5), op_start + timedelta(seconds=25)]
        ctx = self.base_ctx(measurement_intervals_raw=intervals_raw, sample_times=sample_times)
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry,
                                                          pv('curl', 'os', class_='os', verdict='unresolved'),
                                                          'S0', ctx)
        self.assertEqual(cause, 'short_lived_use')
        # The same package's S2 miss is not eligible for this cause at all.
        cause_s2, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry,
                                                             pv('curl', 'os', class_='os', verdict='unresolved'),
                                                             'S2', ctx)
        self.assertNotEqual(cause_s2, 'short_lived_use')

    def test_unpaired_osops_instance_is_not_used_as_retention(self):
        # 'paired': False means read_operation_intervals could not find
        # a genuine exec~exit pairing for this instance in usage.jsonl
        # at all (only a bare recorded timestamp) - using it as
        # retention would be exactly the same mistake as using a fixed
        # operation's own "load" span.
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 10, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['osops_curl'], subjects=['short_lived'])
        intervals_raw = [{'op': 'osops_curl', 'start': op_start, 'end': op_start + timedelta(seconds=0.05),
                           'paired': False}]
        sample_times = [op_start - timedelta(seconds=5), op_start + timedelta(seconds=25)]
        ctx = self.base_ctx(measurement_intervals_raw=intervals_raw, sample_times=sample_times)
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')
        self.assertIn('short_lived_use_candidate', tags)

    def test_mapping_not_supported_when_absent_from_scan(self):
        entry = used_entry('python', 'click', '8.1.7', first_seen_s=10.0, last_seen_s=200.0)
        cause, detail, _tags = coverage.classify_miss(('python', 'click', '8.1.7'), entry, None, 'S2', self.base_ctx())
        self.assertEqual(cause, 'mapping_not_supported')
        self.assertIn('scan', detail)

    def test_mapping_not_supported_when_event_captured_but_unconfirmed(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0,
                            paths=['/usr/local/lib/python3.12/site-packages/requests/__init__.py'])
        ctx = self.base_ctx(captured_paths={'/usr/local/lib/python3.12/site-packages/requests/__init__.py': [{}]})
        cause, _detail, _tags = coverage.classify_miss(
            ('python', 'requests', '2.32.3'), entry,
            pv('requests', 'python-pkg', verdict='unresolved'), 'S2', ctx)
        self.assertEqual(cause, 'mapping_not_supported')

    def test_mapping_not_supported_from_lang_pkg_factor(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0)
        present = pv('requests', 'python-pkg', verdict='unobserved', factor='lang_pkg_unmappable')
        cause, _detail, _tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, present, 'S2', self.base_ctx())
        self.assertEqual(cause, 'mapping_not_supported')

    def test_insufficient_permission_from_failure_step(self):
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=200.0, paths=['/usr/bin/curl'])
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        ctx = self.base_ctx(failures=[{'step': 'rootfs_denied', 'message': 'open /usr/bin/curl: permission denied'}])
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S2', ctx)
        self.assertEqual(cause, 'insufficient_permission')

    def test_proc_gone_failure_is_not_insufficient_permission(self):
        # ENOENT/ESRCH-equivalent (collect.go's own "proc_gone" step) must
        # never be read as a permission result.
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=200.0, paths=['/usr/bin/curl'])
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        ctx = self.base_ctx(failures=[{'step': 'proc_gone', 'message': 'open /usr/bin/curl: no such file or directory'}])
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S2', ctx)
        self.assertNotEqual(cause, 'insufficient_permission')
        self.assertEqual(cause, 'unknown')

    def test_other_cause_for_a_non_permission_non_not_found_failure(self):
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=200.0, paths=['/usr/bin/curl'])
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        ctx = self.base_ctx(failures=[{'step': 'aux_read_failed', 'message': 'read /usr/bin/curl: input/output error'}])
        cause, detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S2', ctx)
        self.assertEqual(cause, 'other')
        self.assertIn('input/output error', detail)

    def test_truth_side_retention_is_never_transplanted_onto_this_run(self):
        # The exact counterexample: truth's own retention was a mere
        # 50ms, but THIS measurement run's own events.jsonl shows a real
        # exec~exit span from 10s to 50s (40 real seconds) - and one of
        # this run's own actual samples landed at 30s, squarely inside
        # it. A sample genuinely could have caught it on THIS run; truth
        # side's own (much shorter) retention figure must not override
        # that.
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=10.05,
                            used_during_operations=['osops_curl'], exec_hold_seconds_min=0.05,
                            paths=['/usr/bin/curl'])
        events_by_pid = {
            (501, 99): [
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': op_start + timedelta(seconds=10.0)},
                {'event': 'exit', 'path': '/usr/bin/curl', 'ts_dt': op_start + timedelta(seconds=50.0)},
            ],
        }
        sample_times = [op_start, op_start + timedelta(seconds=30.0), op_start + timedelta(seconds=60.0)]
        ctx = self.base_ctx(events_by_pid=events_by_pid, sample_times=sample_times)
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')

    def test_no_retention_evidence_at_all_is_unknown_with_a_candidate_tag_not_short_lived_use(self):
        # No events.jsonl exec~exit/dlopen~dlclose pairing for any of
        # this package's own paths, AND no matching operation instance
        # on this measurement run to fall back to either: retention is
        # simply unknown on THIS run, never assumed short. Falls through
        # to "unknown", tagged as a candidate this cause could not
        # confirm one way or the other.
        entry = used_entry('python', 'sqlalchemy', '2.0.30', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['request_lazy_sqlalchemy'])
        ctx = self.base_ctx(measurement_op_intervals={}, sample_times=[])
        present = pv('sqlalchemy', 'python-pkg', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('python', 'sqlalchemy', '2.0.30'), entry, present, 'S0', ctx)
        self.assertEqual(cause, 'unknown')
        self.assertIn('short_lived_use_candidate', tags)

    def test_resident_lazy_load_operation_span_is_never_used_as_retention(self):
        # The exact counterexample: a 50ms "load" operation instance
        # (importing the module) says nothing about how long the loaded
        # library then stayed mapped in this RESIDENT process - which
        # keeps running long after the import statement itself returns.
        # No exec~exit/dlopen~dlclose pairing exists in this run's own
        # events.jsonl either (today's event schema does not emit exit/
        # dlclose at all), and this is not a short-lived subject to
        # begin with, so this run's own evidence simply cannot confirm a
        # retention interval - never short_lived_use, falls through to
        # "unknown" with the candidate tag.
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 10, 0, tzinfo=timezone.utc)
        entry = used_entry('python', 'sqlalchemy', '2.0.30', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['request_lazy_sqlalchemy'], subjects=['resident'])
        intervals_raw = [{'op': 'request_lazy_sqlalchemy', 'start': op_start,
                           'end': op_start + timedelta(seconds=0.05), 'paired': True}]
        sample_times = [op_start - timedelta(seconds=5), op_start + timedelta(seconds=25)]
        ctx = self.base_ctx(measurement_intervals_raw=intervals_raw, sample_times=sample_times)
        present = pv('sqlalchemy', 'python-pkg', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('python', 'sqlalchemy', '2.0.30'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')
        self.assertEqual(cause, 'unknown')
        self.assertIn('short_lived_use_candidate', tags)

    def test_events_jsonl_exec_exit_pairing_confirms_short_lived_use(self):
        # The preferred source over the operation-instance fallback: a
        # real exec~exit pairing from this run's own events.jsonl.
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 10, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['osops_curl'], paths=['/usr/bin/curl'])
        events_by_pid = {
            (501, 99): [
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': op_start},
                {'event': 'exit', 'path': '/usr/bin/curl', 'ts_dt': op_start + timedelta(seconds=0.05)},
            ],
        }
        sample_times = [op_start - timedelta(seconds=5), op_start + timedelta(seconds=25)]
        ctx = self.base_ctx(events_by_pid=events_by_pid, sample_times=sample_times)
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S0', ctx)
        self.assertEqual(cause, 'short_lived_use')

    def test_short_lived_use_requires_every_retention_interval_to_fit_not_just_the_first(self):
        # The exact counterexample: this package has TWO independent
        # retention intervals on this measurement run (opened by two
        # different processes) - a brief one (10s to 10.05s) that fits
        # cleanly between samples at 0s and 30s, and a much longer one
        # (20s to 40s) that a sample at 30s genuinely falls inside. A
        # verdict based on only the first interval found would wrongly
        # call this short_lived_use; every interval must fit, and the
        # ORDER they are enumerated in must not change the outcome.
        from datetime import datetime, timedelta, timezone
        base = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=40.0,
                            used_during_operations=['osops_curl'], paths=['/usr/bin/curl'])
        sample_times = [base, base + timedelta(seconds=30), base + timedelta(seconds=60)]

        def make_events(order):
            brief = [
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=10)},
                {'event': 'exit', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=10.05)},
            ]
            long = [
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=20)},
                {'event': 'exit', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=40)},
            ]
            pairs = [((501, 99), brief), ((502, 100), long)]
            if order == 'reversed':
                pairs = list(reversed(pairs))
            return dict(pairs)

        present = pv('curl', 'os', class_='os', verdict='unresolved')
        for order in ('forward', 'reversed'):
            with self.subTest(order=order):
                ctx = self.base_ctx(events_by_pid=make_events(order), sample_times=sample_times)
                cause, _detail, tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S0', ctx)
                self.assertNotEqual(cause, 'short_lived_use')

    def test_a_second_unclosed_load_by_the_same_process_is_not_hidden_by_the_first_loads_own_close(self):
        # The exact counterexample: the SAME (pid, starttime) events
        # group loads the package at 10s, closes it at 10.05s, then
        # loads it again at 20s with no closing event ever recorded at
        # all. Pairing "the earliest open" against "the earliest close
        # after it" globally (rather than sequentially, one load to one
        # close in order) would match 10s to 10.05s and simply never
        # notice the second, unclosed load at 20s - wrongly reporting
        # only the brief, cleanly-fitting first interval and calling
        # this short_lived_use. The second load must be recognized as a
        # genuine "held, unknown for how long" use of its own.
        from datetime import datetime, timedelta, timezone
        base = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=20.0,
                            used_during_operations=['osops_curl'], paths=['/usr/bin/curl'])
        events_by_pid = {
            (501, 99): [
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=10)},
                {'event': 'exit', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=10.05)},
                {'event': 'exec', 'path': '/usr/bin/curl', 'ts_dt': base + timedelta(seconds=20)},
                # No second exit recorded at all.
            ],
        }
        sample_times = [base, base + timedelta(seconds=15), base + timedelta(seconds=30)]
        ctx = self.base_ctx(events_by_pid=events_by_pid, sample_times=sample_times)
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')
        self.assertIn('short_lived_use_candidate', tags)

    def test_an_unrelated_paths_own_close_never_closes_this_paths_own_open(self):
        # The exact counterexample: a.so is loaded (dlopen) at 10s, and
        # an entirely UNRELATED library, b.so, is closed (dlclose) at
        # 10.05s by the same process. Pairing by "earliest open, next
        # close" without checking the path at all would wrongly treat
        # b.so's own close as though it closed a.so - a.so's own open
        # must stay unconfirmed (has_unconfirmed_use), never
        # short_lived_use.
        from datetime import datetime, timedelta, timezone
        base = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        entry = used_entry('python', 'a-lib', '1.0.0', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['request_lazy_a'], paths=['/lib/a.so'])
        events_by_pid = {
            (501, 99): [
                {'event': 'dlopen', 'path': '/lib/a.so', 'ts_dt': base + timedelta(seconds=10)},
                {'event': 'dlclose', 'path': '/lib/b.so', 'ts_dt': base + timedelta(seconds=10.05)},
            ],
        }
        sample_times = [base, base + timedelta(seconds=15), base + timedelta(seconds=30)]
        ctx = self.base_ctx(events_by_pid=events_by_pid, sample_times=sample_times)
        present = pv('a-lib', 'python-pkg', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('python', 'a-lib', '1.0.0'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')
        self.assertIn('short_lived_use_candidate', tags)

    def test_a_process_exit_closes_every_pending_path_at_once(self):
        # The counterpart to the above: an "exit" event (never a
        # dlclose) DOES legitimately close a.so's own still-pending
        # open, since the process exiting reclaims everything it held
        # regardless of path.
        from datetime import datetime, timedelta, timezone
        base = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        entry = used_entry('python', 'a-lib', '1.0.0', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['request_lazy_a'], paths=['/lib/a.so'])
        events_by_pid = {
            (501, 99): [
                {'event': 'dlopen', 'path': '/lib/a.so', 'ts_dt': base + timedelta(seconds=10)},
                {'event': 'exit', 'ts_dt': base + timedelta(seconds=10.05)},
            ],
        }
        sample_times = [base, base + timedelta(seconds=15), base + timedelta(seconds=30)]
        ctx = self.base_ctx(events_by_pid=events_by_pid, sample_times=sample_times)
        present = pv('a-lib', 'python-pkg', verdict='unresolved')
        cause, _detail, _tags = coverage.classify_miss(('python', 'a-lib', '1.0.0'), entry, present, 'S0', ctx)
        self.assertEqual(cause, 'short_lived_use')

    def test_retention_interval_spanning_a_sample_is_not_short_lived_use(self):
        # The genuine (paired) retention interval DOES straddle one of
        # this run's own actual sample times - a sample genuinely could
        # have caught it, so this is not explained by short_lived_use at
        # all.
        from datetime import datetime, timedelta, timezone
        op_start = datetime(2026, 9, 19, 3, 12, 10, 0, tzinfo=timezone.utc)
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=10.0, last_seen_s=10.0,
                            used_during_operations=['osops_curl'], subjects=['short_lived'])
        intervals_raw = [{'op': 'osops_curl', 'start': op_start, 'end': op_start + timedelta(seconds=10.0),
                           'paired': True}]
        # A sample lands 2 seconds into the 10-second retention window.
        sample_times = [op_start - timedelta(seconds=5), op_start + timedelta(seconds=2),
                         op_start + timedelta(seconds=25)]
        ctx = self.base_ctx(measurement_intervals_raw=intervals_raw, sample_times=sample_times)
        cause, _detail, tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry,
                                                         pv('curl', 'os', class_='os', verdict='unresolved'),
                                                         'S0', ctx)
        self.assertNotEqual(cause, 'short_lived_use')

    def test_used_before_window_does_not_apply_to_an_executed_image(self):
        # An executed image stays mapped for as long as the process that
        # ran it keeps running, so evidence entirely before the window
        # does not by itself mean it was gone by the time the window
        # opened.
        entry = used_entry('os', 'curl', '8.14.1', first_seen_s=-20.0, last_seen_s=-15.0,
                            evidence_types=['exec'], paths=['/usr/bin/curl'])
        present = pv('curl', 'os', class_='os', verdict='unresolved')
        cause, _detail, _tags = coverage.classify_miss(('os', 'curl', '8.14.1'), entry, present, 'S2', self.base_ctx())
        self.assertNotEqual(cause, 'used_before_window')

    def test_used_before_window_does_not_apply_to_a_shared_library(self):
        entry = used_entry('os', 'libssl3', '3.0.15', first_seen_s=-20.0, last_seen_s=-15.0,
                            paths=['/usr/lib/x86_64-linux-gnu/libssl.so.3'])
        present = pv('libssl3', 'os', class_='os', verdict='unresolved')
        cause, _detail, _tags = coverage.classify_miss(('os', 'libssl3', '3.0.15'), entry, present, 'S2', self.base_ctx())
        self.assertNotEqual(cause, 'used_before_window')

    def test_lost_events_promoted_when_a_gap_overlaps_the_packages_own_operation(self):
        from datetime import datetime, timezone
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0,
                            used_during_operations=['request_lazy_requests'])
        present = pv('requests', 'python-pkg', verdict='unresolved')
        gap = (datetime(2026, 9, 19, 3, 15, 0, tzinfo=timezone.utc),
               datetime(2026, 9, 19, 3, 15, 30, tzinfo=timezone.utc))
        op_intervals = {'request_lazy_requests': [(datetime(2026, 9, 19, 3, 15, 10, tzinfo=timezone.utc),
                                                     datetime(2026, 9, 19, 3, 15, 11, tzinfo=timezone.utc))]}
        ctx = self.base_ctx(has_event_drops=True, identified_loss_window=gap,
                             measurement_op_intervals=op_intervals)
        cause, detail, tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, present, 'S2', ctx)
        self.assertEqual(cause, 'lost_events')
        self.assertIn('03:15:00', detail)

    def test_lost_events_not_promoted_when_the_gap_does_not_overlap_this_packages_operation(self):
        from datetime import datetime, timezone
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0,
                            used_during_operations=['request_lazy_requests'])
        present = pv('requests', 'python-pkg', verdict='unresolved')
        gap = (datetime(2026, 9, 19, 3, 15, 0, tzinfo=timezone.utc),
               datetime(2026, 9, 19, 3, 15, 30, tzinfo=timezone.utc))
        # This package's own operation happened well before the gap.
        op_intervals = {'request_lazy_requests': [(datetime(2026, 9, 19, 3, 12, 0, tzinfo=timezone.utc),
                                                     datetime(2026, 9, 19, 3, 12, 1, tzinfo=timezone.utc))]}
        ctx = self.base_ctx(has_event_drops=True, identified_loss_window=gap,
                             measurement_op_intervals=op_intervals)
        cause, _detail, _tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, present, 'S2', ctx)
        self.assertNotEqual(cause, 'lost_events')

    def test_s0_never_uses_event_capture_for_the_mapping_gap_cause(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0,
                            paths=['/usr/local/lib/python3.12/site-packages/requests/__init__.py'])
        ctx = self.base_ctx(captured_paths={'/usr/local/lib/python3.12/site-packages/requests/__init__.py': [{}]})
        present = pv('requests', 'python-pkg', verdict='unresolved')
        cause_s0, _detail, _tags = coverage.classify_miss(
            ('python', 'requests', '2.32.3'), entry, present, 'S0', ctx)
        self.assertNotEqual(cause_s0, 'mapping_not_supported')
        cause_s2, _detail, _tags = coverage.classify_miss(
            ('python', 'requests', '2.32.3'), entry, present, 'S2', ctx)
        self.assertEqual(cause_s2, 'mapping_not_supported')

    def test_unknown_with_lost_events_tag(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0)
        present = pv('requests', 'python-pkg', verdict='unresolved')
        ctx = self.base_ctx(has_event_drops=True)
        cause, _detail, tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, present, 'S2', ctx)
        self.assertEqual(cause, 'unknown')
        self.assertEqual(tags, ['lost_events_candidate'])

    def test_unknown_without_lost_events_tag(self):
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=10.0, last_seen_s=200.0)
        present = pv('requests', 'python-pkg', verdict='unresolved')
        cause, _detail, tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, present, 'S2', self.base_ctx())
        self.assertEqual(cause, 'unknown')
        self.assertEqual(tags, [])

    def test_priority_before_window_wins_over_mapping_gap(self):
        # Even though this package is entirely absent from the scan
        # (which alone would be mapping_not_supported), it also never
        # appears inside the window at all, which takes priority.
        entry = used_entry('python', 'requests', '2.32.3', first_seen_s=-30.0, last_seen_s=-25.0)
        cause, _detail, _tags = coverage.classify_miss(('python', 'requests', '2.32.3'), entry, None, 'S2', self.base_ctx())
        self.assertEqual(cause, 'used_before_window')


class RestoreUnusedAfterRecomparisonTests(unittest.TestCase):
    def test_entry_blocked_only_by_operations_is_restored(self):
        truth = {
            'unused': [],
            'unknown': [
                {'ecosystem': 'python', 'name': 'pycparser', 'version': '2.22',
                 'reasons': ["no measurement run was given to compare this truth run's own firing "
                             'procedure against; N cannot be certified until one is (see coverage.py)']},
            ],
        }
        unused, unknown = coverage.restore_unused_after_recomparison(truth)
        self.assertEqual(len(unused), 1)
        self.assertEqual((unused[0]['ecosystem'], unused[0]['name'], unused[0]['version']),
                          ('python', 'pycparser', '2.22'))
        self.assertNotIn('reasons', unused[0])
        self.assertEqual(unknown, [])

    def test_entry_with_an_additional_completeness_gap_is_not_restored(self):
        truth = {
            'unused': [],
            'unknown': [
                {'ecosystem': 'python', 'name': 'six', 'version': '1.16.0',
                 'reasons': ["no measurement run was given to compare this truth run's own firing "
                             'procedure against; N cannot be certified until one is (see coverage.py)',
                             '1 trace file(s) carry no lines at all']},
            ],
        }
        unused, unknown = coverage.restore_unused_after_recomparison(truth)
        self.assertEqual(unused, [])
        self.assertEqual(len(unknown), 1)

    def test_entry_with_no_reasons_at_all_is_left_alone(self):
        truth = {'unused': [], 'unknown': [{'ecosystem': 'python', 'name': 'pytz', 'version': '2024.1'}]}
        unused, unknown = coverage.restore_unused_after_recomparison(truth)
        self.assertEqual(unused, [])
        self.assertEqual(len(unknown), 1)

    def test_inconsistent_reason_wording_is_also_restored(self):
        truth = {
            'unused': [],
            'unknown': [
                {'ecosystem': 'python', 'name': 'attrs', 'version': '23.2.0',
                 'reasons': ["this truth run's own firing procedure does not match the measurement run's"]},
            ],
        }
        unused, _unknown = coverage.restore_unused_after_recomparison(truth)
        self.assertEqual(len(unused), 1)

    def test_existing_unused_entries_are_kept_alongside_restored_ones(self):
        truth = {
            'unused': [{'ecosystem': 'python', 'name': 'tomli', 'version': '2.0.1'}],
            'unknown': [
                {'ecosystem': 'python', 'name': 'pycparser', 'version': '2.22',
                 'reasons': ['no measurement run was given to compare']},
            ],
        }
        unused, _unknown = coverage.restore_unused_after_recomparison(truth)
        names = {u['name'] for u in unused}
        self.assertEqual(names, {'tomli', 'pycparser'})


class ComputeEndToEndTests(unittest.TestCase):
    def _run_dir(self):
        tmp = tempfile.mkdtemp()
        return tmp

    def test_case26_like_input_restores_unused_and_computes_fpr_after_recomparison(self):
        # The scenario item 3 exists for: truth.py itself ran standalone
        # (no measurement run given at build time), so every one of its
        # own would-be-unused candidates was pushed into 'unknown' with
        # nothing but the operations-unchecked reason attached. Once
        # THIS run's own fresh re-comparison has succeeded (main()'s own
        # HOLD gate already confirmed this before calling compute() at
        # all), those candidates must come back as N so FPR is a real,
        # computed figure - not silently left at 0 unused/None forever.
        truth = {
            'used': [
                used_entry('python', 'flask', '3.0.3', first_seen_s=1.0, last_seen_s=2.0),
            ],
            'unused': [],
            'unknown': [
                {'ecosystem': 'python', 'name': 'pycparser', 'version': '2.22',
                 'reasons': ["no measurement run was given to compare this truth run's own firing "
                             'procedure against; N cannot be certified until one is (see coverage.py)']},
                {'ecosystem': 'python', 'name': 'six', 'version': '1.16.0',
                 'reasons': ["no measurement run was given to compare this truth run's own firing "
                             'procedure against; N cannot be certified until one is (see coverage.py)']},
            ],
        }
        match_json = {'packages': [
            pv('flask', 'python-pkg', verdict='confirmed', version='3.0.3'),
            # six is wrongly confirmed - a real false positive once six
            # comes back as N.
            pv('six', 'python-pkg', verdict='confirmed', version='1.16.0'),
        ], 'run_key': {'interval_seconds': 30}}
        run = self._run_dir()
        result = coverage.compute(run, match_json, truth, 'all')
        python_row = result['categories']['python']
        self.assertEqual(python_row['unused_count'], 2)
        s2 = python_row['series']['S2']
        self.assertIsNotNone(s2['fpr'])
        self.assertEqual(s2['fp'], 1)  # six
        self.assertEqual(s2['tn'], 1)  # pycparser

    def test_recall_fp_and_identification_gap(self):
        truth = {
            'used': [
                used_entry('python', 'flask', '3.0.3', first_seen_s=1.0, last_seen_s=2.0),
                used_entry('python', 'requests', '2.32.3', first_seen_s=1.0, last_seen_s=2.0),
                used_entry('os', 'curl', '8.14.1', subjects=['short_lived'], first_seen_s=1.0, last_seen_s=1.0),
            ],
            'unused': [
                {'ecosystem': 'python', 'name': 'pycparser', 'version': '2.22'},
            ],
        }
        match_json = {'packages': [
            pv('flask', 'python-pkg', verdict='confirmed', version='3.0.3'),
            pv('requests', 'python-pkg', verdict='unobserved', s1='unobserved', s2='unobserved', version='2.32.3'),
            pv('curl', 'os', class_='os', verdict='confirmed', version='8.14.1',
               confirmations=[{'source': 'event_exec', 'path': '/usr/bin/curl',
                                'process_generation': {'pid': 501, 'starttime': '99'}}]),
            # a package the scan confirms that is outside the bundled inventory entirely:
            pv('unexpected-pkg', 'python-pkg', verdict='confirmed', version='9.9.9'),
        ], 'run_key': {'interval_seconds': 30}}
        run = self._run_dir()
        result = coverage.compute(run, match_json, truth, 'all')
        python_row = result['categories']['python']
        self.assertEqual(python_row['used_count'], 2)
        s2 = python_row['series']['S2']
        self.assertEqual(s2['tp'], 1)  # flask
        self.assertEqual(s2['fn'], 1)  # requests: present but never confirmed at S2
        self.assertEqual(s2['recall'], 0.5)
        self.assertEqual(s2['fp'], 0)  # pycparser never confirmed
        short_lived_row = result['categories']['short_lived_os']
        self.assertEqual(short_lived_row['series']['S2']['tp'], 1)
        self.assertEqual(short_lived_row['series']['S2']['short_lived_direct_confirmations'], 1)
        idmis = result['identification_misconfirmations']['S2']
        self.assertEqual(len(idmis), 1)
        self.assertEqual((idmis[0]['ecosystem'], idmis[0]['name'], idmis[0]['version']),
                          ('python', 'unexpected-pkg', '9.9.9'))

    def test_misattributed_version_produces_fp_for_wrong_and_fn_for_right(self):
        # Two different bundled versions of "ms": 2.1.3 is genuinely used,
        # 2.0.0 is genuinely unused. match confirms 2.0.0 (the unused
        # copy) and never confirms 2.1.3 at all - the conditional
        # misattribution rule this is meant to cover falls straight out
        # of exact (ecosystem, name, version) matching.
        truth = {
            'used': [used_entry('node', 'ms', '2.1.3', first_seen_s=1.0, last_seen_s=2.0)],
            'unused': [{'ecosystem': 'node', 'name': 'ms', 'version': '2.0.0'}],
        }
        match_json = {'packages': [
            pv('ms', 'node-pkg', verdict='confirmed', version='2.0.0'),
        ], 'run_key': {'interval_seconds': 30}}
        result = coverage.compute(self._run_dir(), match_json, truth, 'all')
        node_row = result['categories']['node']['series']['S2']
        self.assertEqual(node_row['tp'], 0)
        self.assertEqual(node_row['fn'], 1)  # ms@2.1.3 never confirmed
        self.assertEqual(node_row['fp'], 1)  # ms@2.0.0 (unused) confirmed
        self.assertEqual(result['identification_misconfirmations']['S2'], [])

    def test_misattributed_version_that_is_also_used_is_a_true_positive(self):
        # Both versions of "ms" are genuinely used; match happens to
        # confirm only the 2.0.0 entry. That is a true positive for
        # 2.0.0 and a false negative for 2.1.3, not a false positive.
        truth = {
            'used': [
                used_entry('node', 'ms', '2.1.3', first_seen_s=1.0, last_seen_s=2.0),
                used_entry('node', 'ms', '2.0.0', first_seen_s=1.0, last_seen_s=2.0),
            ],
            'unused': [],
        }
        match_json = {'packages': [
            pv('ms', 'node-pkg', verdict='confirmed', version='2.0.0'),
        ], 'run_key': {'interval_seconds': 30}}
        result = coverage.compute(self._run_dir(), match_json, truth, 'all')
        node_row = result['categories']['node']['series']['S2']
        self.assertEqual(node_row['tp'], 1)
        self.assertEqual(node_row['fn'], 1)
        self.assertEqual(node_row['fp'], 0)

    def test_miss_cause_counts_sum_to_fn(self):
        truth = {
            'used': [
                used_entry('python', 'a', '1.0', first_seen_s=-30.0, last_seen_s=-29.0),  # before window
                used_entry('python', 'b', '1.0', first_seen_s=1.0, last_seen_s=2.0),  # mapping gap (absent)
                used_entry('python', 'c', '1.0'),  # untimed, absent from scan -> mapping gap
            ],
            'unused': [],
        }
        result = coverage.compute(self._run_dir(), {'packages': [], 'run_key': {'interval_seconds': 30}}, truth, 'all')
        s2 = result['categories']['python']['series']['S2']
        self.assertEqual(sum(s2['miss_cause_counts'].values()), s2['fn'])
        self.assertEqual(s2['fn'], 3)

    def test_empty_used_or_unused_is_na_not_zero(self):
        truth = {'used': [], 'unused': []}
        result = coverage.compute(self._run_dir(), {'packages': []}, truth, 'all')
        self.assertEqual(result['categories'], {})

    def test_operation_consistency_output_is_the_fresh_result_never_truths_own_saved_one(self):
        # truth.json's own saved operation_consistency claims consistent
        # (as if verified against some other, or its own, measurement
        # run) - compute()'s own output must show whatever THIS run's
        # own fresh re-comparison (ops_result, from
        # check_operations_consistent) actually found, never that saved
        # value.
        truth = {
            'used': [], 'unused': [],
            'operation_consistency': {'checked': True, 'consistent': True,
                                       'measurement_run': '/some/unrelated/old/run'},
        }
        fresh_result = {'checked': True, 'consistent': True, 'measurement_run': '/this/actual/run',
                         'detail': 'fixed sequence matches'}
        result = coverage.compute(self._run_dir(), {'packages': []}, truth, 'all', fresh_result)
        self.assertEqual(result['operation_consistency'], fresh_result)
        self.assertNotEqual(result['operation_consistency'], truth['operation_consistency'])

    def test_confirmation_of_an_x_entry_is_not_an_identification_misconfirmation(self):
        # pytz is in truth's own "unknown" (X) list - part of the ledger
        # I = U ∪ N ∪ X, just not resolved either way. Confirming it is
        # a "confirmed_in_x" outcome, not "confirmed something outside
        # the ledger entirely" (identification_misconfirmations), which
        # is reserved for a key I has no record of whatsoever.
        truth = {
            'used': [], 'unused': [],
            'unknown': [{'ecosystem': 'python', 'name': 'pytz', 'version': '2024.1'}],
        }
        match_json = {'packages': [pv('pytz', 'python-pkg', verdict='confirmed', version='2024.1')],
                      'run_key': {'interval_seconds': 30}}
        result = coverage.compute(self._run_dir(), match_json, truth, 'all')
        self.assertEqual(result['identification_misconfirmations']['S2'], [])
        confirmed_in_x = result['confirmed_in_x']['S2']
        self.assertEqual(len(confirmed_in_x), 1)
        self.assertEqual((confirmed_in_x[0]['ecosystem'], confirmed_in_x[0]['name'], confirmed_in_x[0]['version']),
                          ('python', 'pytz', '2024.1'))

    def test_confirmation_truly_outside_the_ledger_is_still_an_identification_misconfirmation(self):
        truth = {'used': [], 'unused': [], 'unknown': []}
        match_json = {'packages': [pv('unexpected-pkg', 'python-pkg', verdict='confirmed', version='9.9.9')],
                      'run_key': {'interval_seconds': 30}}
        result = coverage.compute(self._run_dir(), match_json, truth, 'all')
        self.assertEqual(len(result['identification_misconfirmations']['S2']), 1)
        self.assertEqual(result['confirmed_in_x']['S2'], [])


class ReadSampleProcessIndexTests(unittest.TestCase):
    def _write_obs(self, tmp, processes):
        os.makedirs(os.path.join(tmp, 'collect'))
        with open(os.path.join(tmp, 'collect', 'obs.json'), 'w') as f:
            json.dump({'window': {}, 'processes': processes}, f)

    def test_a_valid_resident_process_and_an_invalid_one_sharing_a_library_are_not_conflated(self):
        # match.go's own buildReadOutcomes skips a process record marked
        # invalid entirely (its own generation identity could not be
        # confirmed stable across the sample) - this reader must apply
        # the same rule, or an invalid, possibly mixed-generation curl
        # record could get credited as the subject for a library a
        # genuinely resident, valid server process also has mapped.
        with tempfile.TemporaryDirectory() as tmp:
            self._write_obs(tmp, [
                {'sample_id': 's0', 'exe': '/usr/local/bin/python3', 'invalid': False,
                 'maps': [{'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}]},
                {'sample_id': 's0', 'exe': '/usr/bin/curl', 'invalid': True,
                 'maps': [{'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}]},
            ])
            index = coverage.read_sample_process_index(tmp)
            self.assertEqual(index[('s0', '/usr/lib/x86_64-linux-gnu/libssl.so.3')], {'python3'})

    def test_exe_error_excludes_the_process_entirely(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_obs(tmp, [
                {'sample_id': 's0', 'exe': '/usr/bin/curl', 'exe_error': 'ESRCH',
                 'maps': [{'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}]},
            ])
            index = coverage.read_sample_process_index(tmp)
            self.assertEqual(index, {})

    def test_maps_error_excludes_only_the_maps_half(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_obs(tmp, [
                {'sample_id': 's0', 'exe': '/usr/bin/curl', 'maps_error': 'EACCES',
                 'maps': [{'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}]},
            ])
            index = coverage.read_sample_process_index(tmp)
            self.assertEqual(index, {('s0', '/usr/bin/curl'): {'curl'}})


class ShortLivedSubjectForSeriesTests(unittest.TestCase):
    def test_s0_credits_curl_via_its_own_sampling_confirmations_subject_not_its_name(self):
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'sampling', 'sample_id': 's3', 'path': '/usr/bin/curl'}])
        sample_process_index = {('s3', '/usr/bin/curl'): {'curl'}}
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S0', {}, True, sample_process_index))
        # A key never actually confirmed by S0 (sampling) at all must
        # not be credited with P just because pv happens to carry a
        # sampling confirmation.
        self.assertFalse(coverage.short_lived_subject_for_series(p, 'S0', {}, False, sample_process_index))

    def test_s0_credits_a_shared_library_when_its_sampling_confirmation_resolves_to_a_short_lived_process(self):
        # The exact case a name-only check could never handle: libssl3
        # is not itself named after a short-lived command, but THIS
        # run's own sample found it mapped by a curl process at the
        # confirming sample - a genuine, subject-resolved P
        # confirmation, cumulative across every series.
        p = pv('libssl3', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'sampling', 'sample_id': 's4',
                                'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}])
        sample_process_index = {('s4', '/usr/lib/x86_64-linux-gnu/libssl.so.3'): {'curl'}}
        self.assertEqual(coverage.short_lived_subject_for_series(p, 'S0', {}, True, sample_process_index), True)
        self.assertEqual(coverage.short_lived_subject_for_series(p, 'S1', {}, True, sample_process_index), True)
        self.assertEqual(coverage.short_lived_subject_for_series(p, 'S2', {}, True, sample_process_index), True)

    def test_shared_library_sampling_confirmation_resolved_to_a_resident_process_is_not_credited(self):
        p = pv('libssl3', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'sampling', 'sample_id': 's4',
                                'path': '/usr/lib/x86_64-linux-gnu/libssl.so.3'}])
        sample_process_index = {('s4', '/usr/lib/x86_64-linux-gnu/libssl.so.3'): {'python3'}}
        self.assertFalse(coverage.short_lived_subject_for_series(p, 'S0', {}, True, sample_process_index))

    def test_s1_never_credits_an_event_sourced_confirmation(self):
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'event_exec', 'path': '/usr/bin/curl'}])
        self.assertFalse(coverage.short_lived_subject_for_series(p, 'S1', {}, False, {}))

    def test_s1_credits_source_a_confirmation_with_a_resolvable_subject(self):
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'os_package_path_index', 'path': '/usr/bin/curl',
                                'process_generation': {'pid': 501, 'starttime': 99}}])
        events_index = {(501, 99, '/usr/bin/curl'): '/usr/bin/curl'}
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S1', events_index, False, {}))

    def test_s1_does_not_credit_when_subject_cannot_be_resolved(self):
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'os_package_path_index', 'path': '/usr/bin/curl',
                                'process_generation': {'pid': 501, 'starttime': 99}}])
        self.assertFalse(coverage.short_lived_subject_for_series(p, 'S1', {}, False, {}))

    def test_s2_credits_event_sourced_confirmation(self):
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'event_exec', 'path': '/usr/bin/curl'}])
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S2', {}, False, {}))

    def test_cumulative_across_series_for_the_same_s0_confirmation(self):
        # The design's own requirement: the same sampling-based
        # confirmation must count toward every series it is a part of
        # (S0 = P, S1 = P union A, S2 = P union A union E), not be
        # exclusive to S0 alone.
        p = pv('curl', 'os', class_='os', verdict='confirmed',
               confirmations=[{'source': 'sampling', 'sample_id': 's3', 'path': '/usr/bin/curl'}])
        sample_process_index = {('s3', '/usr/bin/curl'): {'curl'}}
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S0', {}, True, sample_process_index))
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S1', {}, True, sample_process_index))
        self.assertTrue(coverage.short_lived_subject_for_series(p, 'S2', {}, True, sample_process_index))


class WindowOperationSetsTests(unittest.TestCase):
    def _interval(self, op, start, end):
        return {'op': op, 'start': start, 'end': end}

    def test_fully_contained_interval_is_in_window(self):
        from datetime import datetime, timezone
        ws = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
        intervals = [self._interval('op_a', datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
                                     datetime(2026, 1, 1, 0, 1, 5, tzinfo=timezone.utc))]
        inside, straddling, seen = coverage.build_window_operation_sets(intervals, ws, we)
        self.assertEqual(inside, {'op_a'})
        self.assertEqual(straddling, set())
        self.assertEqual(seen, {'op_a'})

    def test_boundary_straddling_interval_is_excluded_from_in_window(self):
        from datetime import datetime, timezone
        ws = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
        intervals = [self._interval('op_b', datetime(2026, 1, 1, 0, 4, 59, tzinfo=timezone.utc),
                                     datetime(2026, 1, 1, 0, 5, 30, tzinfo=timezone.utc))]
        inside, straddling, seen = coverage.build_window_operation_sets(intervals, ws, we)
        self.assertEqual(inside, set())
        self.assertEqual(straddling, {'op_b'})

    def test_an_operation_with_both_a_clean_and_a_straddling_instance_is_in_window(self):
        from datetime import datetime, timezone
        ws = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
        intervals = [
            self._interval('osops_curl', datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
                            datetime(2026, 1, 1, 0, 1, 1, tzinfo=timezone.utc)),
            self._interval('osops_curl', datetime(2026, 1, 1, 0, 4, 59, tzinfo=timezone.utc),
                            datetime(2026, 1, 1, 0, 5, 30, tzinfo=timezone.utc)),
        ]
        inside, straddling, _seen = coverage.build_window_operation_sets(intervals, ws, we)
        self.assertEqual(inside, {'osops_curl'})
        self.assertEqual(straddling, set())  # not "straddling_only": a clean instance exists too

    def test_wholly_outside_interval_is_neither_in_window_nor_straddling(self):
        from datetime import datetime, timezone
        ws = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)
        intervals = [self._interval('op_c', datetime(2026, 1, 1, 0, 10, 0, tzinfo=timezone.utc),
                                     datetime(2026, 1, 1, 0, 10, 1, tzinfo=timezone.utc))]
        inside, straddling, seen = coverage.build_window_operation_sets(intervals, ws, we)
        self.assertEqual(inside, set())
        self.assertEqual(straddling, set())
        self.assertEqual(seen, {'op_c'})


class WindowMembershipTests(unittest.TestCase):
    def test_used_at_startup_without_persistence_evidence_is_not_unconditionally_u_window(self):
        # flask's own module file is neither executed nor a shared
        # library; startup use alone, with no operation evidence either,
        # does not confirm it was still in play once the window opened.
        entry = used_entry('python', 'flask', '3.0.3', used_at_startup=True, used_during_operations=[])
        self.assertEqual(coverage.window_membership(entry, set(), set(), set()), 'x_window')

    def test_used_at_startup_with_persistence_evidence_is_u_window(self):
        # The resident process's own executable stays mapped for as
        # long as it keeps running - startup use of it counts toward
        # U_window even with no separate operation evidence at all.
        entry = used_entry('os', 'python3', '3.12.3', used_at_startup=True, used_during_operations=[],
                            evidence_types=['exec'], paths=['/usr/local/bin/python3'])
        self.assertEqual(coverage.window_membership(entry, set(), set(), set()), 'u_window')

    def test_startup_use_of_a_shared_library_is_u_window(self):
        entry = used_entry('os', 'libssl3', '3.0.15', used_at_startup=True, used_during_operations=[],
                            paths=['/usr/lib/x86_64-linux-gnu/libssl.so.3'])
        self.assertEqual(coverage.window_membership(entry, set(), set(), set()), 'u_window')

    def test_operation_confirmed_in_window_is_u_window(self):
        entry = used_entry('python', 'requests', '2.32.3', used_at_startup=False,
                            used_during_operations=['request_lazy_requests'])
        result = coverage.window_membership(entry, {'request_lazy_requests'}, set(), {'request_lazy_requests'})
        self.assertEqual(result, 'u_window')

    def test_operation_only_seen_straddling_is_x_window(self):
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'])
        result = coverage.window_membership(entry, set(), {'osops_curl'}, {'osops_curl'})
        self.assertEqual(result, 'x_window')

    def test_operation_never_recorded_by_measurement_run_is_x_window(self):
        entry = used_entry('python', 'yaml', '6.0.1', used_at_startup=False,
                            used_during_operations=['request_lazy_yaml'])
        result = coverage.window_membership(entry, set(), set(), set())
        self.assertEqual(result, 'x_window')

    def test_operation_cleanly_outside_window_with_no_ambiguity_is_n_window(self):
        entry = used_entry('python', 'requests', '2.32.3', used_at_startup=False,
                            used_during_operations=['request_lazy_requests'])
        # measurement_seen_ops includes it (this run did record it), just
        # not in o_window and not in straddling_only either: a clean,
        # confirmed "not in this window" result.
        result = coverage.window_membership(entry, set(), set(), {'request_lazy_requests'})
        self.assertEqual(result, 'n_window')

    def test_no_evidence_at_all_is_x_window_not_a_confirmed_negative(self):
        # No operation evidence, and startup use (if any) does not
        # persist: this run's own evidence simply has nothing to place
        # the package's use against within the window, which is
        # unresolved, never a confirmed N_window.
        entry = used_entry('python', 'flask', '3.0.3', used_at_startup=False, used_during_operations=[])
        self.assertEqual(coverage.window_membership(entry, set(), set(), set()), 'x_window')

    def test_one_ambiguous_operation_among_several_clean_ones_is_still_x_window(self):
        # This package was used during two different operations: one
        # this run confirmed cleanly outside the window, and one this
        # run only ever saw straddling the boundary. The clean operation
        # alone is not enough to call this a confirmed N_window - the
        # straddling one could still be where in-window use happened, so
        # even a single remaining ambiguous candidate must leave the
        # whole package unresolved.
        entry = used_entry('python', 'requests', '2.32.3', used_at_startup=False,
                            used_during_operations=['request_lazy_requests', 'osops_curl'])
        result = coverage.window_membership(
            entry, set(), {'osops_curl'}, {'request_lazy_requests', 'osops_curl'})
        self.assertEqual(result, 'x_window')


class WindowScopedEndToEndTests(unittest.TestCase):
    """Exercises compute()'s window-scoped scoring against a synthetic
    measurement-run directory under testdata/ built in the shape a real
    case-run.sh run leaves (an observation JSON's window, a
    <case>.operations.jsonl/occurrences.jsonl/usage.jsonl trio, an
    events.jsonl, and a match_all.json) - root privileges are not needed
    to build one by hand, unlike a real measurement run."""

    RUN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata', '26-window-scoring')

    def setUp(self):
        self.truth = json.load(open(os.path.join(self.RUN, 'truth.json')))
        self.match_all = json.load(open(os.path.join(self.RUN, 'match_all.json')))
        self.result = coverage.compute(self.RUN, self.match_all, self.truth, 'all')

    def test_o_window_and_excluded_operations(self):
        ws = self.result['window_scoped']
        self.assertTrue(ws['available'])
        self.assertEqual(set(ws['operations_in_window']), {'osops_curl', 'request_lazy_requests'})
        self.assertEqual(set(ws['operations_excluded']), {'request_lazy_sqlalchemy', 'request_lazy_yaml'})

    def test_python_window_scoped_counts(self):
        w = self.result['categories']['python']['series']['S2']['window']
        # flask is used at startup, but its own fixture evidence is a
        # plain module-file open (no "exec" evidence type, no .so path)
        # - not the kind that persists into the window on its own, and
        # it carries no operation evidence either, so it no longer
        # qualifies for U_window unconditionally; only requests
        # (confirmed operation inside the window) does. Both flask and
        # requests are confirmed at S2, so TP=1 (requests), and flask's
        # own confirmation now shows up under confirmed_in_x_window
        # instead.
        self.assertEqual(w['u_window'], 1)
        self.assertEqual(w['tp'], 1)
        self.assertEqual(w['fn'], 0)
        self.assertEqual(w['recall'], 1.0)
        # flask, sqlalchemy (used only during an operation this
        # measurement run saw straddling the window boundary), and
        # pyyaml (used only during an operation this measurement run
        # never recorded at all) are all X_window, alongside pytz
        # (already X globally). flask is confirmed at S2 (the one
        # package here that is both X_window and confirmed).
        self.assertEqual(w['x_window'], 4)
        self.assertEqual(w['confirmed_in_x_window'], 1)
        # cryptography is genuinely used (globally a true positive) but
        # only during an operation this run's own window-scoped evidence
        # places entirely before the window opened, with no ambiguity -
        # so it is N_window, and match still confirming it at S2 is a
        # window-scoped false positive, alongside six (a true negative).
        self.assertEqual(w['n_window'], 2)
        self.assertEqual(w['fp'], 1)
        self.assertEqual(w['tn'], 1)
        self.assertEqual(w['fpr'], 0.5)

    def test_short_lived_os_window_scoped_counts_and_direct_confirmation(self):
        row = self.result['categories']['short_lived_os']['series']['S2']
        w = row['window']
        # curl was used during osops_curl, which this measurement run's
        # own window-scoped evidence shows completing inside the window.
        self.assertEqual(w['u_window'], 1)
        self.assertEqual(w['tp'], 1)
        self.assertEqual(w['recall'], 1.0)
        # The direct-confirmation count is built from match's own
        # confirmations (an event_exec of /usr/bin/curl itself), never
        # from truth's own subject label.
        self.assertEqual(row['short_lived_direct_confirmations'], 1)

    def test_main_scoping_uses_what_this_measurement_run_actually_ran(self):
        # The PRIMARY figure is scored against what THIS measurement
        # run's own operations.jsonl recorded, not truth's whole-run
        # life span: sqlalchemy's own operation (request_lazy_sqlalchemy)
        # was recorded by this run, but only a straddling instance (this
        # run's own window closed in the middle of it) with no retention
        # evidence for sqlalchemy itself (a plain module-file open, no
        # held_evidence) - unresolved which side of the cutoff its own
        # use fell on, so it is excluded from U/N entirely (X_main) the
        # same as pyyaml's own operation (request_lazy_yaml), which this
        # run never recorded at all - neither is counted as a miss this
        # run never had the opportunity to make.
        s2 = self.result['categories']['python']['series']['S2']
        self.assertEqual(s2['tp'], 3)  # flask, requests, cryptography
        self.assertEqual(s2['fn'], 0)  # sqlalchemy and pyyaml are both X_main
        self.assertEqual(s2['x_main_confirmed'], 0)
        self.assertTrue(self.result['main_scoping']['available'])

    def test_row_used_count_reflects_main_scoping(self):
        # used_count now reflects U_main (3: flask, requests,
        # cryptography), not truth's raw 5 (which also includes
        # sqlalchemy and pyyaml).
        row = self.result['categories']['python']
        self.assertEqual(row['used_count'], 3)
        self.assertEqual(row['x_main_count'], 3)  # sqlalchemy + pyyaml + pytz (truth X)


class MainMembershipTests(unittest.TestCase):
    def setUp(self):
        from datetime import datetime, timezone
        self.fired_at = datetime(2026, 9, 19, 3, 12, 0, tzinfo=timezone.utc)
        self.window_end = self.fired_at + timedelta(seconds=300.0)

    def _at(self, rel_s):
        return self.fired_at + timedelta(seconds=rel_s)

    def test_used_at_startup_is_u_main_regardless_of_operations(self):
        entry = used_entry('python', 'flask', '3.0.3', used_at_startup=True, used_during_operations=[])
        self.assertEqual(coverage.main_membership(entry, set(), set(), {}, self.window_end), 'u_main')

    def test_operation_completed_by_cutoff_is_u_main_even_if_not_in_window(self):
        entry = used_entry('python', 'requests', '2.32.3', used_at_startup=False,
                            used_during_operations=['request_lazy_requests'])
        self.assertEqual(
            coverage.main_membership(entry, {'request_lazy_requests'}, set(), {}, self.window_end), 'u_main')

    def test_operation_never_recorded_is_x_main(self):
        entry = used_entry('python', 'yaml', '6.0.1', used_at_startup=False,
                            used_during_operations=['request_lazy_yaml'])
        self.assertEqual(coverage.main_membership(entry, set(), set(), {}, self.window_end), 'x_main')

    def test_no_operation_evidence_at_all_is_x_main_not_a_confirmed_negative(self):
        # truth.py's own attribute_evidence could not place this
        # package's timed evidence at startup or against any operation
        # at all (post-stop-only, or otherwise unattributed): a real
        # usage signal it could not pin to a period, which is
        # unresolved for this run, never a confirmed non-use.
        entry = used_entry('python', 'flask', '3.0.3', used_at_startup=False, used_during_operations=[])
        self.assertEqual(coverage.main_membership(entry, set(), set(), {}, self.window_end), 'x_main')

    def test_straddling_operation_without_retention_evidence_is_x_main(self):
        # The operation started before this run's own window closed, but
        # this run's own window-scoped evidence shows it still running
        # past the cutoff - whether THIS package's own use fell before or
        # after the cutoff is unresolved without independent retention
        # evidence, so it must not be counted as a confirmed opportunity.
        entry = used_entry('python', 'sqlalchemy', '2.0.30', used_at_startup=False,
                            used_during_operations=['request_lazy_sqlalchemy'],
                            evidence_types=['open'], paths=['/x/sqlalchemy/__init__.py'],
                            operation_offsets_s={'request_lazy_sqlalchemy': 5.0})
        op_intervals = {'request_lazy_sqlalchemy': [(self._at(290.0), self._at(320.0))]}
        self.assertEqual(
            coverage.main_membership(entry, set(), {'request_lazy_sqlalchemy'},
                                      op_intervals, self.window_end), 'x_main')

    def test_straddling_operation_with_exec_evidence_and_confirmed_overlap_is_u_main(self):
        entry = used_entry('os', 'python3', '3.12.3', used_at_startup=False,
                            used_during_operations=['request_lazy_sqlalchemy'],
                            evidence_types=['exec'], paths=['/usr/local/bin/python3'],
                            operation_offsets_s={'request_lazy_sqlalchemy': 5.0})
        op_intervals = {'request_lazy_sqlalchemy': [(self._at(290.0), self._at(320.0))]}
        self.assertEqual(
            coverage.main_membership(entry, set(), {'request_lazy_sqlalchemy'},
                                      op_intervals, self.window_end), 'u_main')

    def test_straddling_operation_with_held_evidence_and_confirmed_overlap_is_u_main(self):
        entry = used_entry('python', 'sqlalchemy', '2.0.30', used_at_startup=False,
                            used_during_operations=['request_lazy_sqlalchemy'],
                            evidence_types=['open'], paths=['/x/sqlalchemy/__init__.py'],
                            operation_offsets_s={'request_lazy_sqlalchemy': 5.0},
                            held_evidence=[{'path': '/x/sqlalchemy/__init__.py', 'phase': 'after_lazy',
                                            'ts_relative_s': 320.0}])
        op_intervals = {'request_lazy_sqlalchemy': [(self._at(290.0), self._at(320.0))]}
        self.assertEqual(
            coverage.main_membership(entry, set(), {'request_lazy_sqlalchemy'},
                                      op_intervals, self.window_end), 'u_main')

    def test_mapped_instant_past_window_end_is_x_main_even_with_persistence_evidence(self):
        # The exact counterexample: truth's own package was first used
        # 20s into the operation on the TRUTH run - but on THIS
        # measurement run, the matching operation instance itself only
        # started at 290s (relative to firing), with the window closing
        # at 300s. Mapping truth's own 20s offset onto THIS run's own
        # instance start lands at 310s - already past this run's own
        # window end - so this must not become u_main, even though
        # persistence-shaped evidence (held_evidence) is present.
        # Directly comparing truth's own first_seen_s (or any absolute
        # truth-side clock reading) against this run's own window_end
        # would get this wrong.
        entry = used_entry('python', 'sqlalchemy', '2.0.30', used_at_startup=False,
                            used_during_operations=['request_lazy_sqlalchemy'],
                            evidence_types=['open'], paths=['/x/sqlalchemy/__init__.py'],
                            operation_offsets_s={'request_lazy_sqlalchemy': 20.0},
                            held_evidence=[{'path': '/x/sqlalchemy/__init__.py', 'phase': 'after_lazy',
                                            'ts_relative_s': 400.0}])
        op_intervals = {'request_lazy_sqlalchemy': [(self._at(290.0), self._at(320.0))]}
        self.assertEqual(
            coverage.main_membership(entry, set(), {'request_lazy_sqlalchemy'},
                                      op_intervals, self.window_end), 'x_main')

    def test_missing_offset_cannot_confirm_overlap_and_is_x_main(self):
        entry = used_entry('python', 'sqlalchemy', '2.0.30', used_at_startup=False,
                            used_during_operations=['request_lazy_sqlalchemy'],
                            evidence_types=['exec'], paths=['/usr/local/bin/python3'],
                            operation_offsets_s={})
        op_intervals = {'request_lazy_sqlalchemy': [(self._at(290.0), self._at(320.0))]}
        self.assertEqual(
            coverage.main_membership(entry, set(), {'request_lazy_sqlalchemy'},
                                      op_intervals, self.window_end), 'x_main')

    def test_osops_candidate_used_in_both_paired_and_unpaired_ranges_is_u_main(self):
        # This package's own evidence ties it to TWO instances of
        # osops_curl: one this run's own fresh re-comparison actually
        # verified (paired), and one beyond that (unpaired). Being used
        # even once in the verified range is enough.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            operation_instances=['osops-1', 'osops-99'])
        unpaired = {'osops-99'}
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end, unpaired), 'u_main')

    def test_osops_candidate_used_only_in_the_unpaired_range_is_x_main(self):
        # Every instance this package's own evidence ties to falls
        # beyond what this run's own fresh re-comparison ever verified -
        # the operation's own NAME still appears in completed_ops, but
        # that alone is not enough: this run never had the chance to
        # confirm the two runs behaved the same way for THIS specific
        # instance.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            operation_instances=['osops-99'])
        unpaired = {'osops-99'}
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end, unpaired), 'x_main')

    def test_no_operation_instances_recorded_falls_back_to_trusting_the_name(self):
        # An older truth.json (or evidence attributed some other way)
        # with no operation_instances at all - nothing more specific to
        # check, so the operation-name match in completed_ops is
        # trusted, same as before this check existed.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'])
        unpaired = {'osops-99'}
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end, unpaired), 'u_main')

    def test_straddling_osops_candidate_confirmed_only_via_an_unpaired_instance_is_x_main(self):
        # The exact counterexample: the same operation instance spans
        # 290-320s (straddling this run's own 300s window end), with an
        # offset of just 1s (which would map to 291s, well before
        # window_end) and exec evidence (persistence) - every ingredient
        # the OLD, name-only straddling check would have accepted. But
        # this package's own evidence is tied ONLY to an operation
        # instance id ('osops-99') that this run's own fresh
        # re-comparison never actually paired against any measurement
        # instance at all - so the offset can never be applied within a
        # genuine correspondence, and this must stay x_main.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            evidence_types=['exec'], paths=['/usr/bin/curl'],
                            operation_instances=['osops-99'],
                            operation_instance_offsets_s={'osops-99': 1.0})
        measurement_intervals_raw = [
            {'op': 'osops_curl', 'id': 'measurement-99', 'start': self._at(290.0), 'end': self._at(320.0),
             'paired': True},
        ]
        # osops-99 (truth's own instance) is NOT among the paired ids at
        # all - only some other instance ('osops-1') was ever verified.
        osops_pairing = {
            'paired_truth_osops_ids': ['osops-1'], 'paired_measurement_osops_ids': ['measurement-99'],
            'unpaired_truth_osops_ids': ['osops-99'], 'unpaired_measurement_osops_ids': [],
        }
        self.assertEqual(
            coverage.main_membership(entry, set(), {'osops_curl'}, {}, self.window_end,
                                      unpaired_osops_ids={'osops-99'}, osops_pairing=osops_pairing,
                                      measurement_intervals_raw=measurement_intervals_raw),
            'x_main')

    def test_straddling_osops_candidate_confirmed_via_a_genuinely_paired_instance_is_u_main(self):
        # The counterpart: this time the package's own evidence IS tied
        # to the instance osops_pairing actually verified, so the same
        # offset-within-window mapping applies and confirms u_main.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            evidence_types=['exec'], paths=['/usr/bin/curl'],
                            operation_instances=['osops-1'],
                            operation_instance_offsets_s={'osops-1': 1.0})
        measurement_intervals_raw = [
            {'op': 'osops_curl', 'id': 'measurement-1', 'start': self._at(290.0), 'end': self._at(320.0),
             'paired': True},
        ]
        osops_pairing = {
            'paired_truth_osops_ids': ['osops-1'], 'paired_measurement_osops_ids': ['measurement-1'],
            'unpaired_truth_osops_ids': [], 'unpaired_measurement_osops_ids': [],
        }
        self.assertEqual(
            coverage.main_membership(entry, set(), {'osops_curl'}, {}, self.window_end,
                                      unpaired_osops_ids=set(), osops_pairing=osops_pairing,
                                      measurement_intervals_raw=measurement_intervals_raw),
            'u_main')

    def test_osops_name_with_a_completed_AND_a_straddling_instance_is_not_confirmed_by_name_alone(self):
        # The exact counterexample: the same operation NAME has two
        # instances on this measurement run - instance-1 (10-11s,
        # cleanly completed before window_end=300) and instance-2
        # (290-320s, straddling window_end). measurement_ops_completed_
        # by/measurement_ops_straddling_only would classify this NAME as
        # "completed" outright (instance-1 alone is enough), hiding
        # instance-2's own straddling state entirely. This package's own
        # evidence is tied ONLY to instance-2 (offset 20s -> mapped
        # 310s, past window_end) - instance-1's own completion is
        # irrelevant to THIS package, since nothing ties it there. Must
        # be x_main, never confirmed by the operation's own name having
        # SOME completed instance.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            evidence_types=['exec'], paths=['/usr/bin/curl'],
                            operation_instances=['osops-2'],
                            operation_instance_offsets_s={'osops-2': 20.0})
        measurement_intervals_raw = [
            {'op': 'osops_curl', 'id': 'measurement-1', 'start': self._at(10.0), 'end': self._at(11.0),
             'paired': True},
            {'op': 'osops_curl', 'id': 'measurement-2', 'start': self._at(290.0), 'end': self._at(320.0),
             'paired': True},
        ]
        osops_pairing = {
            'paired_truth_osops_ids': ['osops-1', 'osops-2'],
            'paired_measurement_osops_ids': ['measurement-1', 'measurement-2'],
            'unpaired_truth_osops_ids': [], 'unpaired_measurement_osops_ids': [],
        }
        # completed_ops/straddling_ops as build_window_operation_sets'
        # own name-level aggregation would actually produce for this
        # exact scenario: the name is "completed" (instance-1 alone
        # qualifies it), so straddling_ops never even names it.
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end,
                                      unpaired_osops_ids=set(), osops_pairing=osops_pairing,
                                      measurement_intervals_raw=measurement_intervals_raw),
            'x_main')

    def test_osops_name_with_a_completed_AND_a_straddling_instance_confirms_when_evidence_ties_to_the_completed_one(self):
        # The counterpart: this package's own evidence is tied to BOTH
        # instance-1 (completed) and instance-2 (straddling, unconfirmed
        # per the previous test) - being confirmed via instance-1 alone
        # is enough for u_main, regardless of instance-2's own outcome.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            evidence_types=['exec'], paths=['/usr/bin/curl'],
                            operation_instances=['osops-1', 'osops-2'],
                            operation_instance_offsets_s={'osops-1': 0.5, 'osops-2': 20.0})
        measurement_intervals_raw = [
            {'op': 'osops_curl', 'id': 'measurement-1', 'start': self._at(10.0), 'end': self._at(11.0),
             'paired': True},
            {'op': 'osops_curl', 'id': 'measurement-2', 'start': self._at(290.0), 'end': self._at(320.0),
             'paired': True},
        ]
        osops_pairing = {
            'paired_truth_osops_ids': ['osops-1', 'osops-2'],
            'paired_measurement_osops_ids': ['measurement-1', 'measurement-2'],
            'unpaired_truth_osops_ids': [], 'unpaired_measurement_osops_ids': [],
        }
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end,
                                      unpaired_osops_ids=set(), osops_pairing=osops_pairing,
                                      measurement_intervals_raw=measurement_intervals_raw),
            'u_main')

    def test_all_instances_unpaired_with_real_osops_pairing_never_falls_back_to_the_name(self):
        # The regression this guards against: osops_pairing IS given
        # (genuine pairing information exists), but every one of this
        # package's own operation_instances is unpaired. The old bug
        # treated "no instance resolved" the same as "no pairing info at
        # all" and fell back to the coarse, NAME-based straddling check
        # - which this entry's own operation_offsets_s (name-keyed) is
        # deliberately populated here to still satisfy (1s offset onto
        # the 290-320s instance maps to 291s, comfortably before
        # window_end=300) - the exact way that fallback would wrongly
        # confirm u_main if the routing bug were still present. With
        # both offset dicts populated, only correct routing (straight to
        # X, never touching the name-based fallback at all) makes this
        # x_main.
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            evidence_types=['exec'], paths=['/usr/bin/curl'],
                            operation_instances=['osops-99'],
                            operation_offsets_s={'osops_curl': 1.0},
                            operation_instance_offsets_s={'osops-99': 1.0})
        measurement_op_intervals = {'osops_curl': [(self._at(290.0), self._at(320.0))]}
        measurement_intervals_raw = [
            {'op': 'osops_curl', 'id': 'measurement-1', 'start': self._at(290.0), 'end': self._at(320.0),
             'paired': True},
        ]
        # osops-99 (this package's own instance) is not among the
        # paired ids at all - only some other instance ('osops-1') was
        # ever verified, and it is not this package's own.
        osops_pairing = {
            'paired_truth_osops_ids': ['osops-1'], 'paired_measurement_osops_ids': ['measurement-1'],
            'unpaired_truth_osops_ids': ['osops-99'], 'unpaired_measurement_osops_ids': [],
        }
        self.assertEqual(
            coverage.main_membership(entry, set(), {'osops_curl'}, measurement_op_intervals, self.window_end,
                                      unpaired_osops_ids={'osops-99'}, osops_pairing=osops_pairing,
                                      measurement_intervals_raw=measurement_intervals_raw),
            'x_main')

    def test_unpaired_ids_none_never_restricts_anything(self):
        entry = used_entry('os', 'curl', '8.14.1', used_at_startup=False,
                            used_during_operations=['osops_curl'],
                            operation_instances=['osops-99'])
        self.assertEqual(
            coverage.main_membership(entry, {'osops_curl'}, set(), {}, self.window_end, None), 'u_main')


class ScoringPreconditionTests(unittest.TestCase):
    """check_same_image and check_operations_consistent are the two
    preconditions main() holds scoring on entirely - neither the image
    match alone, nor an operation-sequence check that was never
    performed, is enough on its own to trust a truth.json's own N set."""

    def test_same_image_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'image_id.txt'), 'w') as f:
                f.write('sha256:abc\n')
            ok, reason = coverage.check_same_image(tmp, {'image_id': 'sha256:abc'})
            self.assertTrue(ok)
            self.assertEqual(reason, '')

    def test_different_image_ids_do_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'image_id.txt'), 'w') as f:
                f.write('sha256:abc\n')
            ok, reason = coverage.check_same_image(tmp, {'image_id': 'sha256:def'})
            self.assertFalse(ok)
            self.assertIn('sha256:abc', reason)
            self.assertIn('sha256:def', reason)

    def test_missing_measurement_image_id_file_does_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, reason = coverage.check_same_image(tmp, {'image_id': 'sha256:abc'})
            self.assertFalse(ok)
            self.assertIn('image_id.txt', reason)

    def _make_truth_run(self, tmp, ops):
        """A minimal truth-run directory: varlog/operations.jsonl (from
        the given [(op, ok), ...] pairs) and its own image_id.txt -
        enough for check_operations_consistent to re-open and
        re-compare against, the way it does with a real truth run."""
        truth_run = os.path.join(tmp, 'truth-run')
        os.makedirs(os.path.join(truth_run, 'varlog'))
        with open(os.path.join(truth_run, 'varlog', 'operations.jsonl'), 'w') as f:
            for i, (op, ok) in enumerate(ops):
                f.write(json.dumps({'id': f'op-{i}', 'op': op, 'ok': ok}) + '\n')
        with open(os.path.join(truth_run, 'image_id.txt'), 'w') as f:
            f.write('sha256:abc\n')
        return truth_run

    def _make_measurement_run(self, tmp, name, ops):
        measurement_run = os.path.join(tmp, name)
        os.makedirs(measurement_run)
        with open(os.path.join(measurement_run, 'operations.jsonl'), 'w') as f:
            for i, (op, ok) in enumerate(ops):
                f.write(json.dumps({'id': f'op-{i}', 'op': op, 'ok': ok}) + '\n')
        with open(os.path.join(measurement_run, 'image_id.txt'), 'w') as f:
            f.write('sha256:abc\n')
        return measurement_run

    def test_reruns_the_comparison_against_this_measurement_run_and_passes_when_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops = [('fired', True), ('render_startup_template', True)]
            truth_run = self._make_truth_run(tmp, ops)
            measurement_run = self._make_measurement_run(tmp, 'measurement', ops)
            truth = {'truth_run_dir': truth_run, 'image_id': 'sha256:abc'}
            ok, reason, _result = coverage.check_operations_consistent(measurement_run, truth)
            self.assertTrue(ok)
            self.assertEqual(reason, '')

    def test_never_trusts_a_saved_consistent_verdict_that_does_not_match_this_run(self):
        # The exact scenario this function exists to catch: a truth.json
        # whose OWN saved completeness.operations/operation_consistency
        # says "consistent" (because it was verified against ITS OWN
        # logs, or some other measurement run entirely) must still HOLD
        # when actually pointed at a DIFFERENT run whose own firing
        # procedure does not match.
        with tempfile.TemporaryDirectory() as tmp:
            truth_run = self._make_truth_run(tmp, [('fired', True), ('render_startup_template', True)])
            other_measurement_run = self._make_measurement_run(
                tmp, 'other-measurement', [('fired', True), ('render_startup_template', False)])
            truth = {
                'truth_run_dir': truth_run, 'image_id': 'sha256:abc',
                # A saved verdict claiming consistency (as if truth.py
                # had already verified this truth run against some
                # measurement run, possibly itself) - must be ignored.
                'operation_consistency': {'checked': True, 'consistent': True},
                'completeness': {'operations': 'consistent'},
            }
            ok, reason, _result = coverage.check_operations_consistent(other_measurement_run, truth)
            self.assertFalse(ok)
            self.assertTrue(reason)

    def test_missing_truth_run_dir_field_holds(self):
        ok, reason, _result = coverage.check_operations_consistent('/irrelevant', {})
        self.assertFalse(ok)
        self.assertIn('truth_run_dir', reason)

    def test_truth_run_directory_gone_from_disk_holds(self):
        ok, reason, _result = coverage.check_operations_consistent(
            '/irrelevant', {'truth_run_dir': '/does/not/exist/at/all'})
        self.assertFalse(ok)
        self.assertIn('no longer exists', reason)


if __name__ == '__main__':
    unittest.main()
