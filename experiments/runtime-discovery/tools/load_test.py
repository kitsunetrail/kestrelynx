#!/usr/bin/env python3
"""Unit tests for the pure functions in load.py: measured/not_measured sentinels, cgroup
cpu/memory delta computation, percentile and per-operation duration statistics, window
classification, the event_state replication rule (now header/trailer-aware), and the
end-to-end aggregation over small synthetic out-directories of load.json files - no Docker,
no real measurement run. Run with (from the repository root):

  python3 -m unittest discover -s experiments/runtime-discovery/tools -p 'load_test.py'
  python3 experiments/runtime-discovery/tools/load_test.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import load
import load_run_assemble


class SentinelTests(unittest.TestCase):
    def test_not_measured_round_trips_its_reason(self):
        v = load.not_measured('kernel too old for memory.peak')
        self.assertTrue(load.is_not_measured(v))
        self.assertEqual(load.not_measured_reason(v), 'kernel too old for memory.peak')

    def test_a_measured_number_is_not_a_sentinel(self):
        self.assertFalse(load.is_not_measured(0))
        self.assertFalse(load.is_not_measured(12345))
        self.assertIsNone(load.not_measured_reason(0))

    def test_measured_or_picks_the_right_side(self):
        self.assertEqual(load.measured_or(42, True, 'unused'), 42)
        self.assertEqual(load.measured_or(42, False, 'why not'), load.not_measured('why not'))


class CgroupDeltaTests(unittest.TestCase):
    def test_both_readings_present(self):
        self.assertEqual(load.cgroup_cpu_delta_us('1000', '2500'), 1500)

    def test_missing_before_is_not_measured(self):
        v = load.cgroup_cpu_delta_us('', '2500')
        self.assertTrue(load.is_not_measured(v))

    def test_missing_after_is_not_measured(self):
        v = load.cgroup_cpu_delta_us('1000', '')
        self.assertTrue(load.is_not_measured(v))

    def test_a_decrease_is_reported_rather_than_a_negative_number(self):
        # usage_usec is monotonically non-decreasing within one cgroup's lifetime; a
        # decrease means the two readings were not of the same cgroup lifetime at all.
        v = load.cgroup_cpu_delta_us('5000', '4000')
        self.assertTrue(load.is_not_measured(v))
        self.assertIn('decreased', load.not_measured_reason(v))

    def test_memory_peak_measured_and_not(self):
        self.assertEqual(load.cgroup_memory_peak_bytes(True, '104857600'), 104857600)
        self.assertTrue(load.is_not_measured(load.cgroup_memory_peak_bytes(False, '')))


class FromMeasuredJsonAndDeltaMeasuredTests(unittest.TestCase):
    def test_from_measured_json_measured_true(self):
        self.assertEqual(load.from_measured_json({'measured': True, 'value': 42}, 'unused'), 42)

    def test_from_measured_json_measured_false_uses_its_own_reason(self):
        v = load.from_measured_json({'measured': False, 'reason': 'memory controller not available'}, 'unused')
        self.assertTrue(load.is_not_measured(v))
        self.assertEqual(load.not_measured_reason(v), 'memory controller not available')

    def test_from_measured_json_none_uses_missing_reason(self):
        v = load.from_measured_json(None, 'cgroup-stat output file missing')
        self.assertTrue(load.is_not_measured(v))
        self.assertEqual(load.not_measured_reason(v), 'cgroup-stat output file missing')

    def test_delta_measured_both_present(self):
        self.assertEqual(load.delta_measured(1000, 2500), 1500)

    def test_delta_measured_propagates_not_measured_before(self):
        v = load.delta_measured(load.not_measured('no read'), 2500)
        self.assertTrue(load.is_not_measured(v))
        self.assertIn('before:', load.not_measured_reason(v))

    def test_delta_measured_propagates_not_measured_after(self):
        v = load.delta_measured(1000, load.not_measured('no read'))
        self.assertTrue(load.is_not_measured(v))
        self.assertIn('after:', load.not_measured_reason(v))

    def test_delta_measured_rejects_a_decrease(self):
        v = load.delta_measured(5000, 4000)
        self.assertTrue(load.is_not_measured(v))
        self.assertIn('decreased', load.not_measured_reason(v))


class PercentileTests(unittest.TestCase):
    def test_median_odd_length(self):
        self.assertEqual(load.percentile([1, 2, 3, 4, 5], 0.5), 3)

    def test_median_even_length_nearest_rank_not_interpolated(self):
        # Nearest-rank on 4 values at p=0.5: ceil(0.5*4)=2 -> index 1 (0-based) -> the 2nd
        # value, not an interpolated 2.5.
        self.assertEqual(load.percentile([10, 20, 30, 40], 0.5), 20)

    def test_p95_of_a_small_sample(self):
        self.assertEqual(load.percentile(list(range(1, 21)), 0.95), 19)

    def test_single_value(self):
        self.assertEqual(load.percentile([7], 0.95), 7)


class DurationStatsTests(unittest.TestCase):
    def test_no_instances_at_all_is_not_measured_not_zero(self):
        stats = load.duration_stats([], 0, 'no curl instances this run')
        self.assertEqual(stats['n'], 0)
        self.assertTrue(load.is_not_measured(stats['state']))

    def test_all_failed_reports_failure_count_with_no_duration_summary(self):
        stats = load.duration_stats([], 3, 'unused')
        self.assertEqual(stats['n'], 3)
        self.assertEqual(stats['failures'], 3)
        self.assertTrue(load.is_not_measured(stats['median_ms']))

    def test_mixed_success_and_failure(self):
        stats = load.duration_stats([10.0, 20.0, 30.0], 1, 'unused')
        self.assertEqual(stats['n'], 4)
        self.assertEqual(stats['failures'], 1)
        self.assertEqual(stats['median_ms'], 20.0)
        self.assertEqual(stats['max_ms'], 30.0)


class ParseIsoAndWindowTests(unittest.TestCase):
    def test_parses_the_harness_own_9_digit_fraction_format(self):
        t = load.parse_iso('2026-01-01T00:00:05.500000000Z')
        self.assertIsNotNone(t)
        t0 = load.parse_iso('2026-01-01T00:00:00.000000000Z')
        self.assertAlmostEqual(t - t0, 5.5, places=3)

    def test_empty_or_non_z_is_none(self):
        self.assertIsNone(load.parse_iso(''))
        self.assertIsNone(load.parse_iso(None))
        self.assertIsNone(load.parse_iso('not a timestamp'))

    def test_classify_within(self):
        cls = load.classify_window(
            '2026-01-01T00:00:01.000000000Z', '2026-01-01T00:00:02.000000000Z',
            '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:10.000000000Z')
        self.assertEqual(cls, 'within')

    def test_classify_boundary_crossing_at_start(self):
        cls = load.classify_window(
            '2025-12-31T23:59:59.000000000Z', '2026-01-01T00:00:02.000000000Z',
            '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:10.000000000Z')
        self.assertEqual(cls, 'boundary_crossing')

    def test_classify_outside(self):
        cls = load.classify_window(
            '2025-12-31T23:59:50.000000000Z', '2025-12-31T23:59:55.000000000Z',
            '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:10.000000000Z')
        self.assertEqual(cls, 'outside')

    def test_classify_unknown_on_unparseable_input(self):
        cls = load.classify_window('garbage', 'garbage',
                                    '2026-01-01T00:00:00.000000000Z', '2026-01-01T00:00:10.000000000Z')
        self.assertEqual(cls, 'unknown')


def op(seq, opname, ok=True, duration_ms=None, exit_code=0, ts='2026-01-01T00:00:00.000000000Z',
       end_ts='2026-01-01T00:00:00.100000000Z'):
    r = {'id': f'26-op-osops-{seq:06d}', 'ts': ts, 'op': opname, 'ok': ok}
    if duration_ms is not None:
        r['duration_ms'] = duration_ms
        r['end_ts'] = end_ts
        r['exit_code'] = exit_code
    return r


class WorkloadStatsTests(unittest.TestCase):
    def test_each_kind_summarized_independently(self):
        records = [
            op(1, 'osops_curl', duration_ms=12.0),
            op(2, 'osops_git', duration_ms=8.0),
            op(3, 'osops_openssl', duration_ms=5.0),
            op(4, 'osops_curl', duration_ms=14.0),
        ]
        stats = load.workload_stats_from_operations(records)
        self.assertEqual(stats['curl']['n'], 2)
        self.assertEqual(stats['git']['n'], 1)
        self.assertEqual(stats['openssl']['n'], 1)

    def test_a_kind_with_no_instances_is_not_measured_not_zero(self):
        stats = load.workload_stats_from_operations([op(1, 'osops_curl', duration_ms=1.0)])
        self.assertTrue(load.is_not_measured(stats['git']['state']))
        self.assertEqual(stats['git']['n'], 0)

    def test_a_failed_instance_is_a_failure_not_a_duration(self):
        records = [op(1, 'osops_curl', ok=False, duration_ms=999.0, exit_code=7)]
        stats = load.workload_stats_from_operations(records)
        self.assertEqual(stats['curl']['n'], 1)
        self.assertEqual(stats['curl']['failures'], 1)

    def test_operations_log_predating_duration_ms_is_not_measured_not_zero_instances(self):
        # An older operations.jsonl carries "op"/"ok"/"ts" but never duration_ms/exit_code:
        # the operations plainly happened (ops are present), but this run's own log has no
        # timing for them, which must not be reported as if none occurred.
        records = [{'id': '26-op-osops-000001', 'ts': 't', 'op': 'osops_curl', 'ok': True}]
        stats = load.workload_stats_from_operations(records)
        self.assertEqual(stats['curl']['n'], 1)
        self.assertTrue(load.is_not_measured(stats['curl']['state']))

    def test_window_scoping_excludes_boundary_crossing_instances(self):
        window_start = '2026-01-01T00:05:00.000000000Z'
        window_end = '2026-01-01T00:10:00.000000000Z'
        records = [
            # Fully inside the window.
            op(1, 'osops_curl', duration_ms=10.0, ts='2026-01-01T00:06:00.000000000Z',
               end_ts='2026-01-01T00:06:00.010000000Z'),
            # Started before the window opened (attach_running's own operational loop runs
            # for the whole container lifetime, independently of when observation began).
            op(2, 'osops_curl', duration_ms=10.0, ts='2026-01-01T00:04:59.990000000Z',
               end_ts='2026-01-01T00:05:00.010000000Z'),
            # Entirely after the window closed.
            op(3, 'osops_curl', duration_ms=10.0, ts='2026-01-01T00:10:00.100000000Z',
               end_ts='2026-01-01T00:10:00.110000000Z'),
        ]
        stats = load.workload_stats_from_operations(records, window_start, window_end)
        self.assertEqual(stats['curl']['n'], 1)
        self.assertEqual(stats['curl']['median_ms'], 10.0)
        self.assertEqual(stats['curl']['boundary_crossing'], 1)
        self.assertEqual(stats['curl']['outside_window'], 1)

    def test_without_window_bounds_every_instance_is_used(self):
        records = [op(1, 'osops_curl', duration_ms=10.0, ts='2020-01-01T00:00:00.000000000Z',
                       end_ts='2020-01-01T00:00:00.010000000Z')]
        stats = load.workload_stats_from_operations(records)
        self.assertEqual(stats['curl']['n'], 1)


class WebStatsTests(unittest.TestCase):
    def test_no_records(self):
        stats = load.web_stats_from_timing([])
        self.assertTrue(load.is_not_measured(stats['state']))

    def test_a_connection_failure_is_a_failure_not_a_zero_latency(self):
        records = [{'ok': True, 'latency_ms': 12.5}, {'ok': False, 'latency_ms': None}]
        stats = load.web_stats_from_timing(records)
        self.assertEqual(stats['n'], 2)
        self.assertEqual(stats['failures'], 1)
        self.assertEqual(stats['median_ms'], 12.5)

    def test_timeouts_and_real_failures_are_counted_separately(self):
        records = [
            {'ok': True, 'latency_ms': 5.0},
            {'ok': False, 'latency_ms': None, 'timeout_type': 'operation_timeout'},
            # connection_failed is a service refusing the connection outright - a real
            # failure, materially different from being merely too slow - never lumped in
            # with an actual timeout.
            {'ok': False, 'latency_ms': None, 'timeout_type': 'connection_failed'},
            {'ok': False, 'latency_ms': None, 'timeout_type': 'none'},
        ]
        stats = load.web_stats_from_timing(records)
        self.assertEqual(stats['success_count'], 1)
        self.assertEqual(stats['timeout_count'], 1)
        self.assertEqual(stats['failure_count'], 2)
        self.assertEqual(stats['failures'], 3)


class PartialEventsTests(unittest.TestCase):
    def test_sums_exactly_the_four_reference_fields(self):
        drops = {'path_read_failures': 1, 'path_truncations': 2, 'enter_exit_unmatched_boundary': 3,
                  'identity_unavailable': 4, 'lost_events': 100}  # lost_events must NOT be included
        self.assertEqual(load.partial_events_from_drops(drops), 10)

    def test_missing_fields_default_to_zero(self):
        self.assertEqual(load.partial_events_from_drops({}), 0)


class RateTests(unittest.TestCase):
    def test_basic_rate(self):
        self.assertEqual(load.rate(300, 100), 3.0)

    def test_not_measured_count_stays_not_measured(self):
        v = load.rate(load.not_measured('no tracer'), 100)
        self.assertTrue(load.is_not_measured(v))

    def test_zero_or_negative_duration_is_not_measured(self):
        self.assertTrue(load.is_not_measured(load.rate(10, 0)))
        self.assertTrue(load.is_not_measured(load.rate(10, -5)))


class EventStateFromConversionTests(unittest.TestCase):
    def test_not_attempted_without_a_tracer(self):
        self.assertEqual(load.event_state_from_conversion(False, None, None, 0, {}), 'not_attempted')

    def test_failed_with_no_header_at_all(self):
        self.assertEqual(load.event_state_from_conversion(True, None, {'record': 'events_trailer'}, 0, {}), 'failed')

    def test_failed_when_header_says_not_started(self):
        header = {'started': False, 'attached': False}
        self.assertEqual(load.event_state_from_conversion(True, header, {}, 0, {}), 'failed')

    def test_failed_when_header_says_started_but_not_attached(self):
        header = {'started': True, 'attached': False}
        self.assertEqual(load.event_state_from_conversion(True, header, {}, 0, {}), 'failed')

    def test_degraded_when_trailer_missing_despite_good_header(self):
        # A conversion that never finished (crashed, truncated input) must not read as
        # "observed" merely because the header says attachment was confirmed.
        header = {'started': True, 'attached': True}
        self.assertEqual(load.event_state_from_conversion(True, header, None, 0, {}), 'degraded')

    def test_degraded_on_malformed_lines(self):
        header = {'started': True, 'attached': True}
        trailer = {'record': 'events_trailer'}
        self.assertEqual(load.event_state_from_conversion(True, header, trailer, 3, {}), 'degraded')

    def test_observed_when_everything_is_clean(self):
        header = {'started': True, 'attached': True}
        trailer = {'record': 'events_trailer'}
        self.assertEqual(load.event_state_from_conversion(True, header, trailer, 0, {}), 'observed')

    def test_degraded_on_lost_events(self):
        header = {'started': True, 'attached': True}
        trailer = {'record': 'events_trailer'}
        self.assertEqual(load.event_state_from_conversion(True, header, trailer, 0, {'lost_events': 3}), 'degraded')

    def test_degraded_on_stopped_early(self):
        header = {'started': True, 'attached': True}
        trailer = {'record': 'events_trailer'}
        self.assertEqual(
            load.event_state_from_conversion(True, header, trailer, 0, {'stopped_early': True}), 'degraded')

    def test_degraded_when_the_runner_itself_stopped_the_run_early(self):
        # The converter only sees a short window if the tracer's own exit time reached it;
        # the runner's own early stop is its own fact and degrades the state by itself.
        self.assertEqual(load.event_state_from_conversion(
            True, {'started': True, 'attached': True}, {'record': 'events_trailer'}, 0, {},
            runner_stopped_early=True), 'degraded')

    def test_observed_is_unaffected_when_the_runner_did_not_stop_early(self):
        self.assertEqual(load.event_state_from_conversion(
            True, {'started': True, 'attached': True}, {'record': 'events_trailer'}, 0, {},
            runner_stopped_early=False), 'observed')

    def test_degraded_on_unmeasured_category(self):
        header = {'started': True, 'attached': True}
        trailer = {'record': 'events_trailer'}
        self.assertEqual(
            load.event_state_from_conversion(True, header, trailer, 0, {'unmeasured': ['map_overflow']}), 'degraded')


class RunFieldsTests(unittest.TestCase):
    def test_parses_a_well_formed_run_directory_name(self):
        fields = load.run_fields('/x/26-load-events-10-300-r2-attach_running')
        self.assertEqual(fields, {'run': '26-load-events-10-300-r2-attach_running', 'case': '26',
                                   'config': 'events', 'interval': 10, 'window': 300, 'replicate': 2})

    def test_an_unrelated_directory_name_returns_none(self):
        self.assertIsNone(load.run_fields('/x/26-root-30-300-p0-r1-startup-nofilter64p'))

    def test_block_key_ignores_config(self):
        a = load.run_fields('26-load-events-10-300-r1-attach_running')
        b = load.run_fields('26-load-none-10-300-r1-attach_running')
        self.assertEqual(load.block_key(a), load.block_key(b))


class HumanAndDeltaTests(unittest.TestCase):
    def test_human_renders_measured_values_unchanged(self):
        self.assertEqual(load.human(42), 42)

    def test_human_renders_not_measured_as_na_with_reason(self):
        self.assertEqual(load.human(load.not_measured('no tracer')), 'n/a (no tracer)')

    def test_human_renders_missing_as_na(self):
        self.assertEqual(load.human(None), 'n/a (not recorded)')

    def test_delta_of_two_measured_numbers(self):
        self.assertEqual(load.delta(120.0, 100.0), 20.0)

    def test_delta_without_a_matching_none_run(self):
        v = load.delta(120.0, None)
        self.assertTrue(load.is_not_measured(v))
        self.assertIn('no matching config=none run', load.not_measured_reason(v))

    def test_delta_when_this_runs_own_value_is_unmeasured(self):
        v = load.delta(load.not_measured('no data'), 100.0)
        self.assertTrue(load.is_not_measured(v))


def write_load_json(out_dir, run_name, data):
    run_dir = os.path.join(out_dir, run_name)
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, 'load.json'), 'w') as f:
        json.dump(data, f)
    return run_dir


def base_load_json(config, curl_median=20.0, **overrides):
    no_tracer = load.not_measured('this config starts no tracer')
    no_collector = load.not_measured('config=none starts no collector')
    data = {
        'stopped_early': False, 'stop_reason': 'window_elapsed',
        'window': 300, 'image_id': 'sha256:the-same-image',
        'window_established': True, 'window_start_drift_s': 0,
        'measurement_complete': True, 'measurement_incomplete_reasons': [],
        'collector_cpu_usage_delta_prep_us': 100_000 if config != 'none' else no_collector,
        'collector_cpu_usage_delta_window_us': 5_000_000 if config != 'none' else no_collector,
        'collector_cpu_usage_delta_drain_us': 0 if config != 'none' else no_collector,
        'collector_cpu_usage_delta_total_us': 5_100_000 if config != 'none' else no_collector,
        'collector_memory_peak_bytes': 10_000_000 if config != 'none' else no_collector,
        'tracer_cpu_usage_delta_prep_us': 50_000 if config == 'events' else no_tracer,
        'tracer_cpu_usage_delta_window_us': 2_000_000 if config == 'events' else no_tracer,
        'tracer_cpu_usage_delta_drain_us': 10_000 if config == 'events' else no_tracer,
        'tracer_cpu_usage_delta_total_us': 2_060_000 if config == 'events' else no_tracer,
        'tracer_memory_peak_bytes': 8_000_000 if config == 'events' else no_tracer,
        'docker_daemon_cpu_usage_delta_window_us': 1_000_000,
        'events_total': 1000 if config == 'events' else no_tracer,
        'events_total_per_second': 3.33 if config == 'events' else no_tracer,
        'events_attributed': 900 if config == 'events' else no_tracer,
        'events_attributed_per_second': 3.0 if config == 'events' else no_tracer,
        'event_state': 'observed' if config == 'events' else 'not_attempted',
        'partial_events': 0 if config == 'events' else no_tracer,
        'malformed_lines': 0 if config == 'events' else no_tracer,
        'drops': {'lost_events': 0, 'lost_notifications': 0, 'map_overflow': 0,
                  'convert_failures': 0, 'enter_exit_unmatched': 0} if config == 'events' else {},
        'trace_stdout_bytes': 4096 if config == 'events' else no_tracer,
        'trace_stdout_bytes_per_second': 13.65 if config == 'events' else no_tracer,
        'trace_stderr_bytes': 128 if config == 'events' else no_tracer,
        'trace_stderr_bytes_per_second': 0.43 if config == 'events' else no_tracer,
        'run_dir_growth_bytes': 65536,
        'workload': {
            'curl': {'n': 60, 'median_ms': curl_median, 'p95_ms': curl_median * 1.5, 'max_ms': curl_median * 2,
                     'failures': 0, 'boundary_crossing': 0, 'outside_window': 0},
            'git': {'n': 60, 'median_ms': 15.0, 'p95_ms': 20.0, 'max_ms': 25.0, 'failures': 0,
                    'boundary_crossing': 0, 'outside_window': 0},
            'openssl': {'n': 60, 'median_ms': 5.0, 'p95_ms': 7.0, 'max_ms': 9.0, 'failures': 0,
                        'boundary_crossing': 0, 'outside_window': 0},
            'web': {'n': 60, 'median_ms': 3.0, 'p95_ms': 4.0, 'max_ms': 6.0, 'failures': 0},
        },
    }
    data.update(overrides)
    return data


def observation_record(samples, valid, interval=30, window=300, first_delay_ms=5):
    """A collector observation record of exactly the shape collect writes: one sample timing
    per sample it started, and one collection result per sample saying whether that sample
    actually observed anything. The two counts are deliberately independent - a sample that
    failed is still a sample that was taken."""
    return {
        'run_key': {'interval_seconds': interval, 'window_seconds': window},
        'window': {'samples': [{'sample_id': f's{i}', 'index': i,
                                'delay_ms': first_delay_ms if i == 0 else 5}
                               for i in range(samples)]},
        'collection_results': [{'sample_id': f's{i}', 'valid': i < valid,
                                'proc_observe': 'ok' if i < valid else 'top_failed'}
                               for i in range(samples)],
    }


class ObservationCompletenessTests(unittest.TestCase):
    def test_planned_sample_count_is_the_collectors_own_division(self):
        self.assertEqual(load_run_assemble.planned_sample_count(300, 30), 10)
        self.assertEqual(load_run_assemble.planned_sample_count(300, 10), 30)

    def test_a_shorter_window_than_one_interval_still_plans_one_sample(self):
        self.assertEqual(load_run_assemble.planned_sample_count(5, 30), 1)

    def test_a_complete_observation_has_no_reasons(self):
        reasons, notes, delay = load_run_assemble.observation_completeness(
            observation_record(10, 10), 30, 300)
        self.assertEqual(reasons, [])
        self.assertAlmostEqual(delay, 0.005)
        self.assertTrue(any('10 of 10 collection results are valid' in n for n in notes))

    def test_a_normal_exit_after_the_last_sample_is_a_note_not_a_failure(self):
        _reasons, notes, _delay = load_run_assemble.observation_completeness(
            observation_record(10, 10), 30, 300)
        self.assertTrue(any('attempted all 10 planned samples' in n for n in notes))

    def test_stopping_before_the_last_sample_is_incomplete(self):
        reasons, _notes, _delay = load_run_assemble.observation_completeness(
            observation_record(7, 7), 30, 300)
        self.assertTrue(any('attempted 7 of the 10 samples' in r for r in reasons))

    def test_every_sample_failing_is_incomplete_however_many_were_taken(self):
        reasons, _notes, _delay = load_run_assemble.observation_completeness(
            observation_record(10, 0), 30, 300)
        self.assertTrue(any('not one of' in r and 'valid observation' in r for r in reasons),
                        f'reasons were {reasons}')
        # and the reason says the load numbers are the cost of the failed attempts
        self.assertTrue(any('failed attempts' in r for r in reasons))

    def test_one_valid_sample_out_of_ten_is_enough_to_have_observed_something(self):
        reasons, _notes, _delay = load_run_assemble.observation_completeness(
            observation_record(10, 1), 30, 300)
        self.assertFalse(any('valid observation' in r for r in reasons), f'reasons were {reasons}')

    def test_a_record_with_no_collection_results_at_all(self):
        rec = observation_record(10, 10)
        del rec['collection_results']
        reasons, _notes, _delay = load_run_assemble.observation_completeness(rec, 30, 300)
        self.assertTrue(any('no collection results' in r for r in reasons))

    def test_no_record_at_all_is_incomplete_not_silently_fine(self):
        reasons, _notes, delay = load_run_assemble.observation_completeness(None, 30, 300)
        self.assertTrue(any('wrote no observation record' in r for r in reasons))
        self.assertIsNone(delay)

    def test_an_inspect_error_is_its_own_reason(self):
        rec = observation_record(10, 10)
        rec['inspect_error'] = 'no such container'
        reasons, _notes, _delay = load_run_assemble.observation_completeness(rec, 30, 300)
        self.assertTrue(any('could not inspect its target' in r for r in reasons))

    def test_the_first_samples_own_delay_is_reported_in_seconds(self):
        _reasons, _notes, delay = load_run_assemble.observation_completeness(
            observation_record(10, 10, first_delay_ms=9000), 30, 300)
        self.assertEqual(delay, 9.0)


TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))


def tool_source(name):
    with open(os.path.join(TOOLS_DIR, name), encoding='utf-8') as f:
        return f.read()


class RunnerWatcherContractTests(unittest.TestCase):
    """The two scripts agree on how the runner tells the watcher a run is over, and that
    agreement is made of a handful of easily-broken details: one path, published under one
    key, written in one place, with one bound that has to be asked about first. Each of
    these has already been got wrong once, and none of them shows up as a failing behaviour
    until a run is actually left with an orphaned watcher, so they are checked here."""

    def test_the_confirmation_path_is_assigned_exactly_once_and_never_empty(self):
        assignments = [line.strip() for line in tool_source('load-run.sh').splitlines()
                       if line.strip().startswith('CONFIRMED_FILE=')]
        self.assertEqual(len(assignments), 1,
                         f'CONFIRMED_FILE must be set in exactly one place, found: {assignments}')
        self.assertNotIn('CONFIRMED_FILE=""', assignments[0])
        self.assertIn('$R/', assignments[0])

    def test_the_runner_publishes_the_confirmation_path_and_the_bound(self):
        targets_block = tool_source('load-run.sh')
        for key in ('termination_confirmed_file=', 'watch_until_epoch=', 'min_until_epoch='):
            self.assertIn(key, targets_block, f'the targets file must carry {key}')

    def test_the_watcher_reads_every_key_the_runner_publishes(self):
        watch = tool_source('watch-run.sh')
        for key in ('termination_confirmed_file', 'watch_until_epoch', 'min_until_epoch',
                    'residual_unconfirmed', 'expect_tracer', 'expect_collector'):
            self.assertIn(key, watch, f'watch-run.sh must know about {key}')

    def test_the_absolute_bound_is_asked_about_before_any_other_exit_condition(self):
        watch = tool_source('watch-run.sh')
        bound = watch.index('if watch_bound_reached; then')
        normal = watch.index('if watch_may_exit; then')
        self.assertLess(bound, normal,
                        'the absolute bound must be evaluated before the normal exit '
                        'conditions, or it never applies in the cases it exists for')
        # and the normal exit condition must not consult the bound itself: one decision,
        # one place, so the two can never disagree about which applies
        body_start = watch.index('watch_may_exit() {')
        body = watch[body_start:watch.index('\n}\n', body_start)]
        self.assertNotIn('watch_until_epoch', body)

    def test_the_bound_exit_is_distinguishable_from_a_normal_one(self):
        watch = tool_source('watch-run.sh')
        bound_block = watch[watch.index('if watch_bound_reached; then'):watch.index('if watch_may_exit; then')]
        self.assertIn('WATCH_EXIT', bound_block)
        self.assertIn('UNDETERMINED', bound_block)
        self.assertIn('exit 3', bound_block)


class ComparisonBlockerTests(unittest.TestCase):
    def test_two_matching_completed_runs_are_comparable(self):
        self.assertIsNone(load.comparison_blocker(base_load_json('events'), base_load_json('none')))

    def test_no_base_run_at_all(self):
        self.assertIn('no matching config=none run', load.comparison_blocker(base_load_json('events'), None))

    def test_an_early_stopped_run_is_not_compared(self):
        this = base_load_json('events', stopped_early=True, stop_reason='tracer CPU over limit')
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('stopped early', why)
        self.assertIn('tracer CPU over limit', why)

    def test_an_early_stopped_BASE_run_is_not_compared_either(self):
        why = load.comparison_blocker(base_load_json('events'), base_load_json('none', stopped_early=True))
        self.assertIn('config=none run stopped early', why)

    def test_a_window_that_never_opened_when_planned_is_not_compared(self):
        this = base_load_json('events', window_established=False, window_start_drift_s=9)
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('did not open its window', why)
        self.assertIn('9s', why)

    def test_an_incomplete_measurement_is_not_compared(self):
        this = base_load_json('events', measurement_complete=False,
                              measurement_incomplete_reasons=['tracer was placed in its cgroup only after exec'])
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('incomplete measurement', why)
        self.assertIn('only after exec', why)

    def test_different_images_are_not_compared(self):
        why = load.comparison_blocker(base_load_json('events'), base_load_json('none', image_id='sha256:other'))
        self.assertIn('different images', why)

    def test_an_unrecorded_image_id_is_not_compared(self):
        why = load.comparison_blocker(base_load_json('events', image_id=''), base_load_json('none'))
        self.assertIn('image id', why)

    def test_different_planned_windows_are_not_compared(self):
        why = load.comparison_blocker(base_load_json('events'), base_load_json('none', window=900))
        self.assertIn('different windows', why)

    def test_a_record_that_does_not_state_window_establishment_is_not_compared(self):
        this = base_load_json('events')
        del this['window_established']
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('does not record whether its window was established', why)

    def test_a_record_that_does_not_state_measurement_completeness_is_not_compared(self):
        this = base_load_json('events')
        del this['measurement_complete']
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('does not record whether its measurement was complete', why)

    def test_a_base_run_missing_those_fields_blocks_the_comparison_too(self):
        base = base_load_json('none')
        del base['measurement_complete']
        why = load.comparison_blocker(base_load_json('events'), base)
        self.assertIn('config=none run does not record', why)

    def test_a_non_boolean_placeholder_is_not_accepted_as_established(self):
        this = base_load_json('events', window_established='yes')
        why = load.comparison_blocker(this, base_load_json('none'))
        self.assertIn('does not record whether its window was established', why)


class AggregationTests(unittest.TestCase):
    def test_a_run_with_a_matching_none_run_gets_a_real_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '26-load-none-10-300-r1-attach_running', base_load_json('none', curl_median=25.0))
            write_load_json(tmp, '26-load-events-10-300-r1-attach_running', base_load_json('events', curl_median=30.0))
            rows = load.rows_for_out_dir(tmp)
            events_row = next(r for r in rows if r['config'] == 'events')
            self.assertEqual(events_row['curl_median_delta_ms'], 5.0)
            self.assertEqual(events_row['event_state'], 'observed')

    def test_a_run_with_no_matching_none_run_reports_na_not_a_wrong_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '27-load-procfs-30-300-r1-attach_running', base_load_json('procfs'))
            rows = load.rows_for_out_dir(tmp)
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]['curl_median_delta_ms'].startswith('n/a ('))

    def test_unrelated_directories_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, '26-root-30-300-p0-r1-startup-nofilter64p'))
            write_load_json(tmp, '26-load-none-30-300-r1-attach_running', base_load_json('none'))
            rows = load.rows_for_out_dir(tmp)
            self.assertEqual(len(rows), 1)

    def test_write_aggregate_produces_csv_and_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '28-load-none-10-300-r1-attach_running', base_load_json('none'))
            write_load_json(tmp, '28-load-procfs-10-300-r1-attach_running', base_load_json('procfs'))
            rows = load.write_aggregate(tmp)
            self.assertEqual(len(rows), 2)
            self.assertTrue(os.path.exists(os.path.join(tmp, 'AGGREGATE-load.csv')))
            self.assertTrue(os.path.exists(os.path.join(tmp, 'AGGREGATE-load.md')))
            with open(os.path.join(tmp, 'AGGREGATE-load.csv')) as f:
                header = f.readline().strip().split(',')
            self.assertEqual(header, load.ROW_COLUMNS)

    def test_never_renders_a_bare_zero_for_an_unmeasured_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '26-load-procfs-30-300-r1-attach_running', base_load_json('procfs'))
            rows = load.rows_for_out_dir(tmp)
            row = rows[0]
            # procfs starts no tracer: every tracer-derived field must read n/a, never 0.
            for col in ('tracer_cpu_window_s', 'events_total', 'lost_events', 'trace_stdout_bytes'):
                self.assertTrue(str(row[col]).startswith('n/a ('), f'{col} = {row[col]!r}')

    def test_an_incomparable_pair_reports_the_reason_instead_of_a_difference(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '26-load-none-10-300-r1-attach_running', base_load_json('none', curl_median=25.0))
            write_load_json(tmp, '26-load-events-10-300-r1-attach_running',
                            base_load_json('events', curl_median=30.0, stopped_early=True,
                                           stop_reason='free space below the minimum'))
            rows = load.rows_for_out_dir(tmp)
            events_row = next(r for r in rows if r['config'] == 'events')
            self.assertFalse(events_row['comparable_to_none'])
            self.assertIn('stopped early', events_row['not_comparable_because'])
            self.assertTrue(str(events_row['curl_median_delta_ms']).startswith('n/a ('))
            self.assertIn('stopped early', str(events_row['curl_median_delta_ms']))

    def test_a_fallback_placement_run_is_excluded_from_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '27-load-none-30-300-r2-attach_running', base_load_json('none'))
            write_load_json(tmp, '27-load-procfs-30-300-r2-attach_running',
                            base_load_json('procfs', curl_median=40.0, measurement_complete=False,
                                           measurement_incomplete_reasons=[
                                               'collector was placed in its cgroup only after exec']))
            rows = load.rows_for_out_dir(tmp)
            row = next(r for r in rows if r['config'] == 'procfs')
            self.assertFalse(row['comparable_to_none'])
            self.assertIn('only after exec', row['not_comparable_because'])

    def test_prep_window_drain_segments_are_all_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_load_json(tmp, '26-load-events-10-300-r1-attach_running', base_load_json('events'))
            rows = load.rows_for_out_dir(tmp)
            row = rows[0]
            self.assertEqual(row['tracer_cpu_prep_s'], 0.05)
            self.assertEqual(row['tracer_cpu_window_s'], 2.0)
            self.assertEqual(row['tracer_cpu_drain_s'], 0.01)
            self.assertEqual(row['tracer_cpu_total_s'], 2.06)


if __name__ == '__main__':
    unittest.main()
