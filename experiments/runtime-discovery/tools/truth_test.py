#!/usr/bin/env python3
"""Unit tests for the pure functions in truth.py: strace-line parsing and
timestamp conversion, runtime-modules reading, operation-sequence
comparison, OS-subject classification, and the Python/Node/Java inventory
walkers — all against in-memory strings or small fixture directories, no
Docker or image. Run with:

  python3 -m unittest discover -s tools -p 'truth_test.py'
  python3 tools/truth_test.py
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import truth
import gtb as gtb_module


class StraceLineParsingTests(unittest.TestCase):
    def test_successful_execve_without_timestamp(self):
        line = 'execve("/usr/bin/curl", ["curl", "-s"], 0x7ffc /* 11 vars */) = 0'
        rec = truth.parse_strace_line(line)
        self.assertEqual(rec, {'syscall': 'execve', 'path': '/usr/bin/curl', 'ok': True,
                                'resolved': True, 'is_dir_open': False, 'time_of_day': None})

    def test_successful_execve_with_tt_timestamp(self):
        line = '03:11:52.357977 execve("/usr/bin/sh", ["sh"], 0x0 /* 0 vars */) = 0'
        rec = truth.parse_strace_line(line)
        self.assertEqual(rec['time_of_day'], '03:11:52.357977')
        self.assertEqual(rec['path'], '/usr/bin/sh')

    def test_failed_execve_is_not_a_positive(self):
        line = 'execve("/usr/bin/missing", ["missing"], 0x7ffc /* 0 vars */) = -1 ENOENT (No such file or directory)'
        rec = truth.parse_strace_line(line)
        self.assertFalse(rec['ok'])

    def test_openat_with_at_fdcwd_is_resolved(self):
        line = 'openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3'
        rec = truth.parse_strace_line(line)
        self.assertEqual(rec['path'], '/usr/local/lib/python3.12/os.py')
        self.assertTrue(rec['resolved'])

    def test_openat_with_numeric_dirfd_and_relative_path_is_unresolved(self):
        line = 'openat(3, "subdir/file.py", O_RDONLY) = 4'
        rec = truth.parse_strace_line(line)
        self.assertFalse(rec['resolved'])
        self.assertEqual(rec['path'], 'subdir/file.py')

    def test_openat2_parses_like_openat(self):
        line = 'openat2(AT_FDCWD, "/app/lazy/jackson-databind-2.17.1.jar", {flags=O_RDONLY}, 24) = 5'
        rec = truth.parse_strace_line(line)
        self.assertEqual(rec['path'], '/app/lazy/jackson-databind-2.17.1.jar')
        self.assertTrue(rec['resolved'])

    def test_plain_open_two_arg_form(self):
        line = 'open("/etc/passwd", O_RDONLY) = 3'
        rec = truth.parse_strace_line(line)
        self.assertEqual(rec['path'], '/etc/passwd')

    def test_unrelated_syscall_is_ignored(self):
        line = 'close(3) = 0'
        self.assertIsNone(truth.parse_strace_line(line))

    def test_unfinished_line_is_ignored(self):
        line = 'openat(AT_FDCWD, "/some/path" <unfinished ...>'
        self.assertIsNone(truth.parse_strace_line(line))

    def test_blank_line_is_ignored(self):
        self.assertIsNone(truth.parse_strace_line('   '))


class TimeConversionTests(unittest.TestCase):
    def test_iso_utc_trims_long_fraction(self):
        dt = truth.parse_iso_utc('2026-09-19T03:11:52.357977123Z')
        self.assertEqual(dt, datetime(2026, 9, 19, 3, 11, 52, 357977, tzinfo=timezone.utc))

    def test_numeric_offset_is_converted_to_utc_not_dropped(self):
        dt = truth.parse_iso_utc('2026-09-19T23:41:11.119618493+09:00')
        self.assertEqual(dt, datetime(2026, 9, 19, 14, 41, 11, 119618, tzinfo=timezone.utc))
        dt = truth.parse_iso_utc('2026-09-19T14:41:11-00:30')
        self.assertEqual(dt, datetime(2026, 9, 19, 15, 11, 11, tzinfo=timezone.utc))
        dt = truth.parse_iso_utc('2026-09-19T14:41:11.5')
        self.assertEqual(dt, datetime(2026, 9, 19, 14, 41, 11, 500000, tzinfo=timezone.utc))
        with self.assertRaises(ValueError):
            truth.parse_iso_utc('2026-09-19T23:41:11+0900')

    def test_strace_relative_seconds_same_day(self):
        fired_at = datetime(2026, 9, 19, 3, 11, 50, 0, tzinfo=timezone.utc)
        delta = truth.strace_relative_seconds('03:11:52.500000', fired_at)
        self.assertAlmostEqual(delta, 2.5, places=3)

    def test_strace_relative_seconds_handles_midnight_rollover_forward(self):
        # Fired just before midnight; the observed syscall's time-of-day is
        # just after midnight the next day, which read literally against
        # fired_at's own date would look like a huge negative offset.
        fired_at = datetime(2026, 9, 19, 23, 59, 59, 0, tzinfo=timezone.utc)
        delta = truth.strace_relative_seconds('00:00:01.000000', fired_at)
        self.assertAlmostEqual(delta, 2.0, places=3)

    def test_strace_relative_seconds_none_without_fired_at(self):
        self.assertIsNone(truth.strace_relative_seconds('03:11:52.000000', None))


class DirectoryOpenExclusionTests(unittest.TestCase):
    def test_parse_strace_line_flags_o_directory(self):
        line = 'openat(AT_FDCWD, "/usr/local/lib/python3.12/site-packages", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3'
        rec = truth.parse_strace_line(line)
        self.assertTrue(rec['is_dir_open'])

    def test_plain_file_open_is_not_flagged(self):
        line = 'openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3'
        rec = truth.parse_strace_line(line)
        self.assertFalse(rec['is_dir_open'])

    def test_read_strace_dir_excludes_directory_opens_from_used_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('openat(AT_FDCWD, "/usr/share/doc", O_RDONLY|O_DIRECTORY) = 3\n')
                f.write('openat(AT_FDCWD, "/usr/bin/curl", O_RDONLY) = 3\n')
            used, _unresolved, _failed, _evidence = truth.read_strace_dir(tmp)
            self.assertNotIn('/usr/share/doc', used)
            self.assertIn('/usr/bin/curl', used)


class ReadStraceDirTests(unittest.TestCase):
    def test_aggregates_successful_resolved_paths_across_pid_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.10'), 'w') as f:
                f.write('execve("/usr/bin/python3", ["python3"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3\n')
                f.write('openat(AT_FDCWD, "/usr/local/lib/python3.12/missing.py", O_RDONLY) = -1 ENOENT (No such file or directory)\n')
            with open(os.path.join(tmp, 'trace.20'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(3, "relative.txt", O_RDONLY) = 4\n')
            used, unresolved, failed, evidence = truth.read_strace_dir(tmp)
            self.assertEqual(used, {'/usr/bin/python3', '/usr/local/lib/python3.12/os.py', '/usr/bin/curl'})
            self.assertEqual(unresolved, ['relative.txt'])
            self.assertEqual(failed, 1)
            self.assertEqual(evidence['/usr/bin/python3'][0]['type'], 'exec')
            self.assertEqual(evidence['/usr/local/lib/python3.12/os.py'][0]['type'], 'open')

    def test_evidence_carries_relative_timestamps_when_fired_at_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('03:11:52.500000 execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
            fired_at = datetime(2026, 9, 19, 3, 11, 50, 0, tzinfo=timezone.utc)
            _used, _unresolved, _failed, evidence = truth.read_strace_dir(tmp, fired_at)
            self.assertAlmostEqual(evidence['/usr/bin/curl'][0]['ts_relative_s'], 2.5, places=3)
            self.assertEqual(evidence['/usr/bin/curl'][0]['source'], 'strace')

    def test_directory_open_without_o_directory_is_excluded_via_rootfs_stat(self):
        # openat() succeeds against a directory even without O_DIRECTORY;
        # is_dir_open alone (the flag-only check) would miss this one,
        # so the actual file type on the exported rootfs is also checked.
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            os.makedirs(os.path.join(rootfs, 'usr', 'share', 'doc'))
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('openat(AT_FDCWD, "/usr/share/doc", O_RDONLY) = 3\n')
                f.write('openat(AT_FDCWD, "/usr/bin/curl", O_RDONLY) = 3\n')
            used, _unresolved, _failed, _evidence = truth.read_strace_dir(tmp, rootfs_dir=rootfs)
            self.assertNotIn('/usr/share/doc', used)
            self.assertIn('/usr/bin/curl', used)

    def test_exec_of_a_directory_shaped_path_is_not_excluded_by_the_stat_check(self):
        # The stat-based exclusion only ever applies to "open" evidence;
        # an exec is never a directory open at all, and must not be
        # filtered by this check even if rootfs_dir is given.
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            with open(os.path.join(rootfs, 'usr', 'bin', 'curl'), 'w') as f:
                f.write('#!/bin/sh\n')
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
            used, _unresolved, _failed, _evidence = truth.read_strace_dir(tmp, rootfs_dir=rootfs)
            self.assertIn('/usr/bin/curl', used)


class StraceCompletenessTests(unittest.TestCase):
    def test_ok_capture_reports_no_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
            result = truth.check_strace_completeness(tmp)
            self.assertEqual(result, {'empty_files': [], 'empty_child_files': [], 'unparseable_lines': 0,
                                       'total_files': 1, 'unreconstructed_lines': 0})

    def test_empty_trace_file_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, 'trace.1'), 'w').close()
            result = truth.check_strace_completeness(tmp)
            self.assertEqual(len(result['empty_files']), 1)
            self.assertEqual(result['empty_child_files'], [])

    def test_empty_trace_file_of_a_recorded_clone_child_is_not_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('11:39:20.734700 clone(child_stack=0x7120cda2ae30, flags=CLONE_VM|CLONE_THREAD) = 26\n')
            open(os.path.join(tmp, 'trace.26'), 'w').close()
            open(os.path.join(tmp, 'trace.99'), 'w').close()
            result = truth.check_strace_completeness(tmp)
            self.assertEqual([os.path.basename(p) for p in result['empty_child_files']], ['trace.26'])
            self.assertEqual([os.path.basename(p) for p in result['empty_files']], ['trace.99'])

    def test_truncated_syscall_line_is_unparseable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                # A syscall completion line cut off mid-write: no closing
                # paren before "= N", so it matches neither grammar, but
                # its own "= " makes it look like one was intended.
                f.write('openat(AT_FDCWD, "/usr/bin/cu = 3\n')
            result = truth.check_strace_completeness(tmp)
            self.assertGreaterEqual(result['unparseable_lines'], 1)

    def test_benign_signal_and_attach_lines_are_not_unparseable(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n')
                f.write('+++ exited with 0 +++\n')
            result = truth.check_strace_completeness(tmp)
            self.assertEqual(result['unparseable_lines'], 0)


class ReconstructUnfinishedLinesTests(unittest.TestCase):
    # A signal delivered mid-syscall splits strace's own output for that
    # one call across two lines in the same per-pid trace file: the call
    # so far, ending in "<unfinished ...>", then later "<... name
    # resumed>" with the rest once the call actually returns. Every case
    # here uses a real interruption shape: a signal landing while a
    # blocking openat() (waiting on a slow filesystem) is in flight.

    def test_unfinished_and_resumed_pair_reconstructs_into_one_parseable_line(self):
        lines = [
            '14:23:01.123456 openat(AT_FDCWD, "/usr/lib/libfoo.so", <unfinished ...>\n',
            '14:23:01.150000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n',
            '14:23:01.234567 <... openat resumed>O_RDONLY) = 3\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 0)
        # The benign signal line in between passes through at its own
        # position; the stitched call is emitted where its own "resumed"
        # half was found, carrying the "unfinished" half's own timestamp.
        self.assertEqual(len(reconstructed), 2)
        self.assertEqual(reconstructed[0], '14:23:01.150000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---')
        self.assertTrue(reconstructed[1].startswith('14:23:01.123456 openat('))
        rec = truth.parse_strace_line(reconstructed[1])
        self.assertIsNotNone(rec)
        self.assertEqual(rec['path'], '/usr/lib/libfoo.so')
        self.assertTrue(rec['ok'])

    def test_unfinished_with_no_comma_before_the_marker_still_reconstructs(self):
        # strace prints "<unfinished ...>" wherever the interruption
        # actually landed - just as often right after the last argument
        # value with nothing more to come (no trailing comma) as after a
        # comma with more still expected. A comma before the marker must
        # not be required for reconstruction.
        lines = [
            '14:23:01.123456 openat(AT_FDCWD, "/usr/lib/libfoo.so", O_RDONLY <unfinished ...>\n',
            '14:23:01.234567 <... openat resumed>) = 3\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 0)
        self.assertEqual(len(reconstructed), 1)
        rec = truth.parse_strace_line(reconstructed[0])
        self.assertIsNotNone(rec)
        self.assertEqual(rec['path'], '/usr/lib/libfoo.so')
        self.assertTrue(rec['ok'])

    def test_unfinished_with_no_arguments_printed_yet_still_reconstructs(self):
        # The interruption can land before any argument at all has been
        # printed - just a bare "name( <unfinished ...>".
        lines = [
            '14:23:01.123456 clone( <unfinished ...>\n',
            '14:23:01.234567 <... clone resumed>flags=CLONE_CHILD_CLEARTID) = 501\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 0)
        self.assertEqual(len(reconstructed), 1)
        self.assertEqual(truth.parse_clone_line(reconstructed[0]), 501)

    def test_unrecognized_split_call_marker_is_counted_as_a_gap_not_passed_through(self):
        # A line that carries strace's own split-call vocabulary but in
        # a shape neither exact pattern recognizes (a version/locale
        # difference this tool has not seen) must not be silently
        # treated as an ordinary, benign line - it is real evidence this
        # run cannot vouch for.
        lines = [
            'openat(AT_FDCWD, "/usr/lib/libfoo.so" <unfinished...>\n',  # missing the "..." spacing this tool expects
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 1)
        self.assertEqual(reconstructed, [])

    def test_unfinished_call_never_resumed_before_file_ends_is_a_gap(self):
        # The trace stopped mid-call (e.g. the process was still blocked
        # when the capture window ended): there is no "resumed" line to
        # pair it with at all, so it must be counted as a real
        # completeness gap rather than silently reconstructed or dropped.
        lines = [
            '14:23:01.123456 openat(AT_FDCWD, "/usr/lib/libfoo.so", <unfinished ...>\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 1)
        self.assertEqual(reconstructed, [])

    def test_unrelated_lines_pass_through_unchanged(self):
        lines = [
            'execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 0)
        self.assertEqual(reconstructed, ['execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0'])

    def test_resumed_with_nothing_pending_is_counted_as_a_gap_not_crashed_on(self):
        # No matching "unfinished" was ever seen for this name - the
        # capture started mid-call, or the unfinished half used a shape
        # this cannot recognize. Never crashes, and never silently
        # drops this without counting it as incomplete evidence.
        lines = [
            '14:23:01.234567 <... openat resumed>O_RDONLY) = 3\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 1)
        self.assertEqual(reconstructed, [])

    def test_nested_interruption_pairs_most_recently_opened_call_first(self):
        # A signal handler's own openat() is itself interrupted before the
        # original openat() resumes: two "unfinished" opens of the same
        # name are pending at once, and the first "resumed" to arrive
        # must pair with the most recently opened one (LIFO), not the
        # oldest.
        lines = [
            '14:23:01.100000 openat(AT_FDCWD, "/outer.so", <unfinished ...>\n',
            '14:23:01.110000 openat(AT_FDCWD, "/inner.so", <unfinished ...>\n',
            '14:23:01.120000 <... openat resumed>O_RDONLY) = 4\n',
            '14:23:01.130000 <... openat resumed>O_RDONLY) = 3\n',
        ]
        reconstructed, unreconstructed = truth._reconstruct_unfinished_lines(lines)
        self.assertEqual(unreconstructed, 0)
        self.assertEqual(len(reconstructed), 2)
        first = truth.parse_strace_line(reconstructed[0])
        second = truth.parse_strace_line(reconstructed[1])
        self.assertEqual(first['path'], '/inner.so')
        self.assertEqual(second['path'], '/outer.so')

    def test_read_strace_dir_credits_a_reconstructed_open_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('14:23:01.123456 openat(AT_FDCWD, "/usr/lib/libfoo.so", <unfinished ...>\n')
                f.write('14:23:01.234567 <... openat resumed>O_RDONLY) = 3\n')
            used, unresolved, failed, _evidence = truth.read_strace_dir(tmp)
            self.assertIn('/usr/lib/libfoo.so', used)
            self.assertEqual(unresolved, [])
            self.assertEqual(failed, 0)

    def test_check_strace_completeness_reports_an_unresumed_call_as_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.1'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('14:23:01.123456 openat(AT_FDCWD, "/usr/lib/libfoo.so", <unfinished ...>\n')
            result = truth.check_strace_completeness(tmp)
            self.assertEqual(result['unreconstructed_lines'], 1)


class RuntimeModulesTests(unittest.TestCase):
    def test_reads_resolved_files_and_unresolved_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'runtime-modules.jsonl')
            with open(path, 'w') as f:
                f.write(json.dumps({'ts': '2026-09-19T03:11:51.000000000Z', 'phase': 'startup', 'runtime': 'python',
                                     'module': 'flask', 'file': '/usr/local/lib/python3.12/site-packages/flask/__init__.py',
                                     'resolved': True}) + '\n')
                f.write(json.dumps({'ts': '2026-09-19T03:11:51.000000000Z', 'phase': 'startup', 'runtime': 'python',
                                     'module': 'some_namespace_pkg.sub', 'origin': '', 'resolved': False}) + '\n')
                f.write(json.dumps({'ts': '2026-09-19T03:11:52.000000000Z', 'phase': 'after_lazy', 'runtime': 'java',
                                     'class': 'com.example.Foo', 'jar': '/app/lazy/foo.jar'}) + '\n')
            used, unresolved, evidence, _held = truth.read_runtime_modules(path)
            self.assertIn('/usr/local/lib/python3.12/site-packages/flask/__init__.py', used)
            self.assertIn('/app/lazy/foo.jar', used)
            self.assertEqual(unresolved, ['some_namespace_pkg.sub'])
            self.assertEqual(evidence['/app/lazy/foo.jar'][0]['source'], 'runtime_introspection')

    def test_built_in_origin_module_is_not_counted_as_unresolved(self):
        # "built-in" is the workload's own explicit label for a module
        # this run could confirm has no single resolvable file at all
        # (an interpreter-compiled module, a native extension created
        # outside the normal import machinery, or a namespace package) -
        # a confirmed, well-understood state, never a gap in this run's
        # own observation.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'runtime-modules.jsonl')
            with open(path, 'w') as f:
                f.write(json.dumps({'ts': '2026-09-19T03:11:51.000000000Z', 'phase': 'startup', 'runtime': 'python',
                                     'module': '_abc', 'origin': 'built-in', 'resolved': False}) + '\n')
            _used, unresolved, _evidence, _held = truth.read_runtime_modules(path)
            self.assertEqual(unresolved, [])

    def test_evidence_carries_relative_timestamps_when_fired_at_given(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'runtime-modules.jsonl')
            with open(path, 'w') as f:
                f.write(json.dumps({'ts': '2026-09-19T03:11:52.500000000Z', 'phase': 'startup', 'runtime': 'node',
                                     'file': '/app/node_modules/express/index.js'}) + '\n')
            fired_at = datetime(2026, 9, 19, 3, 11, 50, 0, tzinfo=timezone.utc)
            _used, _unresolved, evidence, _held = truth.read_runtime_modules(path, fired_at)
            self.assertAlmostEqual(evidence['/app/node_modules/express/index.js'][0]['ts_relative_s'], 2.5, places=3)

    def test_missing_file_returns_empty(self):
        used, unresolved, evidence, held = truth.read_runtime_modules('/nonexistent/runtime-modules.jsonl')
        self.assertEqual(used, set())
        self.assertEqual(unresolved, [])
        self.assertEqual(evidence, {})
        self.assertEqual(held, {})

    def test_only_the_first_sighting_of_a_path_becomes_open_evidence(self):
        # requests's own resolved file reappears in every later periodic
        # snapshot merely because it stays loaded - only the FIRST
        # sighting (during request_lazy_requests, say) may become "open"
        # evidence; a much later reappearance (near request_lazy_yaml,
        # say) must not look like a fresh load there.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'runtime-modules.jsonl')
            requests_file = '/usr/local/lib/python3.12/site-packages/requests/__init__.py'
            with open(path, 'w') as f:
                f.write(json.dumps({'ts': '2026-09-19T03:12:05.000000000Z', 'phase': 'after_lazy',
                                     'runtime': 'python', 'module': 'requests', 'file': requests_file,
                                     'resolved': True}) + '\n')
                f.write(json.dumps({'ts': '2026-09-19T03:20:00.000000000Z', 'phase': 'periodic',
                                     'runtime': 'python', 'module': 'requests', 'file': requests_file,
                                     'resolved': True}) + '\n')
            used, _unresolved, evidence, held = truth.read_runtime_modules(path)
            self.assertIn(requests_file, used)
            self.assertEqual(len(evidence[requests_file]), 1)
            self.assertEqual(held[requests_file], [{'phase': 'periodic', 'ts_relative_s': None}])


class UsageExecHoldTests(unittest.TestCase):
    def test_pairs_exec_and_exit_by_pid_and_starttime(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'usage.jsonl')
            with open(path, 'w') as f:
                f.write(json.dumps({'ts': '2026-09-19T03:11:52.000000000Z', 'pid': 13, 'starttime': 100,
                                     'event': 'exec', 'path': '/usr/bin/curl', 'ok': True}) + '\n')
                f.write(json.dumps({'ts': '2026-09-19T03:11:52.013000000Z', 'pid': 13, 'starttime': 100,
                                     'event': 'exit', 'path': '/usr/bin/curl', 'ok': True, 'status': 0}) + '\n')
            holds = truth.read_usage_exec_hold_seconds(path)
            self.assertAlmostEqual(holds['/usr/bin/curl'][0], 0.013, places=3)

    def test_missing_file_returns_empty(self):
        self.assertEqual(truth.read_usage_exec_hold_seconds('/nonexistent/usage.jsonl'), {})


class EvidenceSummaryTests(unittest.TestCase):
    def test_hold_seconds_none_with_a_single_timed_observation(self):
        first, last, hold = truth._evidence_summary([{'ts_relative_s': 5.0}])
        self.assertEqual((first, last), (5.0, 5.0))
        self.assertIsNone(hold)

    def test_hold_seconds_is_span_across_observations(self):
        first, last, hold = truth._evidence_summary([{'ts_relative_s': 5.0}, {'ts_relative_s': 30.0}])
        self.assertEqual((first, last, hold), (5.0, 30.0, 25.0))

    def test_all_untimed_evidence_is_all_none(self):
        self.assertEqual(truth._evidence_summary([{'ts_relative_s': None}]), (None, None, None))


class OperationSequenceTests(unittest.TestCase):
    def test_matching_fixed_sequence_and_periodic_kinds(self):
        truth_ops = ['fired', 'render_startup_template', 'request_lazy_requests', 'osops_curl', 'osops_git', 'osops_curl']
        measurement_ops = ['fired', 'render_startup_template', 'request_lazy_requests', 'osops_curl', 'osops_git']
        ok, detail = truth.compare_operations(truth_ops, measurement_ops)
        self.assertTrue(ok, detail)

    def test_differing_fixed_sequence_is_inconsistent(self):
        truth_ops = ['fired', 'request_lazy_requests']
        measurement_ops = ['fired', 'request_lazy_sqlalchemy']
        ok, detail = truth.compare_operations(truth_ops, measurement_ops)
        self.assertFalse(ok)
        self.assertIn('fixed operation sequence differs', detail)

    def test_missing_periodic_kind_is_inconsistent(self):
        truth_ops = ['fired', 'osops_curl', 'osops_git', 'osops_openssl']
        measurement_ops = ['fired', 'osops_curl', 'osops_git']
        ok, detail = truth.compare_operations(truth_ops, measurement_ops)
        self.assertFalse(ok)
        self.assertIn('periodic operation kinds differ', detail)

    def test_missing_one_side_is_not_checked(self):
        ok, detail = truth.compare_operations(None, ['fired'])
        self.assertIsNone(ok)


class CompareOperationRecordsTests(unittest.TestCase):
    def _records(self, *ops_and_ok):
        return [{'op': op, 'ok': ok} for op, ok in ops_and_ok]

    def test_a_single_mismatched_osops_instance_is_left_unpaired_not_a_hold(self):
        # One periodic instance that succeeded in one run and not the
        # other (the first curl racing the server's readiness, say) is a
        # correspondence gap for that instance, not a different procedure:
        # the runs stay comparable, and that instance is unpaired on both
        # sides so nothing used only during it is certified through it.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', True))
        measurement_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False))
        for prefix, records in (('t', truth_records), ('m', measurement_records)):
            for i, r in enumerate(records):
                r['id'] = f'{prefix}-op-{i}'
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)
        self.assertIn('1 periodic instance(s) differ', detail)
        pairing = truth.osops_pairing_info(truth_records, measurement_records)
        self.assertEqual(pairing['paired_count'], 1)
        self.assertEqual(pairing['mismatched_truth_osops_ids'], [truth_records[2]['id']])
        self.assertIn(truth_records[2]['id'], pairing['unpaired_truth_osops_ids'])
        self.assertIn(measurement_records[2]['id'], pairing['unpaired_measurement_osops_ids'])

    def test_tolerance_counts_only_instances_that_did_pair(self):
        # 100 instances reached, 2 mismatched: 98 paired allow only one
        # mismatch (98 * 2 // 100 == 1), so two is over the line.
        truth_records = self._records(('fired', True), *[('osops_curl', True)] * 100)
        measurement_ok = [True] * 100
        measurement_ok[0] = measurement_ok[50] = False
        measurement_records = self._records(('fired', True), *[('osops_curl', ok) for ok in measurement_ok])
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('2 of 100', detail)
        # 150 reached, 2 mismatched: 148 paired allow two.
        truth_records = self._records(('fired', True), *[('osops_curl', True)] * 150)
        measurement_ok = [True] * 150
        measurement_ok[0] = measurement_ok[50] = False
        measurement_records = self._records(('fired', True), *[('osops_curl', ok) for ok in measurement_ok])
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)

    def test_more_mismatched_osops_instances_than_tolerated_is_inconsistent(self):
        truth_records = self._records(('fired', True), *[('osops_curl', True)] * 4)
        measurement_records = self._records(('fired', True), ('osops_curl', False), ('osops_curl', True),
                                             ('osops_curl', False), ('osops_curl', True))
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('2 of 4', detail)

    def test_osops_all_succeeding_in_both_runs_is_consistent(self):
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_git', True))
        measurement_records = self._records(('fired', True), ('osops_curl', True), ('osops_git', True))
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)

    def test_osops_failing_the_same_way_in_both_runs_is_consistent(self):
        truth_records = self._records(('fired', True), ('osops_openssl', False))
        measurement_records = self._records(('fired', True), ('osops_openssl', False))
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)

    def test_mixed_success_and_failure_is_told_apart_from_all_failed(self):
        # Both runs have SOME osops_curl failure, but truth's own curl
        # merely failed once amid several successes while the
        # measurement run's curl failed every single time - a
        # materially different result a bare "did it ever fail at all"
        # (or a bare success/failure COUNT) comparison could not tell
        # apart: positional comparison catches it at the very first
        # instance, where truth succeeded and measurement did not.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', True),
                                       ('osops_curl', False))
        measurement_records = self._records(('fired', True), ('osops_curl', False), ('osops_curl', False))
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('position 0', detail)
        self.assertIn('osops_curl', detail)

    def test_success_then_failure_is_told_apart_from_failure_then_success(self):
        # Both runs have exactly one success and one failure for curl
        # ("mixed" either way, and even the same 1-success/1-failure
        # count), but in opposite order - a materially different
        # outcome a count-only comparison could not tell apart at all.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False))
        measurement_records = self._records(('fired', True), ('osops_curl', False), ('osops_curl', True))
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('2 of 2', detail)

    def test_same_ordered_pattern_in_both_runs_is_consistent(self):
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False))
        measurement_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False))
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)

    def test_extra_trailing_instances_in_the_longer_run_are_not_compared(self):
        # The measurement run simply ran three more cycles than truth
        # did (or truth ran longer than the measurement run) - the
        # PAIRABLE range (the first two, here) must line up, but a
        # cycle only the longer run ever reached is neither required to
        # match anything nor treated as agreeing; it is just outside
        # what this comparison can certify.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False))
        measurement_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', False),
                                             ('osops_curl', True), ('osops_curl', True), ('osops_curl', True))
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)

    def test_mismatch_within_the_pairable_range_is_inconsistent_even_with_unequal_counts(self):
        # Different total cycle counts on their own must not excuse a
        # mismatch that occurs within the range both runs did reach.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_curl', True),
                                       ('osops_curl', True))
        measurement_records = self._records(('fired', True), ('osops_curl', False), ('osops_curl', False),
                                             ('osops_curl', True), ('osops_curl', True), ('osops_curl', True))
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('2 of 3', detail)

    def test_same_per_kind_counts_in_a_different_relative_order_is_inconsistent(self):
        # Both runs execute exactly one curl and one git cycle each -
        # the SAME total count of each kind - but truth's own loop ran
        # curl before git while the measurement run's own loop ran git
        # before curl. A per-kind-only comparison (pairing curl against
        # curl and git against git independently) would see both kinds
        # matching perfectly and miss this entirely; pairing the full
        # interleaved timeline position by position catches it.
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_git', True))
        measurement_records = self._records(('fired', True), ('osops_git', True), ('osops_curl', True))
        ok, detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertFalse(ok)
        self.assertIn('relative order', detail)

    def test_same_relative_order_each_cycle_is_consistent(self):
        truth_records = self._records(('fired', True), ('osops_curl', True), ('osops_git', True),
                                       ('osops_curl', True), ('osops_git', True))
        measurement_records = self._records(('fired', True), ('osops_curl', True), ('osops_git', True))
        ok, _detail = truth.compare_operation_records(truth_records, measurement_records)
        self.assertTrue(ok)


class OsopsSequenceTests(unittest.TestCase):
    def test_flat_interleaved_order_preserving_kind_ok_detail_and_id(self):
        records = [{'op': 'fired', 'ok': True}, {'op': 'osops_curl', 'ok': True, 'detail': 'a', 'id': 'o1'},
                   {'op': 'osops_git', 'ok': False, 'id': 'o2'}, {'op': 'osops_curl', 'ok': True, 'id': 'o3'}]
        self.assertEqual(truth.osops_sequence(records), [
            ('osops_curl', True, 'a', 'o1'),
            ('osops_git', False, None, 'o2'),
            ('osops_curl', True, None, 'o3'),
        ])


class OsopsPairingInfoTests(unittest.TestCase):
    def test_paired_and_unpaired_ids_split_at_the_shorter_sides_own_length(self):
        truth_records = [{'op': 'osops_curl', 'ok': True, 'id': 't1'},
                          {'op': 'osops_git', 'ok': True, 'id': 't2'},
                          {'op': 'osops_curl', 'ok': True, 'id': 't3'}]
        measurement_records = [{'op': 'osops_curl', 'ok': True, 'id': 'm1'},
                                {'op': 'osops_git', 'ok': True, 'id': 'm2'}]
        info = truth.osops_pairing_info(truth_records, measurement_records)
        self.assertEqual(info['paired_count'], 2)
        self.assertEqual(info['paired_truth_osops_ids'], ['t1', 't2'])
        self.assertEqual(info['paired_measurement_osops_ids'], ['m1', 'm2'])
        self.assertEqual(info['unpaired_truth_osops_ids'], ['t3'])
        self.assertEqual(info['unpaired_measurement_osops_ids'], [])


class CompareMeasurementRunRuntimeModulesTests(unittest.TestCase):
    """compare_measurement_run's own runtime-modules.jsonl gate: cases
    26-28's own workloads always produce one on the truth run, and once
    they do, the measurement run's own copy is mandatory too - missing,
    empty, or unreadable is never silently treated the same as a
    genuine match (modules_match staying None must not let 'consistent'
    default back to whatever the operation comparison alone found)."""

    def _write_ops(self, path):
        with open(path, 'w') as f:
            f.write(json.dumps({'id': 'op-1', 'op': 'fired', 'ok': True}) + '\n')

    def _write_modules(self, path, files):
        with open(path, 'w') as f:
            for p in files:
                f.write(json.dumps({'file': p, 'phase': 'startup'}) + '\n')

    def test_missing_measurement_runtime_modules_holds_when_truth_has_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            varlog = os.path.join(tmp, 'truth-run', 'varlog')
            os.makedirs(varlog)
            self._write_ops(os.path.join(varlog, 'operations.jsonl'))
            self._write_modules(os.path.join(varlog, 'runtime-modules.jsonl'), ['/app/a.py'])
            measurement_run = os.path.join(tmp, 'measurement')
            os.makedirs(measurement_run)
            self._write_ops(os.path.join(measurement_run, 'operations.jsonl'))
            # No runtime-modules.jsonl at all on the measurement side.
            truth_op_records = truth.read_operation_records(os.path.join(varlog, 'operations.jsonl'))
            result = truth.compare_measurement_run(varlog, measurement_run, truth_op_records, None)
            self.assertFalse(result['consistent'])
            self.assertIsNone(result['runtime_modules_match'])
            self.assertIn('runtime-introspection', result['detail'])

    def test_empty_measurement_runtime_modules_file_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            varlog = os.path.join(tmp, 'truth-run', 'varlog')
            os.makedirs(varlog)
            self._write_ops(os.path.join(varlog, 'operations.jsonl'))
            self._write_modules(os.path.join(varlog, 'runtime-modules.jsonl'), ['/app/a.py'])
            measurement_run = os.path.join(tmp, 'measurement')
            os.makedirs(measurement_run)
            self._write_ops(os.path.join(measurement_run, 'operations.jsonl'))
            open(os.path.join(measurement_run, 'runtime-modules.jsonl'), 'w').close()  # 0 bytes
            truth_op_records = truth.read_operation_records(os.path.join(varlog, 'operations.jsonl'))
            result = truth.compare_measurement_run(varlog, measurement_run, truth_op_records, None)
            self.assertFalse(result['consistent'])
            self.assertIsNone(result['runtime_modules_match'])

    def test_both_present_and_matching_is_consistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            varlog = os.path.join(tmp, 'truth-run', 'varlog')
            os.makedirs(varlog)
            self._write_ops(os.path.join(varlog, 'operations.jsonl'))
            self._write_modules(os.path.join(varlog, 'runtime-modules.jsonl'), ['/app/a.py'])
            measurement_run = os.path.join(tmp, 'measurement')
            os.makedirs(measurement_run)
            self._write_ops(os.path.join(measurement_run, 'operations.jsonl'))
            self._write_modules(os.path.join(measurement_run, 'runtime-modules.jsonl'), ['/app/a.py'])
            truth_op_records = truth.read_operation_records(os.path.join(varlog, 'operations.jsonl'))
            result = truth.compare_measurement_run(varlog, measurement_run, truth_op_records, None)
            self.assertTrue(result['consistent'])
            self.assertTrue(result['runtime_modules_match'])

    def test_neither_side_having_runtime_modules_never_gates_on_it(self):
        # A case (like 24) whose own workload never produces a
        # runtime-modules.jsonl at all - nothing to compare, so this
        # never blocks consistency on that basis alone.
        with tempfile.TemporaryDirectory() as tmp:
            varlog = os.path.join(tmp, 'truth-run', 'varlog')
            os.makedirs(varlog)
            self._write_ops(os.path.join(varlog, 'operations.jsonl'))
            measurement_run = os.path.join(tmp, 'measurement')
            os.makedirs(measurement_run)
            self._write_ops(os.path.join(measurement_run, 'operations.jsonl'))
            truth_op_records = truth.read_operation_records(os.path.join(varlog, 'operations.jsonl'))
            result = truth.compare_measurement_run(varlog, measurement_run, truth_op_records, None)
            self.assertTrue(result['consistent'])
            self.assertIsNone(result['runtime_modules_match'])


class SubjectClassificationTests(unittest.TestCase):
    def test_curl_git_openssl_are_short_lived(self):
        for path in ('/usr/bin/curl', '/usr/bin/git', '/usr/bin/openssl'):
            self.assertEqual(truth.classify_exec_subject(path), 'short_lived')

    def test_everything_else_is_resident(self):
        self.assertEqual(truth.classify_exec_subject('/usr/local/bin/python3'), 'resident')
        self.assertEqual(truth.classify_exec_subject('/os-ops.sh'), 'resident')

    def test_read_strace_subjects_tags_paths_by_preceding_exec(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.5'), 'w') as f:
                f.write('execve("/usr/local/bin/python3", ["python3"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3\n')
            with open(os.path.join(tmp, 'trace.6'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 3\n')
            subjects = truth.read_strace_subjects(tmp)
            self.assertEqual(subjects['/usr/local/lib/python3.12/os.py'], {'resident'})
            self.assertEqual(subjects['/etc/ssl/certs/ca-certificates.crt'], {'short_lived'})

    def test_read_strace_subjects_propagates_through_clone_without_exec(self):
        # curl (pid 6) clones a helper (pid 7) that never execs anything
        # of its own before opening a file - a certificate-loading helper
        # curl can spawn this way. The helper's own open must still be
        # attributed to the short-lived subject it inherited at the
        # moment it was cloned, not to a "resident" default.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.6'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('clone(child_stack=0x7f0000000000, flags=CLONE_VM|SIGCHLD) = 7\n')
            with open(os.path.join(tmp, 'trace.7'), 'w') as f:
                f.write('openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 3\n')
            subjects = truth.read_strace_subjects(tmp)
            self.assertEqual(subjects['/etc/ssl/certs/ca-certificates.crt'], {'short_lived'})

    def test_read_strace_subjects_resident_child_without_exec_stays_resident(self):
        # The resident program (pid 5) clones a worker thread (pid 8)
        # that never execs anything of its own; that thread's own opens
        # must stay resident, inherited the same way.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.5'), 'w') as f:
                f.write('execve("/usr/local/bin/python3", ["python3"], 0x0 /* 0 vars */) = 0\n')
                f.write('clone(child_stack=0x0, flags=CLONE_VM|CLONE_THREAD) = 8\n')
            with open(os.path.join(tmp, 'trace.8'), 'w') as f:
                f.write('openat(AT_FDCWD, "/usr/local/lib/python3.12/site-packages/flask/__init__.py", O_RDONLY) = 3\n')
            subjects = truth.read_strace_subjects(tmp)
            self.assertEqual(
                subjects['/usr/local/lib/python3.12/site-packages/flask/__init__.py'], {'resident'})

    def test_read_strace_subjects_grandchild_inherits_through_a_non_exec_hop(self):
        # curl (pid 6) clones a non-exec-ing helper (pid 7), which itself
        # clones a further child (pid 9) that opens a file. The subject
        # inherited at clone time must propagate through both hops.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.6'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('clone(child_stack=0x0, flags=SIGCHLD) = 7\n')
            with open(os.path.join(tmp, 'trace.7'), 'w') as f:
                f.write('clone(child_stack=0x0, flags=SIGCHLD) = 9\n')
            with open(os.path.join(tmp, 'trace.9'), 'w') as f:
                f.write('openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY) = 3\n')
            subjects = truth.read_strace_subjects(tmp)
            self.assertEqual(subjects['/etc/resolv.conf'], {'short_lived'})


class CloneParsingTests(unittest.TestCase):
    def test_successful_clone_returns_child_pid(self):
        self.assertEqual(
            truth.parse_clone_line('clone(child_stack=0x0, flags=SIGCHLD) = 42'), 42)

    def test_successful_vfork_returns_child_pid(self):
        self.assertEqual(truth.parse_clone_line('vfork() = 43'), 43)

    def test_successful_clone3_returns_child_pid(self):
        self.assertEqual(
            truth.parse_clone_line('clone3({flags=CLONE_VM, exit_signal=SIGCHLD}, 88) = 44'), 44)

    def test_failed_clone_is_none(self):
        line = 'clone(child_stack=0x0, flags=SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable)'
        self.assertIsNone(truth.parse_clone_line(line))

    def test_non_clone_syscall_is_none(self):
        self.assertIsNone(truth.parse_clone_line('openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'))

    def test_unfinished_line_is_none(self):
        self.assertIsNone(truth.parse_clone_line('clone(child_stack=0x0 <unfinished ...>'))


def _write_dist_info(site, name, version):
    d = os.path.join(site, f'{name}-{version}.dist-info')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'METADATA'), 'w') as f:
        f.write(f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n')


class PythonInventoryTests(unittest.TestCase):
    def test_collects_dist_info_and_egg_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = os.path.join(tmp, 'site-packages')
            os.makedirs(os.path.join(site, 'Flask-3.0.3.dist-info'))
            with open(os.path.join(site, 'Flask-3.0.3.dist-info', 'METADATA'), 'w') as f:
                f.write('Metadata-Version: 2.1\nName: Flask\nVersion: 3.0.3\n')
            os.makedirs(os.path.join(site, 'legacytool.egg-info'))
            with open(os.path.join(site, 'legacytool.egg-info', 'PKG-INFO'), 'w') as f:
                f.write('Name: legacytool\nVersion: 1.0\n')
            dists = truth.collect_python_distributions([(site, site)])
            self.assertEqual(dists.get('flask'), '3.0.3')
            self.assertEqual(dists.get('legacytool'), '1.0')


class PythonPerEnvironmentVersionTests(unittest.TestCase):
    def test_two_environments_bundling_the_same_name_are_kept_separately(self):
        # A venv pinning an older "demo" alongside a system-wide install
        # of a newer one: the per-root API must keep both versions, never
        # let the second one read silently overwrite the first's.
        with tempfile.TemporaryDirectory() as tmp:
            site_a = os.path.join(tmp, 'venv', 'site-packages')
            site_b = os.path.join(tmp, 'usr', 'site-packages')
            _write_dist_info(site_a, 'demo', '1.0')
            _write_dist_info(site_b, 'demo', '2.0')
            by_root, failures = truth.collect_python_distributions_by_root(
                [(site_a, site_a), (site_b, site_b)])
            self.assertEqual(by_root[site_a]['demo'], '1.0')
            self.assertEqual(by_root[site_b]['demo'], '2.0')
            self.assertEqual(failures, [])

    def test_used_path_resolves_to_its_own_environments_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            site_a = os.path.join(tmp, 'venv', 'site-packages')
            site_b = os.path.join(tmp, 'usr', 'site-packages')
            _write_dist_info(site_a, 'demo', '1.0')
            _write_dist_info(site_b, 'demo', '2.0')
            os.makedirs(os.path.join(site_a, 'demo'))
            open(os.path.join(site_a, 'demo', '__init__.py'), 'w').close()
            os.makedirs(os.path.join(site_b, 'demo'))
            open(os.path.join(site_b, 'demo', '__init__.py'), 'w').close()
            # RECORD, not top_level.txt, so python_owner resolves via
            # py_exact rather than the coarser prefix fallback.
            with open(os.path.join(site_a, 'demo-1.0.dist-info', 'RECORD'), 'w') as f:
                f.write('demo/__init__.py,,\n')
            with open(os.path.join(site_b, 'demo-2.0.dist-info', 'RECORD'), 'w') as f:
                f.write('demo/__init__.py,,\n')
            site_roots = [(site_a, site_a), (site_b, site_b)]
            py_exact, py_prefixes = gtb_module.build_python_index(site_roots)
            versions_by_root, _failures = truth.collect_python_distributions_by_root(site_roots)
            path_a = os.path.join(site_a, 'demo', '__init__.py')
            path_b = os.path.join(site_b, 'demo', '__init__.py')
            self.assertEqual(
                truth.python_owner_with_versions(path_a, py_exact, py_prefixes, site_roots, versions_by_root),
                [('demo', '1.0')])
            self.assertEqual(
                truth.python_owner_with_versions(path_b, py_exact, py_prefixes, site_roots, versions_by_root),
                [('demo', '2.0')])

    def test_discover_python_site_roots_finds_placements_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            venv_site = os.path.join(rootfs, 'home', 'appuser', '.venv', 'lib', 'python3.11', 'site-packages')
            _write_dist_info(venv_site, 'demo', '1.0')
            roots = truth.discover_python_site_roots(rootfs)
            image_dirs = {d for d, _local in roots}
            self.assertIn('/home/appuser/.venv/lib/python3.11/site-packages', image_dirs)


def _write_package_json(path, name, version):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump({'name': name, 'version': version}, f)


class NodeInventoryTests(unittest.TestCase):
    def test_collects_plain_and_scoped_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            nm = os.path.join(tmp, 'node_modules')
            _write_package_json(os.path.join(nm, 'express', 'package.json'), 'express', '4.17.1')
            _write_package_json(os.path.join(nm, '@scope', 'pkg', 'package.json'), '@scope/pkg', '1.0.0')
            pkgs, _owner, failures, manifests_found = truth.collect_node_packages(tmp)
            self.assertIn(('express', '4.17.1'), pkgs)
            self.assertIn(('@scope/pkg', '1.0.0'), pkgs)
            self.assertEqual(failures, [])
            self.assertEqual(manifests_found, 2)

    def test_two_nested_versions_of_the_same_name_are_both_kept(self):
        # npm's own hoisting: the top-level copy is one version, and a
        # package that needed an incompatible version gets its own nested
        # copy under its own node_modules.
        with tempfile.TemporaryDirectory() as tmp:
            top_nm = os.path.join(tmp, 'node_modules')
            _write_package_json(os.path.join(top_nm, 'ms', 'package.json'), 'ms', '2.1.3')
            nested_nm = os.path.join(top_nm, 'send', 'node_modules')
            _write_package_json(os.path.join(nested_nm, 'ms', 'package.json'), 'ms', '2.0.0')
            pkgs, _owner, _failures, _n = truth.collect_node_packages(tmp)
            self.assertIn(('ms', '2.1.3'), pkgs)
            self.assertIn(('ms', '2.0.0'), pkgs)
            self.assertEqual(sum(1 for name, _v in pkgs if name == 'ms'), 2)

    def test_collects_a_global_install_and_nodes_own_bundled_npm(self):
        # A global npm install (including Node's own bundled npm/corepack
        # tooling) is found the same way the application's own bundled
        # tree is: the bundled-package population this is meant to match
        # is Trivy's own --list-all-pkgs population, which lists npm's
        # own vendored dependencies too - excluding them would undercount
        # against that population, not correct it.
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            _write_package_json(os.path.join(rootfs, 'app', 'node_modules', 'express', 'package.json'),
                                 'express', '4.17.1')
            _write_package_json(
                os.path.join(rootfs, 'usr', 'local', 'lib', 'node_modules', 'npm', 'package.json'), 'npm', '10.0.0')
            _write_package_json(
                os.path.join(rootfs, 'usr', 'local', 'lib', 'node_modules', 'npm', 'node_modules',
                              'semver', 'package.json'),
                'semver', '7.6.0')
            pkgs, _owner, _failures, manifests_found = truth.collect_node_packages(rootfs)
            self.assertIn(('express', '4.17.1'), pkgs)
            self.assertIn(('npm', '10.0.0'), pkgs)
            self.assertIn(('semver', '7.6.0'), pkgs)
            self.assertEqual(manifests_found, 3)

    def test_collects_a_manifest_outside_any_node_modules_directory(self):
        # The workload's own root package.json, and any other tool's own
        # bundled manifest laid down outside node_modules entirely (an
        # extracted yarn distribution, say), are both found: Trivy's own
        # node-pkg population is not limited to node_modules-nested
        # manifests either.
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            _write_package_json(os.path.join(rootfs, 'app', 'package.json'), 'my-app', '1.0.0')
            _write_package_json(os.path.join(rootfs, 'opt', 'yarn-v1.22.22', 'package.json'), 'yarn', '1.22.22')
            pkgs, _owner, _failures, manifests_found = truth.collect_node_packages(rootfs)
            self.assertIn(('my-app', '1.0.0'), pkgs)
            self.assertIn(('yarn', '1.22.22'), pkgs)
            self.assertEqual(manifests_found, 2)

    def test_manifest_missing_name_or_version_is_a_read_failure_not_a_guess(self):
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            manifest = os.path.join(rootfs, 'opt', 'incomplete', 'package.json')
            os.makedirs(os.path.dirname(manifest))
            with open(manifest, 'w') as f:
                json.dump({'name': 'no-version-here'}, f)
            pkgs, owner, failures, manifests_found = truth.collect_node_packages(rootfs)
            self.assertEqual(pkgs, set())
            self.assertEqual(owner, {})
            self.assertEqual(manifests_found, 1)
            self.assertEqual(len(failures), 1)

    def test_manifest_owner_is_keyed_by_the_manifests_own_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            _write_package_json(os.path.join(rootfs, 'app', 'package.json'), 'my-app', '1.0.0')
            _pkgs, owner, _failures, _n = truth.collect_node_packages(rootfs)
            self.assertEqual(owner.get('/app'), ('my-app', '1.0.0'))


class NearestOwningManifestTests(unittest.TestCase):
    def test_resolves_to_the_nearest_enclosing_manifests_own_version(self):
        manifest_owner = {'/app/node_modules/ms': ('ms', '2.1.3'),
                           '/app/node_modules/send/node_modules/ms': ('ms', '2.0.0')}
        self.assertEqual(
            truth.nearest_owning_manifest('/app/node_modules/ms/index.js', manifest_owner), ('ms', '2.1.3'))
        self.assertEqual(
            truth.nearest_owning_manifest('/app/node_modules/send/node_modules/ms/index.js', manifest_owner),
            ('ms', '2.0.0'))

    def test_resolves_to_the_workloads_own_root_manifest_outside_node_modules(self):
        manifest_owner = {'/app': ('my-app', '1.0.0')}
        self.assertEqual(truth.nearest_owning_manifest('/app/server.js', manifest_owner), ('my-app', '1.0.0'))

    def test_no_enclosing_manifest_is_none(self):
        self.assertIsNone(truth.nearest_owning_manifest('/etc/hosts', {}))


def _jar_bytes(group, artifact, version):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr(f'META-INF/maven/{group}/{artifact}/pom.properties',
                     f'groupId={group}\nartifactId={artifact}\nversion={version}\n')
    return buf.getvalue()


class JavaInventoryTests(unittest.TestCase):
    def test_read_jar_pom_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = os.path.join(tmp, 'commons-io-2.15.1.jar')
            with open(jar_path, 'wb') as f:
                f.write(_jar_bytes('commons-io', 'commons-io', '2.15.1'))
            versions = truth.read_jar_pom_versions(jar_path)
            self.assertEqual(versions.get('commons-io:commons-io'), '2.15.1')

    def test_collect_java_jars_separates_versioned_from_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = os.path.join(tmp, 'app')
            os.makedirs(os.path.join(app, 'lazy'))
            with open(os.path.join(app, 'lazy', 'commons-io-2.15.1.jar'), 'wb') as f:
                f.write(_jar_bytes('commons-io', 'commons-io', '2.15.1'))
            # A jar with no pom.properties at all and a name that does not
            # even look versioned: unowned, and (with no name a plan
            # comparison could use) reported as version-unknown by file name.
            with zipfile.ZipFile(os.path.join(app, 'app.jar'), 'w') as zf:
                zf.writestr('App.class', b'\x00')
            versioned, unknown, read_failures = truth.collect_java_jars(app)
            self.assertIn(('commons-io:commons-io', '2.15.1'), versioned)
            unknown_names = {u['name'] for u in unknown}
            self.assertIn('app.jar', unknown_names)
            self.assertEqual(read_failures, [])

    def test_collect_java_jars_scans_beyond_the_application_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = os.path.join(tmp, 'rootfs')
            os.makedirs(os.path.join(rootfs, 'opt', 'extra'))
            with open(os.path.join(rootfs, 'opt', 'extra', 'commons-io-2.15.1.jar'), 'wb') as f:
                f.write(_jar_bytes('commons-io', 'commons-io', '2.15.1'))
            versioned, _unknown, _failures = truth.collect_java_jars(rootfs)
            self.assertIn(('commons-io:commons-io', '2.15.1'), versioned)


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        for rec in records:
            f.write(json.dumps(rec) + '\n')


class OperationIntervalTests(unittest.TestCase):
    def test_fixed_operation_paired_with_its_own_occurrence_start_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops = os.path.join(tmp, 'operations.jsonl')
            occ = os.path.join(tmp, 'occurrences.jsonl')
            usage = os.path.join(tmp, 'usage.jsonl')
            _write_jsonl(ops, [{'id': '26-op-000001', 'ts': '2026-09-19T03:12:00.000000Z',
                                 'op': 'render_startup_template', 'ok': True}])
            _write_jsonl(occ, [{'id': '26-load-000001', 'kind': 'load',
                                 'start': '2026-09-19T03:11:59.500000Z',
                                 'end': '2026-09-19T03:12:00.000000Z'}])
            intervals = truth.read_operation_intervals(ops, occ, usage)
            self.assertEqual(len(intervals), 1)
            self.assertTrue(intervals[0]['paired'])
            self.assertEqual(intervals[0]['op'], 'render_startup_template')
            self.assertEqual(intervals[0]['start'],
                              datetime(2026, 9, 19, 3, 11, 59, 500000, tzinfo=timezone.utc))
            self.assertEqual(intervals[0]['end'],
                              datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc))

    def test_osops_operation_paired_via_usage_exec_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops = os.path.join(tmp, 'operations.jsonl')
            occ = os.path.join(tmp, 'occurrences.jsonl')
            usage = os.path.join(tmp, 'usage.jsonl')
            _write_jsonl(ops, [{'id': '26-op-osops-000001', 'ts': '2026-09-19T03:12:00.000000Z',
                                 'op': 'osops_curl', 'ok': True}])
            _write_jsonl(occ, [{'id': '26-exec-osops-000001', 'kind': 'exec',
                                 'pid': 13, 'starttime': 100}])
            _write_jsonl(usage, [
                {'ts': '2026-09-19T03:12:00.100000Z', 'pid': 13, 'starttime': 100,
                 'event': 'exec', 'path': '/usr/bin/curl', 'ok': True},
                {'ts': '2026-09-19T03:12:00.113000Z', 'pid': 13, 'starttime': 100,
                 'event': 'exit', 'path': '/usr/bin/curl', 'ok': True, 'status': 0},
            ])
            intervals = truth.read_operation_intervals(ops, occ, usage)
            self.assertEqual(len(intervals), 1)
            self.assertTrue(intervals[0]['paired'])
            self.assertEqual(intervals[0]['start'],
                              datetime(2026, 9, 19, 3, 12, 0, 100000, tzinfo=timezone.utc))
            self.assertEqual(intervals[0]['end'],
                              datetime(2026, 9, 19, 3, 12, 0, 113000, tzinfo=timezone.utc))

    def test_two_occurrence_less_operations_do_not_shift_later_pairings(self):
        # "fired" and a second one-time operation (as case 28's own
        # "startup_use" does) both have no occurrence of their own, ahead
        # of an operation that does. Positional consumption would
        # misattribute the one real occurrence to the second
        # occurrence-less operation instead of the operation it actually
        # belongs to.
        with tempfile.TemporaryDirectory() as tmp:
            ops = os.path.join(tmp, 'operations.jsonl')
            occ = os.path.join(tmp, 'occurrences.jsonl')
            usage = os.path.join(tmp, 'usage.jsonl')
            _write_jsonl(ops, [
                {'id': '28-op-000001', 'ts': '2026-09-19T03:12:00.000000Z', 'op': 'fired', 'ok': True},
                {'id': '28-op-000002', 'ts': '2026-09-19T03:12:00.050000Z', 'op': 'startup_use', 'ok': True},
                {'id': '28-op-000003', 'ts': '2026-09-19T03:12:01.000000Z', 'op': 'request_lazy_jackson', 'ok': True},
            ])
            _write_jsonl(occ, [{'id': '28-load-000001', 'kind': 'load',
                                 'start': '2026-09-19T03:12:00.900000Z',
                                 'end': '2026-09-19T03:12:01.000000Z'}])
            intervals = truth.read_operation_intervals(ops, occ, usage)
            by_op = {i['op']: i for i in intervals}
            self.assertFalse(by_op['fired']['paired'])
            self.assertFalse(by_op['startup_use']['paired'])
            self.assertTrue(by_op['request_lazy_jackson']['paired'])
            self.assertEqual(by_op['request_lazy_jackson']['start'],
                              datetime(2026, 9, 19, 3, 12, 0, 900000, tzinfo=timezone.utc))

    def test_operation_without_matching_occurrence_falls_back_to_zero_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            ops = os.path.join(tmp, 'operations.jsonl')
            _write_jsonl(ops, [{'id': '26-op-000001', 'ts': '2026-09-19T03:11:50.000000Z',
                                 'op': 'fired', 'ok': True}])
            intervals = truth.read_operation_intervals(
                ops, os.path.join(tmp, 'occurrences.jsonl'), os.path.join(tmp, 'usage.jsonl'))
            self.assertEqual(len(intervals), 1)
            self.assertFalse(intervals[0]['paired'])
            self.assertEqual(intervals[0]['start'], intervals[0]['end'])


class ClassifyEvidencePeriodTests(unittest.TestCase):
    def setUp(self):
        self.fired_at = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        self.stopped_at = datetime(2026, 9, 19, 3, 27, 0, 0, tzinfo=timezone.utc)
        self.operation_intervals = [
            {'op': 'request_lazy_requests',
             'start': datetime(2026, 9, 19, 3, 12, 5, 0, tzinfo=timezone.utc),
             'end': datetime(2026, 9, 19, 3, 12, 6, 0, tzinfo=timezone.utc)},
        ]

    def test_before_firing_is_startup(self):
        kind, op, exact = truth.classify_evidence_period(
            self.fired_at - timedelta(seconds=5), self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('startup', None, True))

    def test_at_or_after_stop_is_post_stop(self):
        kind, op, exact = truth.classify_evidence_period(
            self.stopped_at, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('post_stop', None, True))

    def test_inside_an_operations_own_span_names_it(self):
        kind, op, exact = truth.classify_evidence_period(
            datetime(2026, 9, 19, 3, 12, 5, 500000, tzinfo=timezone.utc),
            self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('operation', 'request_lazy_requests', True))

    def test_between_operations_is_unattributed(self):
        kind, op, exact = truth.classify_evidence_period(
            datetime(2026, 9, 19, 3, 20, 0, 0, tzinfo=timezone.utc),
            self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('unattributed', None, True))

    def test_within_tolerance_but_not_strictly_contained_is_nearest(self):
        # 1.5s after the span's own end - outside strict containment,
        # within the 1s tolerance is false (1.5 > 1.0), so this should
        # NOT match; a case just inside the tolerance should.
        kind, op, exact = truth.classify_evidence_period(
            datetime(2026, 9, 19, 3, 12, 6, 500000, tzinfo=timezone.utc),  # +0.5s past end
            self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('operation', 'request_lazy_requests', False))

    def test_beyond_tolerance_is_unattributed(self):
        kind, op, exact = truth.classify_evidence_period(
            datetime(2026, 9, 19, 3, 12, 8, 0, tzinfo=timezone.utc),  # +2s past end
            self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual((kind, op, exact), ('unattributed', None, True))


class AttributeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fired_at = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        self.stopped_at = datetime(2026, 9, 19, 3, 27, 0, 0, tzinfo=timezone.utc)
        self.operation_intervals = [
            {'op': 'request_lazy_requests',
             'start': datetime(2026, 9, 19, 3, 12, 5, 0, tzinfo=timezone.utc),
             'end': datetime(2026, 9, 19, 3, 12, 6, 0, tzinfo=timezone.utc)},
        ]

    def test_startup_only_evidence(self):
        evidence = [{'ts_relative_s': -2.0}]
        used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertTrue(used_at_startup)
        self.assertEqual(ops, [])
        self.assertEqual(counts['startup'], 1)

    def test_operation_evidence(self):
        evidence = [{'ts_relative_s': 5.5}]  # 03:12:05.5, inside the span
        used_at_startup, ops, counts, offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, ['request_lazy_requests'])
        self.assertEqual(counts['operations'], {'request_lazy_requests': 1})
        # 0.5s past THIS instance's own start (03:12:05.0), never past
        # firing overall (which would be 5.5s).
        self.assertAlmostEqual(offsets['request_lazy_requests'], 0.5, places=3)

    def test_operation_offset_takes_the_earliest_use_within_the_operation(self):
        evidence = [{'ts_relative_s': 5.8}, {'ts_relative_s': 5.2}]
        _used_at_startup, _ops, _counts, offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertAlmostEqual(offsets['request_lazy_requests'], 0.2, places=3)

    def test_post_stop_evidence_does_not_count_as_startup_or_any_operation(self):
        evidence = [{'ts_relative_s': 20 * 60.0}]  # long after stop
        used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, [])
        self.assertEqual(counts['post_stop'], 1)

    def test_no_fired_at_attributes_nothing(self):
        evidence = [{'ts_relative_s': -2.0}]
        used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, None, self.stopped_at, self.operation_intervals)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, [])
        self.assertEqual(counts, {'startup': 0, 'operations': {}, 'operations_nearest': {},
                                   'post_stop': 0, 'unattributed': 0})

    def test_untimed_evidence_is_ignored(self):
        evidence = [{'ts_relative_s': None}]
        used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, [])
        self.assertEqual(sum(counts['operations'].values()) + counts['startup']
                          + counts['post_stop'] + counts['unattributed'], 0)

    def test_resident_evidence_within_tolerance_is_marked_nearest(self):
        # 0.4s past the span's own end: outside strict containment, but
        # within the 1s tolerance resident evidence gets.
        evidence = [{'ts_relative_s': 6.4, 'pid': None}]
        _used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual(ops, ['request_lazy_requests'])
        self.assertEqual(counts['operations'], {'request_lazy_requests': 1})
        self.assertEqual(counts['operations_nearest'], {'request_lazy_requests': 1})

    def test_runtime_introspection_evidence_never_uses_the_nearest_fallback(self):
        # A snapshot's own timestamp is always at-or-after the actual
        # load (a periodic dump taken once, well after the operation
        # that really loaded the module already finished) - never
        # "nearby" the way strace's own per-syscall drift is. The same
        # 0.4s-past-the-end instant that a strace-sourced (or untagged)
        # evidence record would get "nearest"-attributed for must be
        # left unattributed for a runtime_introspection-sourced one -
        # this is the exact real-world case (a package's own
        # after-the-fact snapshot sighting nearest-matching a LATER,
        # unrelated operation) this guards against.
        evidence = [{'ts_relative_s': 6.4, 'pid': None, 'source': 'runtime_introspection'}]
        _used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual(ops, [])
        self.assertEqual(counts['operations'], {})
        self.assertEqual(counts['unattributed'], 1)

    def test_runtime_introspection_evidence_still_matches_strict_containment(self):
        evidence = [{'ts_relative_s': 5.5, 'pid': None, 'source': 'runtime_introspection'}]
        _used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, self.operation_intervals)
        self.assertEqual(ops, ['request_lazy_requests'])
        self.assertEqual(counts['operations_nearest'], {})


class PidBasedAttributionTests(unittest.TestCase):
    """Short-lived (osops) evidence is attributed by pid, sidestepping
    the strace/shell-script timing drift that otherwise leaves most of a
    short-lived command's own evidence outside even its own operation's
    reconstructed span - the exact problem observed against a real truth
    run before this attribution path was added."""

    def setUp(self):
        self.fired_at = datetime(2026, 9, 19, 3, 12, 0, 0, tzinfo=timezone.utc)
        self.stopped_at = datetime(2026, 9, 19, 3, 27, 0, 0, tzinfo=timezone.utc)
        # osops_curl's own instance: pid 501 is the exact pid occurrences.jsonl
        # named as the one that execs curl directly.
        self.pid_to_interval = {
            501: {'op': 'osops_curl',
                  'start': datetime(2026, 9, 19, 3, 12, 5, 0, tzinfo=timezone.utc),
                  'end': datetime(2026, 9, 19, 3, 12, 5, 1, tzinfo=timezone.utc)},
        }

    def test_pid_match_attributes_regardless_of_its_own_drifted_timestamp(self):
        # strace's own timestamp for this evidence (relative -50s, i.e.
        # long before firing) would, read literally, say "startup" - but
        # the pid ties it to osops_curl's own instance, whose interval
        # places it firmly mid-run. The pid match must win.
        evidence = [{'pid': 502, 'ts_relative_s': -50.0}]
        root_pid_by_pid = {502: 501}  # pid 502 is curl's own child/thread
        used_at_startup, ops, counts, offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, [],
            root_pid_by_pid=root_pid_by_pid, pid_to_interval=self.pid_to_interval)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, ['osops_curl'])
        self.assertEqual(counts['operations'], {'osops_curl': 1})
        self.assertEqual(counts['operations_nearest'], {})
        # The offset itself still uses this evidence's own actual
        # instant (ts_relative_s=-50.0, i.e. -50s from firing), not the
        # matched instance's own start (5s from firing) substituted in
        # for it - only PERIOD classification (startup/operation/
        # post_stop) is decided by the pid-matched interval, to sidestep
        # strace's own drift; the offset genuinely measures -55.0s
        # relative to that instance's own start, drifted timestamp and
        # all, since a caller mapping it onto a measurement run's own
        # instance has nothing else to go on.
        self.assertAlmostEqual(offsets['osops_curl'], -55.0, places=3)

    def test_pid_matched_offset_uses_the_evidences_own_instant_not_the_instances_start(self):
        # The exact counterexample: this package's own strace evidence
        # was recorded 30s after osops_curl's own instance started on
        # the TRUTH run. Substituting the instance's own start for the
        # evidence's own instant (the bug this replaces) would silently
        # report an offset of 0.0 instead of 30.0.
        evidence = [{'pid': 501, 'ts_relative_s': 35.0}]  # instance starts at 5s, +30s
        used_at_startup, ops, _counts, offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, [],
            root_pid_by_pid={501: 501}, pid_to_interval=self.pid_to_interval)
        self.assertFalse(used_at_startup)
        self.assertEqual(ops, ['osops_curl'])
        self.assertAlmostEqual(offsets['osops_curl'], 30.0, places=3)

    def test_pid_matched_instance_before_firing_is_startup(self):
        early_pid_to_interval = {
            501: {'op': 'osops_curl',
                  'start': datetime(2026, 9, 19, 3, 11, 58, 0, tzinfo=timezone.utc),
                  'end': datetime(2026, 9, 19, 3, 11, 58, 1, tzinfo=timezone.utc)},
        }
        evidence = [{'pid': 501, 'ts_relative_s': -55.0}]
        used_at_startup, ops, _counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, [],
            root_pid_by_pid={501: 501}, pid_to_interval=early_pid_to_interval)
        self.assertTrue(used_at_startup)
        self.assertEqual(ops, [])

    def test_short_lived_pid_with_no_recorded_instance_is_unattributed(self):
        # This run's own process-tree reconstruction says pid 999 is a
        # short-lived descendant, but no osops instance in
        # operations.jsonl names 999 as its own launching pid (a
        # truncated log, say) - never guessed at by timestamp for this
        # subject.
        evidence = [{'pid': 999, 'ts_relative_s': 5.5}]
        _used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, [],
            root_pid_by_pid={999: 999}, pid_to_interval={})
        self.assertEqual(ops, [])
        self.assertEqual(counts['unattributed'], 1)

    def test_resident_pid_falls_back_to_timestamp(self):
        # root_pid_by_pid maps this pid to None (resident): falls through
        # to the ordinary timestamp-based path against operation_intervals.
        operation_intervals = [{'op': 'request_lazy_requests',
                                 'start': datetime(2026, 9, 19, 3, 12, 5, 0, tzinfo=timezone.utc),
                                 'end': datetime(2026, 9, 19, 3, 12, 6, 0, tzinfo=timezone.utc)}]
        evidence = [{'pid': 100, 'ts_relative_s': 5.5}]
        _used_at_startup, ops, counts, _offsets, _instances, _instance_offsets = truth.attribute_evidence(
            evidence, self.fired_at, self.stopped_at, operation_intervals,
            root_pid_by_pid={100: None}, pid_to_interval=self.pid_to_interval)
        self.assertEqual(ops, ['request_lazy_requests'])
        self.assertEqual(counts['operations_nearest'], {})


class SimulateProcessTreeRootPidTests(unittest.TestCase):
    def test_root_pid_is_the_pid_that_execs_the_short_lived_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.501'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('clone(child_stack=0x0, flags=SIGCHLD) = 502\n')
            with open(os.path.join(tmp, 'trace.502'), 'w') as f:
                f.write('openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 3\n')
            _subjects, root_pid_by_pid, _missing = truth._simulate_process_tree(tmp)
            self.assertEqual(root_pid_by_pid[501], 501)
            self.assertEqual(root_pid_by_pid[502], 501)

    def test_resident_pid_has_no_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.100'), 'w') as f:
                f.write('execve("/usr/local/bin/python3", ["python3"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(AT_FDCWD, "/usr/local/lib/python3.12/os.py", O_RDONLY) = 3\n')
            _subjects, root_pid_by_pid, _missing = truth._simulate_process_tree(tmp)
            self.assertIsNone(root_pid_by_pid[100])

    def test_short_lived_pid_stays_short_lived_after_execing_a_different_program(self):
        # git commonly re-execs into a remote helper (git-remote-https,
        # say) that is not itself one of the three named short-lived
        # commands; the pid must not be demoted back to resident just
        # because its own later exec target is unrecognized.
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.600'), 'w') as f:
                f.write('execve("/usr/bin/git", ["git", "log"], 0x0 /* 0 vars */) = 0\n')
                f.write('execve("/usr/lib/git-core/git-remote-https", ["git-remote-https"], 0x0 /* 0 vars */) = 0\n')
                f.write('openat(AT_FDCWD, "/etc/gitconfig", O_RDONLY) = 3\n')
            subjects, root_pid_by_pid, _missing = truth._simulate_process_tree(tmp)
            self.assertEqual(subjects['/etc/gitconfig'], {'short_lived'})
            self.assertEqual(root_pid_by_pid[600], 600)

    def test_missing_clone_target_trace_file_does_not_raise(self):
        # trace.501 reports cloning pid 999, but this run's own strace
        # directory carries no trace.999 at all (lost, or the process
        # exited before anything of its own was captured).
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'trace.501'), 'w') as f:
                f.write('execve("/usr/bin/curl", ["curl"], 0x0 /* 0 vars */) = 0\n')
                f.write('clone(child_stack=0x0, flags=SIGCHLD) = 999\n')
            _subjects, root_pid_by_pid, missing = truth._simulate_process_tree(tmp)
            self.assertEqual(missing, [999])
            self.assertEqual(root_pid_by_pid[501], 501)
            # pid 999 is still walked (it is reachable via the clone
            # edge) so its own inherited root is still recorded, even
            # though it contributes no events of its own.
            self.assertEqual(root_pid_by_pid[999], 501)


class ResolveRootfsPathTests(unittest.TestCase):
    def test_awk_resolves_through_alternatives_to_mawk(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            os.makedirs(os.path.join(rootfs, 'etc', 'alternatives'))
            open(os.path.join(rootfs, 'usr', 'bin', 'mawk'), 'w').close()
            os.symlink('/etc/alternatives/awk', os.path.join(rootfs, 'usr', 'bin', 'awk'))
            os.symlink('/usr/bin/mawk', os.path.join(rootfs, 'etc', 'alternatives', 'awk'))
            final, state = truth.resolve_rootfs_path('/usr/bin/awk', rootfs)
            self.assertEqual(final, '/usr/bin/mawk')
            self.assertEqual(state, 'resolved')

    def test_relative_symlink_target_resolves_against_its_own_directory(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            open(os.path.join(rootfs, 'usr', 'bin', 'real'), 'w').close()
            os.symlink('real', os.path.join(rootfs, 'usr', 'bin', 'link'))
            final, state = truth.resolve_rootfs_path('/usr/bin/link', rootfs)
            self.assertEqual(final, '/usr/bin/real')
            self.assertEqual(state, 'resolved')

    def test_non_symlink_path_is_returned_unchanged(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            open(os.path.join(rootfs, 'usr', 'bin', 'curl'), 'w').close()
            final, state = truth.resolve_rootfs_path('/usr/bin/curl', rootfs)
            self.assertEqual(final, '/usr/bin/curl')
            self.assertEqual(state, 'resolved')

    def test_broken_link_target_is_reported_broken(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            os.symlink('/usr/bin/does-not-exist', os.path.join(rootfs, 'usr', 'bin', 'awk'))
            final, state = truth.resolve_rootfs_path('/usr/bin/awk', rootfs)
            self.assertEqual(state, 'broken')

    def test_circular_link_is_reported_broken(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            os.symlink('/usr/bin/b', os.path.join(rootfs, 'usr', 'bin', 'a'))
            os.symlink('/usr/bin/a', os.path.join(rootfs, 'usr', 'bin', 'b'))
            _final, state = truth.resolve_rootfs_path('/usr/bin/a', rootfs)
            self.assertEqual(state, 'broken')

    def test_no_rootfs_is_unavailable(self):
        final, state = truth.resolve_rootfs_path('/usr/bin/awk', None)
        self.assertEqual(final, '/usr/bin/awk')
        self.assertEqual(state, 'unavailable')

    def test_path_absent_from_this_rootfs_with_no_symlink_involved_is_resolved_unchanged(self):
        # A path this run observed being used is not necessarily one
        # this run's own export ever captured (an ephemeral file under
        # a tmpfs mount like /run, say) - that is a fact about the
        # path's own place in the filesystem, never a broken link this
        # function found, and must not be flagged as a completeness gap
        # (see os_symlink_resolution_failures). The whole original path
        # comes back unchanged, not a partial prefix of it, so a caller
        # comparing resolved_path != path sees no difference at all.
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'run'))
            final, state = truth.resolve_rootfs_path('/run/fire/container-id', rootfs)
            self.assertEqual(final, '/run/fire/container-id')
            self.assertEqual(state, 'resolved')

    def test_missing_component_after_following_a_link_is_still_broken(self):
        # The counterpart: once a symlink's own target has actually been
        # substituted in, a missing component from then on IS a genuine
        # dangling link, not merely an unexported path.
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            os.makedirs(os.path.join(rootfs, 'opt'))
            os.symlink('/opt/real-tool', os.path.join(rootfs, 'usr', 'bin', 'tool'))
            final, state = truth.resolve_rootfs_path('/usr/bin/tool', rootfs)
            self.assertEqual(state, 'broken')
            self.assertEqual(final, '/opt/real-tool')

    def test_intermediate_absolute_symlink_is_re_rooted_at_the_rootfs_not_the_host(self):
        # /var/run -> /etc (an absolute-target INTERMEDIATE directory
        # symlink, not the final component) must resolve against this
        # rootfs's own "/etc", never the host's real /etc - which this
        # test environment's own host almost certainly has, with its own
        # unrelated passwd file, completely independent of this
        # fixture's own rootfs.
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'var'))
            os.makedirs(os.path.join(rootfs, 'etc'))
            with open(os.path.join(rootfs, 'etc', 'passwd'), 'w') as f:
                f.write('fixture-marker-not-the-hosts-own-passwd\n')
            os.symlink('/etc', os.path.join(rootfs, 'var', 'run'))
            final, state = truth.resolve_rootfs_path('/var/run/passwd', rootfs)
            self.assertEqual(final, '/etc/passwd')
            self.assertEqual(state, 'resolved')
            # Reading through the same rootfs-local mapping must reach
            # THIS fixture's own file, not whatever the host's real
            # /etc/passwd contains.
            local = truth._rootfs_local_path(rootfs, final)
            with open(local) as f:
                self.assertEqual(f.read(), 'fixture-marker-not-the-hosts-own-passwd\n')

    def test_intermediate_absolute_symlink_to_a_path_absent_from_this_rootfs_is_broken(self):
        # The same /var/run -> /etc redirection, but this rootfs's own
        # /etc/passwd does not exist - proving resolution does NOT fall
        # back to the host's own real /etc/passwd (which almost
        # certainly does exist) to call this "resolved" anyway.
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'var'))
            os.makedirs(os.path.join(rootfs, 'etc'))
            os.symlink('/etc', os.path.join(rootfs, 'var', 'run'))
            _final, state = truth.resolve_rootfs_path('/var/run/passwd', rootfs)
            self.assertEqual(state, 'broken')

    def test_stat_based_directory_check_uses_the_same_resolution(self):
        # _is_directory_in_rootfs must not stat a raw, unresolved local
        # path either - the same intermediate-symlink escape would
        # apply to it just as much as to ownership lookup.
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'var'))
            os.makedirs(os.path.join(rootfs, 'real-run'))
            os.symlink('/real-run', os.path.join(rootfs, 'var', 'run'))
            self.assertTrue(truth._is_directory_in_rootfs('/var/run', rootfs))

    def test_resolve_used_path_credits_the_alternatives_target_package(self):
        with tempfile.TemporaryDirectory() as rootfs:
            os.makedirs(os.path.join(rootfs, 'usr', 'bin'))
            os.makedirs(os.path.join(rootfs, 'etc', 'alternatives'))
            open(os.path.join(rootfs, 'usr', 'bin', 'mawk'), 'w').close()
            os.symlink('/etc/alternatives/awk', os.path.join(rootfs, 'usr', 'bin', 'awk'))
            os.symlink('/usr/bin/mawk', os.path.join(rootfs, 'etc', 'alternatives', 'awk'))
            context = {
                'owners': {'/usr/bin/mawk': {'mawk'}}, 'os_versions': {'mawk': '1.3.4'},
                'py_exact': {}, 'py_prefixes': [], 'py_site_roots': [], 'py_versions_by_root': {},
                'rootfs_dir': rootfs, 'os_db_available': True, 'node_manifest_owner': {},
                'os_symlink_resolution_failures': [],
            }
            keys = truth.resolve_used_path('/usr/bin/awk', context)
            self.assertIn(('os', 'mawk', '1.3.4'), keys)


class DeclarationGapsTests(unittest.TestCase):
    def test_missing_and_extra_are_reported_separately(self):
        case = {
            'case_id': '26',
            'coverage_plan': {
                'used_at_startup': ['flask', 'never-installed'],
                'used_lazily': [], 'unused': [],
            },
        }
        inventory = {
            ('python', 'flask', '3.0.3'): {}, ('python', 'greenlet', '3.5.6'): {},
            ('os', 'curl', '8.14.1'): {},
        }
        missing, extra = truth.declaration_gaps(case, inventory)
        self.assertEqual(missing, ['never-installed'])
        self.assertEqual(extra, ['greenlet'])

    def test_unknown_case_id_is_a_no_op(self):
        missing, extra = truth.declaration_gaps({'case_id': '99'}, {})
        self.assertEqual((missing, extra), ([], []))


class RootfsExportDiskSpaceTests(unittest.TestCase):
    """_check_rootfs_export_disk_space's own pre-flight gate: it must
    refuse to let export_container_rootfs touch `docker export` or the
    tar extraction at all once tmp's own filesystem cannot plausibly
    hold both (see _required_rootfs_export_bytes), rather than
    discovering that partway through - see the ENOSPC-mid-extraction
    incident this hardening responds to (a full /tmp let rootfs
    extraction fail silently, and truth.py still exited 0)."""

    def test_raises_when_free_space_is_less_than_required(self):
        with mock.patch('subprocess.run') as run_mock, \
                mock.patch('shutil.disk_usage') as disk_usage_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                ['docker', 'image', 'inspect'], 0, stdout='1000\n', stderr='')
            disk_usage_mock.return_value = mock.Mock(free=500)  # required is 2x1000=2000
            with self.assertRaises(OSError):
                truth._check_rootfs_export_disk_space('img:tag', '/some/tmp')

    def test_does_not_raise_when_free_space_is_sufficient(self):
        with mock.patch('subprocess.run') as run_mock, \
                mock.patch('shutil.disk_usage') as disk_usage_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                ['docker', 'image', 'inspect'], 0, stdout='1000\n', stderr='')
            disk_usage_mock.return_value = mock.Mock(free=10_000)
            truth._check_rootfs_export_disk_space('img:tag', '/some/tmp')  # must not raise

    def test_docker_image_inspect_failure_is_an_oserror(self):
        with mock.patch('subprocess.run') as run_mock:
            run_mock.return_value = subprocess.CompletedProcess(
                ['docker', 'image', 'inspect'], 1, stdout='', stderr='no such image')
            with self.assertRaises(OSError):
                truth._check_rootfs_export_disk_space('img:tag', '/some/tmp')


def _build_two_member_tar(path):
    """A small, well-formed tar with two members, for
    TarCompletenessTests below to truncate at specific byte offsets."""
    with tarfile.open(path, 'w') as tf:
        for name, content in (('a.txt', b'hello'), ('b.txt', b'world!!')):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))


class TarCompletenessTests(unittest.TestCase):
    """_verify_tar_completeness's own defense against exactly what
    tarfile.open()'s own member-by-member reading misses: a tar cut off
    at a point that still looks, to tarfile's own lenient header reader,
    like an ordinary end of archive rather than a truncation: cutting a
    two-member tar at either 512 or 612 bytes still leaves plain
    tarfile.open() reporting one complete member and no error at all."""

    def test_complete_tar_passes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'rootfs.tar')
            _build_two_member_tar(path)
            truth._verify_tar_completeness(path)  # must not raise

    def test_truncated_at_512_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            complete_path = os.path.join(d, 'rootfs.tar')
            _build_two_member_tar(complete_path)
            data = open(complete_path, 'rb').read()
            truncated_path = os.path.join(d, 'truncated.tar')
            with open(truncated_path, 'wb') as f:
                f.write(data[:512])
            with self.assertRaises(OSError):
                truth._verify_tar_completeness(truncated_path)

    def test_truncated_at_612_bytes_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            complete_path = os.path.join(d, 'rootfs.tar')
            _build_two_member_tar(complete_path)
            data = open(complete_path, 'rb').read()
            truncated_path = os.path.join(d, 'truncated.tar')
            with open(truncated_path, 'wb') as f:
                f.write(data[:612])
            with self.assertRaises(OSError):
                truth._verify_tar_completeness(truncated_path)

    def test_missing_end_of_archive_marker_is_rejected_even_with_both_members_intact(self):
        with tempfile.TemporaryDirectory() as d:
            complete_path = os.path.join(d, 'rootfs.tar')
            _build_two_member_tar(complete_path)
            with tarfile.open(complete_path) as tf:
                last_end = max(m.offset_data + m.size for m in tf.getmembers())
            content_end = ((last_end + 511) // 512) * 512
            data = open(complete_path, 'rb').read()
            # Keep both members' own header+data intact, but leave only
            # ONE trailing all-zero block instead of the two the tar
            # format itself requires to mark a real end of archive.
            short_trailer_path = os.path.join(d, 'short-trailer.tar')
            with open(short_trailer_path, 'wb') as f:
                f.write(data[:content_end + 512])
            with self.assertRaises(OSError):
                truth._verify_tar_completeness(short_trailer_path)


def _fake_docker_subprocess_run(cmd, **_kwargs):
    """Stands in for every `docker` invocation build_inventory's own call
    chain makes (docker create, gtb.extract_os_db's own docker cp calls,
    docker image inspect, docker export, docker rm), so
    MainAbortsOnRootfsExportFailureTests can drive that real call chain -
    not a mock of build_inventory itself - all the way down into
    export_container_rootfs raising OSError from a failed `docker
    export`, without any real Docker daemon."""
    cmd = list(cmd)
    if cmd[:2] == ['docker', 'create']:
        return subprocess.CompletedProcess(cmd, 0, stdout='fakecid1234\n', stderr='')
    if cmd[:2] == ['docker', 'cp']:
        # Both the dpkg and apk copies "fail" (no image to copy from at
        # all here); gtb.extract_os_db reads that as os_db_available=False
        # and moves on, which is fine - this test is only about the
        # rootfs export path below it.
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='no such container')
    if cmd[:3] == ['docker', 'image', 'inspect']:
        return subprocess.CompletedProcess(cmd, 0, stdout='1000\n', stderr='')
    if cmd[:2] == ['docker', 'export']:
        return subprocess.CompletedProcess(
            cmd, 1, stdout=None, stderr=b'write /fake/rootfs.tar: no space left on device')
    if cmd[:2] == ['docker', 'rm']:
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
    raise AssertionError(f'unexpected subprocess.run call in test: {cmd}')


class MainAbortsOnRootfsExportFailureTests(unittest.TestCase):
    """main()'s own reaction to a failed rootfs export/extraction: it
    must exit nonzero and never write truth.json, rather than the old
    behavior of recording rootfs_export_ok=false and completing anyway
    with whatever partial inventory/used set the truncated rootfs
    happened to yield."""

    def _write_run_fixture(self, run_dir):
        with open(os.path.join(run_dir, 'image_id.txt'), 'w') as f:
            f.write('sha256:deadbeef\n')
        case_path = os.path.join(run_dir, 'case.json')
        with open(case_path, 'w') as f:
            json.dump({}, f)
        return case_path

    def test_a_failed_docker_export_aborts_main_nonzero_without_writing_truth_json(self):
        with tempfile.TemporaryDirectory() as run_dir:
            case_path = self._write_run_fixture(run_dir)
            with mock.patch('subprocess.run', side_effect=_fake_docker_subprocess_run), \
                    mock.patch.object(sys, 'argv', ['truth.py', run_dir, case_path]):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = truth.main()
            self.assertEqual(result, 1)
            self.assertFalse(os.path.exists(os.path.join(run_dir, 'truth.json')))
            self.assertIn('rootfs export/extraction failed', stderr.getvalue())

    def test_export_container_rootfs_raising_oserror_is_never_swallowed_by_build_inventory(self):
        # The same scenario one level down: build_inventory itself must
        # propagate the OSError, not catch it and return some fallback -
        # its own try/finally around `cid` is for docker rm cleanup only.
        with mock.patch('subprocess.run', side_effect=_fake_docker_subprocess_run), \
                tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(OSError):
                truth.build_inventory('sha256:deadbeef', tmp)


class MainHonorsKlTruthTmpdirTests(unittest.TestCase):
    """KL_TRUTH_TMPDIR must reach tempfile.mkdtemp's own `dir` argument,
    so a truth.py invocation's own rootfs export/extraction can be
    pointed at a filesystem other than tmpfs /tmp (the ENOSPC incident
    this hardening responds to happened on a 7.7 GB tmpfs)."""

    def _write_run_fixture(self, run_dir):
        with open(os.path.join(run_dir, 'image_id.txt'), 'w') as f:
            f.write('sha256:deadbeef\n')
        case_path = os.path.join(run_dir, 'case.json')
        with open(case_path, 'w') as f:
            json.dump({}, f)
        return case_path

    def test_kl_truth_tmpdir_is_passed_to_mkdtemp(self):
        with tempfile.TemporaryDirectory() as run_dir, tempfile.TemporaryDirectory() as custom_base:
            case_path = self._write_run_fixture(run_dir)
            with mock.patch.object(truth, 'build_inventory', side_effect=OSError('boom')), \
                    mock.patch.object(sys, 'argv', ['truth.py', run_dir, case_path]), \
                    mock.patch.dict(os.environ, {'KL_TRUTH_TMPDIR': custom_base}), \
                    mock.patch('tempfile.mkdtemp', wraps=tempfile.mkdtemp) as mkdtemp_spy:
                with contextlib.redirect_stderr(io.StringIO()):
                    truth.main()
            self.assertEqual(mkdtemp_spy.call_args.kwargs.get('dir'), custom_base)

    def test_unset_kl_truth_tmpdir_keeps_the_default(self):
        with tempfile.TemporaryDirectory() as run_dir:
            case_path = self._write_run_fixture(run_dir)
            with mock.patch.object(truth, 'build_inventory', side_effect=OSError('boom')), \
                    mock.patch.object(sys, 'argv', ['truth.py', run_dir, case_path]), \
                    mock.patch.dict(os.environ, {}, clear=False) as _env:
                os.environ.pop('KL_TRUTH_TMPDIR', None)
                with mock.patch('tempfile.mkdtemp', wraps=tempfile.mkdtemp) as mkdtemp_spy:
                    with contextlib.redirect_stderr(io.StringIO()):
                        truth.main()
            self.assertIsNone(mkdtemp_spy.call_args.kwargs.get('dir'))


if __name__ == '__main__':
    unittest.main()
