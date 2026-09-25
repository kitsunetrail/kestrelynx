#!/usr/bin/env python3
"""Unit tests for gen_sensor_seccomp_profile.py's transform()/verify logic,
against a frozen copy of the real upstream profile (testdata/moby-seccomp-
default.json, fetched from moby/profiles on the date recorded in this
file's own git history — a real fetched artifact, not hand-authored, so
these tests exercise the actual shape upstream uses rather than a
simplified stand-in for it).

Run with:
  python3 scripts/gen_sensor_seccomp_profile_test.py
  python3 -m unittest discover -s scripts -p 'gen_sensor_seccomp_profile_test.py'
"""
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_sensor_seccomp_profile as gen

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "moby-seccomp-default.json")


def load_fixture_bytes():
    with open(FIXTURE, "rb") as f:
        return f.read()


class TransformTest(unittest.TestCase):
    def setUp(self):
        self.raw = load_fixture_bytes()
        self.profile = gen.transform(self.raw)
        self.names = set()
        for entry in self.profile["syscalls"]:
            self.names.update(entry["names"])

    def test_excluded_names_all_absent(self):
        present = self.names & gen.EXCLUDE_NAMES
        self.assertEqual(present, set(), f"excluded names still present: {sorted(present)}")

    def test_multiplexed_syscalls_absent(self):
        self.assertNotIn("socketcall", self.names)
        self.assertNotIn("ipc", self.names)

    def test_arch_map_restricted(self):
        arches = {e["architecture"] for e in self.profile["archMap"]}
        self.assertEqual(arches, gen.ARCH_KEEP)
        for e in self.profile["archMap"]:
            self.assertNotIn("subArchitectures", e, f"{e['architecture']} still has subArchitectures")

    def test_socketpair_constrained_not_removed(self):
        entries = [e for e in self.profile["syscalls"] if "socketpair" in e["names"]]
        self.assertEqual(len(entries), 1, "expected exactly one socketpair entry")
        self.assertEqual(entries[0], gen.SOCKETPAIR_ENTRY)

    def test_socketpair_condition_means_type_and_15_equals_5(self):
        # A structural/constant match (above) would pass even if "value"
        # and "valueTwo" were swapped, as they once were here: both are
        # just integers, and only their *meaning* under SCMP_CMP_MASKED_EQ
        # — (argument & value) == valueTwo — tells the two apart. This
        # test evaluates that meaning directly against real socket type
        # values instead of trusting the constant names.
        entries = [e for e in self.profile["syscalls"] if "socketpair" in e["names"]]
        arg1 = entries[0]["args"][1]
        self.assertEqual(arg1["op"], "SCMP_CMP_MASKED_EQ")
        mask, compare_to = arg1["value"], arg1["valueTwo"]

        def matches(type_value):
            return (type_value & mask) == compare_to

        SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_PACKET = 1, 2, 3, 4, 5, 10
        SOCK_CLOEXEC, SOCK_NONBLOCK = 0x80000, 0x800

        for bad in (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_PACKET):
            self.assertFalse(matches(bad), f"socket type {bad} must not match the socketpair condition")
        self.assertTrue(matches(SOCK_SEQPACKET))
        self.assertTrue(matches(SOCK_SEQPACKET | SOCK_CLOEXEC))
        self.assertTrue(matches(SOCK_SEQPACKET | SOCK_NONBLOCK))
        self.assertTrue(matches(SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK))
        # The specific bug this test exists to catch: mask/value swapped so
        # the condition became (type & 5) == 15. 5 has no bits outside of
        # what 15 already covers, so ANDing anything with 5 can never
        # produce 15 — that swapped condition is never true for *any*
        # type, silently denying every socketpair call, including
        # legitimate ones. matches(SOCK_SEQPACKET) above already fails
        # under that swapped condition; this spells out why.
        self.assertEqual(mask, gen.SOCK_TYPE_MASK)
        self.assertEqual(compare_to, SOCK_SEQPACKET)

    def test_ftruncate_survives_but_truncate_does_not(self):
        # The one deliberately narrow exclusion: "truncate" (path-based)
        # is excluded, "ftruncate"/"ftruncate64" (fd-based, which the
        # observer needs on its already-open evidence fd) are not.
        self.assertNotIn("truncate", self.names)
        self.assertNotIn("truncate64", self.names)
        self.assertIn("ftruncate", self.names)
        self.assertIn("ftruncate64", self.names)

    def test_fd_passing_syscalls_survive(self):
        for n in ("sendmsg", "recvmsg", "read", "pread64", "close", "exit", "exit_group", "futex", "bpf"):
            self.assertIn(n, self.names, f"{n} should not have been excluded")

    def test_landlock_syscalls_survive(self):
        for n in ("landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"):
            self.assertIn(n, self.names)

    def test_output_is_deterministic(self):
        again = gen.transform(self.raw)
        self.assertEqual(
            json.dumps(self.profile, sort_keys=True),
            json.dumps(again, sort_keys=True),
        )

    def test_verify_accepts_own_output(self):
        gen._verify(self.profile)  # must not raise


class GuardRailTest(unittest.TestCase):
    """Confirms the generator fails loudly instead of silently mis-handling
    an upstream shape it does not recognize — the multiplexed-syscall and
    io_uring checks exist specifically so a future upstream change cannot
    reintroduce a bypass unnoticed."""

    def setUp(self):
        self.raw_profile = json.loads(load_fixture_bytes())

    def test_missing_socketpair_raises(self):
        for entry in self.raw_profile["syscalls"]:
            entry["names"] = [n for n in entry["names"] if n != "socketpair"]
        with self.assertRaises(SystemExit):
            gen.transform(json.dumps(self.raw_profile).encode())

    def test_io_uring_present_raises(self):
        self.raw_profile["syscalls"].append({"names": ["io_uring_setup"], "action": "SCMP_ACT_ALLOW"})
        with self.assertRaises(SystemExit):
            gen.transform(json.dumps(self.raw_profile).encode())

    def test_arch_map_missing_an_architecture_raises(self):
        self.raw_profile["archMap"] = [
            e for e in self.raw_profile["archMap"] if e["architecture"] != "SCMP_ARCH_AARCH64"
        ]
        with self.assertRaises(SystemExit):
            gen.transform(json.dumps(self.raw_profile).encode())

    def test_verify_rejects_tampered_socketpair_entry(self):
        profile = gen.transform(load_fixture_bytes())
        tampered = copy.deepcopy(profile)
        for e in tampered["syscalls"]:
            if "socketpair" in e["names"]:
                e["args"][1]["value"] = 2  # SOCK_DGRAM instead of SOCK_SEQPACKET
        with self.assertRaises(SystemExit):
            gen._verify(tampered)

    def test_verify_rejects_reintroduced_excluded_name(self):
        profile = gen.transform(load_fixture_bytes())
        tampered = copy.deepcopy(profile)
        tampered["syscalls"].append({"names": ["ptrace"], "action": "SCMP_ACT_ALLOW"})
        with self.assertRaises(SystemExit):
            gen._verify(tampered)


if __name__ == "__main__":
    unittest.main()
