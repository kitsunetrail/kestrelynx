#!/usr/bin/env python3
"""Unit tests for prod_summary.py's three-state classification, generation
discovery/ordering, and before/after table construction.

Two of the fixtures below (REAL_REQUESTS_PV, REAL_CURL_PV) are trimmed
copies of actual PackageVerdict entries taken from
experiments/runtime-discovery/out/26-root-30-300-p0-r1-startup-nofilter512p/match_hc.json
- a real S2 run, kept in this repository from an earlier measurement. Both
show the exact pattern that makes S0-vs-S2 selection matter: the top-level
"verdict" (S0) is "unobserved" for both, while "s2_verdict" is "confirmed"
via an event. Reading the display state from "verdict" instead of
"s2_verdict" would show a real, event-confirmed package as undeterminable
or no_evidence - the two tests test_uses_the_real_s2_confirmed_requests_fixture
and test_uses_the_real_s2_confirmed_curl_fixture below fail against that
mistake and pass against the fix. The rest of the fixtures are synthetic,
hand-shaped to match the same field names.

Run with:
  python3 -m unittest discover -s tools -p 'prod_summary_test.py'
  python3 tools/prod_summary_test.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prod_summary as ps

# --- trimmed real fixtures (see module docstring) --------------------------

REAL_REQUESTS_PV = {
    "package": "requests", "class": "lang", "installed_version": "2.32.3",
    "finding_count": 0, "verdict": "unobserved", "factor": "lang_pkg_unmappable",
    "observation_state": "observed",
    "confirmation_gap_class": "E2", "confirmation_gap_recoverability": "confirmed",
    "s1_verdict": "unobserved", "s1_factor": "no_observation",
    "s2_verdict": "confirmed", "s2_sources": ["event_open"],
    "confirmations": [
        {"source": "event_open", "path": "/usr/local/lib/python3.12/site-packages/requests/__init__.py",
         "verb": "opened", "observed_at": "2026-09-20T01:30:07.71975811Z"},
        {"source": "event_open", "path": "/usr/local/lib/python3.12/site-packages/requests/exceptions.py",
         "verb": "opened", "observed_at": "2026-09-20T01:30:07.820145504Z"},
    ],
}

REAL_CURL_PV = {
    "package": "curl", "class": "os", "installed_version": "8.14.1-2+deb13u5",
    "finding_count": 4, "verdict": "unobserved", "factor": "no_observation",
    "observation_state": "observed",
    "confirmation_gap_class": "unclassified", "confirmation_gap_recoverability": "unknown",
    "s1_verdict": "unobserved", "s1_factor": "no_observation",
    "s2_verdict": "confirmed", "s2_sources": ["event_exec"],
    "confirmations": [
        {"source": "event_exec", "path": "/usr/bin/curl", "verb": "executed",
         "observed_at": "2026-09-20T01:30:07.356619252Z"},
    ],
}


def pv(package, class_="os", finding_count=1, verdict="unobserved", factor="",
       observation_state="observed", installed_version="1.0", gap_class="",
       s1_verdict="", s1_factor="", s2_verdict="", s2_factor="", confirmations=None):
    return {
        "package": package, "class": class_, "installed_version": installed_version,
        "finding_count": finding_count, "verdict": verdict, "factor": factor,
        "observation_state": observation_state, "confirmation_gap_class": gap_class,
        "s1_verdict": s1_verdict, "s1_factor": s1_factor,
        "s2_verdict": s2_verdict, "s2_factor": s2_factor,
        "confirmations": confirmations or [],
    }


def match_result(packages, event_state="observed", event_drops=None, event_notes=None):
    return {"packages": packages, "event_state": event_state,
            "event_drops": event_drops or {}, "event_notes": event_notes or []}


def record(container_name, started_at, image_id="sha256:img"):
    return {"subject": {"docker": {"container_name": container_name, "image_id": image_id}, "started_at": started_at}}


def write_generation(run_dir, base, match, rec):
    os.makedirs(os.path.join(run_dir, "match"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "collect"), exist_ok=True)
    with open(os.path.join(run_dir, "match", base + ps.MATCH_SUFFIX), "w") as f:
        json.dump(match, f)
    with open(os.path.join(run_dir, "collect", base + ".json"), "w") as f:
        json.dump(rec, f)


def write_timeline(run_dir, mode, at):
    with open(os.path.join(run_dir, "timeline.jsonl"), "w") as f:
        f.write(json.dumps({"event": "effective_observation_start", "mode": mode, "at": at}) + "\n")


class TestEffectiveVerdict(unittest.TestCase):
    def test_uses_the_real_s2_confirmed_requests_fixture(self):
        # verdict (S0) is "unobserved", s2_verdict is "confirmed". The
        # display classification must be confirmed, not
        # undeterminable/no_evidence.
        state, sub, tier = ps.classify(REAL_REQUESTS_PV, None, None, "observed")
        self.assertEqual(state, "confirmed")
        self.assertIsNone(sub)
        self.assertEqual(tier, "s2")

    def test_uses_the_real_s2_confirmed_curl_fixture(self):
        state, sub, tier = ps.classify(REAL_CURL_PV, None, None, "observed")
        self.assertEqual(state, "confirmed")
        self.assertIsNone(sub)
        self.assertEqual(tier, "s2")

    def test_falls_back_to_s1_when_s2_is_empty(self):
        p = pv("libfoo", s1_verdict="confirmed", s1_factor="", s2_verdict="")
        verdict, factor, tier = ps.effective_verdict(p)
        self.assertEqual((verdict, tier), ("confirmed", "s1"))

    def test_falls_back_to_s0_when_s1_and_s2_are_both_empty(self):
        p = pv("libfoo", verdict="unresolved", factor="db_error", s1_verdict="", s2_verdict="")
        verdict, factor, tier = ps.effective_verdict(p)
        self.assertEqual((verdict, factor, tier), ("unresolved", "db_error", "s0"))

    def test_a_not_confirmed_s2_verdict_is_not_a_reason_to_fall_back(self):
        # "unobserved" at S2 is still a real S2 answer, not a missing one -
        # falling back to S1/S0 here would silently discard S2's own,
        # already-more-complete conclusion.
        p = pv("libfoo", verdict="unobserved", s1_verdict="unobserved", s2_verdict="unobserved")
        verdict, factor, tier = ps.effective_verdict(p)
        self.assertEqual(tier, "s2")


class TestClassifyPackage(unittest.TestCase):
    def test_confirmed_wins_regardless_of_anything_else(self):
        p = pv("openssl", verdict="confirmed", s2_verdict="confirmed", class_="lang", factor="lang_pkg_unmappable")
        state, sub, _ = ps.classify(p, ps.parse_ts("2026-01-02T00:00:00Z"), ps.parse_ts("2026-01-01T00:00:00Z"), "observed")
        self.assertEqual(state, "confirmed")
        self.assertIsNone(sub)

    def test_lang_package_started_before_observation_is_undeterminable(self):
        p = pv("flask", class_="lang", verdict="unobserved")
        started = ps.parse_ts("2026-01-01T00:00:00Z")
        obs_start = ps.parse_ts("2026-01-02T00:00:00Z")
        state, sub, _ = ps.classify(p, started, obs_start, "observed")
        self.assertEqual(state, "undeterminable_started_before_observation")
        self.assertIsNone(sub)

    def test_os_package_started_before_observation_is_not_exempted(self):
        p = pv("libssl3", class_="os", verdict="unobserved")
        started = ps.parse_ts("2026-01-01T00:00:00Z")
        obs_start = ps.parse_ts("2026-01-02T00:00:00Z")
        state, sub, _ = ps.classify(p, started, obs_start, "observed")
        self.assertEqual(state, "no_evidence")

    def test_lang_package_started_after_observation_falls_through(self):
        p = pv("flask", class_="lang", verdict="unobserved", factor="lang_pkg_unmappable")
        started = ps.parse_ts("2026-01-03T00:00:00Z")
        obs_start = ps.parse_ts("2026-01-02T00:00:00Z")
        state, sub, _ = ps.classify(p, started, obs_start, "observed")
        self.assertEqual((state, sub), ("no_evidence", "mapping_unsupported"))

    def test_permission_failure_subreason(self):
        p = pv("curl", factor="proc_denied")
        state, sub, _ = ps.classify(p, None, None, "observed")
        self.assertEqual((state, sub), ("no_evidence", "permission_failure"))

    def test_no_observation_subreason_from_factor(self):
        p = pv("git", factor="top_failed")
        state, sub, _ = ps.classify(p, None, None, "observed")
        self.assertEqual((state, sub), ("no_evidence", "no_observation"))

    def test_no_observation_subreason_from_observation_state(self):
        p = pv("git", factor="", observation_state="observation_failed")
        state, sub, _ = ps.classify(p, None, None, "observed")
        self.assertEqual((state, sub), ("no_evidence", "no_observation"))

    def test_mapping_unsupported_subreason_from_factor(self):
        p = pv("libfoo", factor="no_file_list")
        state, sub, _ = ps.classify(p, None, None, "observed")
        self.assertEqual((state, sub), ("no_evidence", "mapping_unsupported"))

    def test_mapping_unsupported_subreason_from_gap_class_only_at_s0(self):
        p = pv("libfoo", factor="", gap_class="E2")
        state, sub, tier = ps.classify(p, None, None, "observed")
        self.assertEqual(tier, "s0")
        self.assertEqual((state, sub), ("no_evidence", "mapping_unsupported"))

    def test_s0_gap_class_e2_is_not_applied_while_classifying_by_s2(self):
        # confirmation_gap_class is always computed from the S0
        # verdict/factor in match itself, regardless of what S1/S2 later
        # decide - so a package that S0 called E2 but that carries its own,
        # different s2_factor must be read by that s2_factor, never by the
        # S0-only gap class. "event_unavailable" here is a real S2 factor
        # (the event source itself had nothing to say) that is not mapping-
        # related at all, so it must fall through to unclassified rather
        # than being coerced into mapping_unsupported by the S0 label.
        p = pv("libfoo", factor="", gap_class="E2", s2_verdict="unobserved", s2_factor="event_unavailable")
        state, sub, tier = ps.classify(p, None, None, "observed")
        self.assertEqual(tier, "s2")
        self.assertEqual((state, sub), ("no_evidence", "unclassified"))

    def test_s1_s2_specific_mapping_factors_are_recognized_directly(self):
        for factor in ("mapping_input_missing", "event_path_unresolved"):
            with self.subTest(factor=factor):
                p = pv("libfoo", factor="", s2_verdict="unobserved", s2_factor=factor)
                state, sub, tier = ps.classify(p, None, None, "observed")
                self.assertEqual(tier, "s2")
                self.assertEqual((state, sub), ("no_evidence", "mapping_unsupported"))

    def test_event_no_observation_factor_is_recognized_directly(self):
        p = pv("libfoo", factor="", s2_verdict="unobserved", s2_factor="event_no_observation")
        state, sub, tier = ps.classify(p, None, None, "observed")
        self.assertEqual(tier, "s2")
        self.assertEqual((state, sub), ("no_evidence", "no_observation"))

    def test_mapping_checked_before_drops_even_with_measured_loss(self):
        # A lang package that is ALSO an unmappable-mapping case must not
        # be re-explained as event loss just because this generation's
        # event collection also happened to lose data.
        p = pv("flask", class_="lang", factor="lang_pkg_unmappable")
        drops = {"lost_events": 5}
        state, sub, _ = ps.classify(p, None, None, "degraded", drops)
        self.assertEqual((state, sub), ("no_evidence", "mapping_unsupported"))

    def test_drops_requires_a_specific_measured_loss(self):
        p = pv("flask", class_="lang", factor="")
        drops = {"lost_events": 3, "lost_notifications": 1}
        state, sub, _ = ps.classify(p, None, None, "degraded", drops)
        self.assertEqual((state, sub), ("no_evidence", "drops"))

    def test_drops_candidate_when_event_state_is_bad_but_nothing_measures_loss(self):
        # event_state alone (degraded/failed) is not proof of loss: it is
        # also what an attach that never confirmed live, or a collection
        # stopped early with nothing lost, looks like.
        p = pv("flask", class_="lang", factor="")
        state, sub, _ = ps.classify(p, None, None, "degraded", {})
        self.assertEqual((state, sub), ("no_evidence", "drops_candidate"))

        state2, sub2, _ = ps.classify(p, None, None, "failed", None)
        self.assertEqual((state2, sub2), ("no_evidence", "drops_candidate"))

    def test_drops_and_drops_candidate_do_not_apply_to_os_packages(self):
        p = pv("libssl3", class_="os", factor="")
        drops = {"lost_events": 5}
        state, sub, _ = ps.classify(p, None, None, "degraded", drops)
        self.assertEqual((state, sub), ("no_evidence", "unclassified"))

    def test_unclassified_fallback(self):
        p = pv("mystery", factor="")
        state, sub, _ = ps.classify(p, None, None, "observed")
        self.assertEqual((state, sub), ("no_evidence", "unclassified"))


class TestMeasuredEventLoss(unittest.TestCase):
    def test_each_measured_field_counts(self):
        for field in ps.MEASURED_LOSS_FIELDS:
            with self.subTest(field=field):
                self.assertTrue(ps.measured_event_loss({field: 1}))

    def test_boundary_field_does_not_count(self):
        # enter_exit_unmatched_boundary is documented in the harness itself
        # as a boundary of what the window measures, not a loss inside it.
        self.assertFalse(ps.measured_event_loss({"enter_exit_unmatched_boundary": 5}))

    def test_volume_counters_do_not_count(self):
        self.assertFalse(ps.measured_event_loss({"events_before_filter": 999, "events_after_filter": 999}))

    def test_notes_are_never_consulted_even_when_they_name_a_loss_field(self):
        # The exact shape a real converter emits when it could not measure
        # something at all: a note naming "map_overflow" while every
        # structured counter, including map_overflow itself, reads zero.
        # measured_event_loss must not read that explanation as evidence of
        # an actual loss.
        drops = {"lost_events": 0, "map_overflow": 0, "path_read_failures": 0}
        self.assertFalse(ps.measured_event_loss(drops))

    def test_measured_event_loss_takes_no_notes_argument(self):
        # A second positional argument here would silently resurrect
        # substring-matching against free text; measured_event_loss's
        # signature itself is what keeps that from being reintroduced.
        import inspect
        params = list(inspect.signature(ps.measured_event_loss).parameters)
        self.assertEqual(params, ["event_drops"])

    def test_empty_inputs_do_not_count(self):
        self.assertFalse(ps.measured_event_loss({}))
        self.assertFalse(ps.measured_event_loss(None))


class TestPackageKey(unittest.TestCase):
    def test_distinguishes_versions_of_the_same_package(self):
        a = pv("flask", installed_version="2.0")
        b = pv("flask", installed_version="2.1")
        self.assertNotEqual(ps.package_key(a), ps.package_key(b))

    def test_distinguishes_class(self):
        a = pv("thing", class_="os")
        b = pv("thing", class_="lang")
        self.assertNotEqual(ps.package_key(a), ps.package_key(b))


class TestFirstEvidenceForPackage(unittest.TestCase):
    def test_picks_the_earliest_entry_from_the_packages_own_confirmations(self):
        at, source = ps.first_evidence_for_package(REAL_REQUESTS_PV)
        self.assertEqual(at, "2026-09-20T01:30:07.71975811Z")
        self.assertEqual(source, "event_open")

    def test_no_confirmations_returns_none(self):
        p = pv("curl", confirmations=[])
        self.assertEqual(ps.first_evidence_for_package(p), (None, None))

    def test_does_not_leak_across_versions(self):
        # first_evidence_for_package reads confirmations straight off the
        # PackageVerdict it is given - passing the wrong version's pv would
        # be a caller bug, not something this function could get right on
        # its own; this test documents that the two versions carry their
        # own, distinct confirmations.
        old = pv("flask", installed_version="2.0", confirmations=[{"source": "event_exec", "observed_at": "2026-01-01T00:00:00Z"}])
        new = pv("flask", installed_version="2.1", confirmations=[{"source": "event_open", "observed_at": "2026-01-02T00:00:00Z"}])
        self.assertEqual(ps.first_evidence_for_package(old), ("2026-01-01T00:00:00Z", "event_exec"))
        self.assertEqual(ps.first_evidence_for_package(new), ("2026-01-02T00:00:00Z", "event_open"))


class TestDiscoverGenerations(unittest.TestCase):
    def test_groups_by_container_name_not_by_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = "regfis__backend"
            write_generation(tmp, "regfis__backend__prod_root__gen1",
                              match_result([pv("a")]), record(name, "2026-01-01T00:00:00Z"))
            write_generation(tmp, "regfis__backend__prod_root__gen2",
                              match_result([pv("a")]), record(name, "2026-01-02T00:00:00Z"))
            by_container = ps.discover_generations(tmp)
            self.assertEqual(list(by_container.keys()), [name])
            self.assertEqual(len(by_container[name]), 2)

    def test_orders_oldest_first_regardless_of_discovery_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_generation(tmp, "b_zzz_gen2", match_result([pv("a")]), record("backend", "2026-01-05T00:00:00Z"))
            write_generation(tmp, "a_aaa_gen1", match_result([pv("a")]), record("backend", "2026-01-01T00:00:00Z"))
            by_container = ps.discover_generations(tmp)
            starts = [g["started_at"] for g in by_container["backend"]]
            self.assertEqual(starts, ["2026-01-01T00:00:00Z", "2026-01-05T00:00:00Z"])

    def test_records_the_image_id_per_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_generation(tmp, "g1", match_result([pv("a")]), record("backend", "2026-01-01T00:00:00Z", image_id="sha256:aaa"))
            by_container = ps.discover_generations(tmp)
            self.assertEqual(by_container["backend"][0]["image_id"], "sha256:aaa")

    def test_a_collect_record_without_a_matching_match_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "collect"))
            with open(os.path.join(tmp, "collect", "orphan.json"), "w") as f:
                json.dump(record("backend", "2026-01-01T00:00:00Z"), f)
            by_container = ps.discover_generations(tmp)
            self.assertEqual(by_container, {})


class TestCounts(unittest.TestCase):
    def test_findings_sum_by_finding_count_packages_sum_by_entry(self):
        rows = [
            {"container": "c", "generation": 1, "state": "confirmed", "finding_count": 3},
            {"container": "c", "generation": 1, "state": "no_evidence", "finding_count": 2},
        ]
        counts = ps.counts_by_container_generation(rows)
        c = counts[("c", 1)]
        self.assertEqual(c["findings"]["confirmed"], 3)
        self.assertEqual(c["findings"]["no_evidence"], 2)
        self.assertEqual(c["packages"]["confirmed"], 1)
        self.assertEqual(c["packages"]["no_evidence"], 1)
        self.assertEqual(sum(c["findings"].values()), 5)


class TestBeforeAfterRows(unittest.TestCase):
    def test_single_generation_container_produces_no_rows(self):
        by_container = {"solo": [{"base": "b", "started_at": "2026-01-01T00:00:00Z", "image_id": "x", "match": match_result([pv("a")])}]}
        self.assertEqual(ps.before_after_rows(by_container, None), [])

    def test_restart_shows_the_package_before_and_after_as_common(self):
        before_match = match_result([pv("flask", class_="lang", verdict="unobserved", installed_version="2.0")])
        after_match = match_result([pv("flask", class_="lang", verdict="unobserved", installed_version="2.0",
                                        s2_verdict="confirmed",
                                        confirmations=[{"source": "event_open", "observed_at": "2026-01-02T00:05:00Z"}])])
        by_container = {
            "backend": [
                {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "sha256:aaa", "match": before_match},
                {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "sha256:aaa", "match": after_match},
            ]
        }
        rows = ps.before_after_rows(by_container, None)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["container"], "backend")
        self.assertEqual(r["package"], "flask")
        self.assertEqual(r["membership"], "common")
        self.assertEqual(r["before_generation"], 1)
        self.assertEqual(r["after_generation"], 2)
        self.assertEqual(r["before_image_id"], "sha256:aaa")
        self.assertEqual(r["state_before"], "no_evidence")
        self.assertEqual(r["state_after"], "confirmed")
        self.assertEqual(r["first_evidence_time"], "2026-01-02T00:05:00Z")
        self.assertEqual(r["remaining_reason"], "")

    def test_package_missing_after_is_reported_as_removed(self):
        before_match = match_result([pv("oldlib", verdict="confirmed", s2_verdict="confirmed")])
        after_match = match_result([])
        by_container = {
            "backend": [
                {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "sha256:aaa", "match": before_match},
                {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "sha256:bbb", "match": after_match},
            ]
        }
        rows = ps.before_after_rows(by_container, None)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["membership"], "removed")
        self.assertEqual(rows[0]["state_after"], "not_present")
        self.assertIn("no longer carries", rows[0]["remaining_reason"])

    def test_same_name_different_version_is_added_and_removed_not_merged(self):
        # The bug this reproduces: keying by name alone would collapse
        # these two rows into one, silently dropping whichever version's
        # entry a dict happened to see first.
        before_match = match_result([pv("flask", installed_version="2.0", verdict="confirmed", s2_verdict="confirmed")])
        after_match = match_result([pv("flask", installed_version="2.1", verdict="unobserved")])
        by_container = {
            "backend": [
                {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "sha256:aaa", "match": before_match},
                {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "sha256:bbb", "match": after_match},
            ]
        }
        rows = ps.before_after_rows(by_container, None)
        self.assertEqual(len(rows), 2, f"want one row per version, got {rows}")
        memberships = {r["version_before"] or r["version_after"]: r["membership"] for r in rows}
        self.assertEqual(memberships["2.0"], "removed")
        self.assertEqual(memberships["2.1"], "added")

    def test_evidence_and_state_do_not_leak_across_versions(self):
        before_match = match_result([pv("flask", installed_version="2.0", verdict="confirmed", s2_verdict="confirmed",
                                         confirmations=[{"source": "event_open", "observed_at": "2026-01-01T00:00:01Z"}])])
        after_match = match_result([pv("flask", installed_version="2.1", verdict="unobserved", factor="lang_pkg_unmappable", class_="lang")])
        by_container = {
            "backend": [
                {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "sha256:aaa", "match": before_match},
                {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "sha256:bbb", "match": after_match},
            ]
        }
        rows = ps.before_after_rows(by_container, None)
        added = next(r for r in rows if r["membership"] == "added")
        # The new version's own row must not show the old version's
        # confirmed state or its confirmation time.
        self.assertEqual(added["state_after"], "no_evidence")
        self.assertEqual(added["first_evidence_time"], "")

    def test_explicit_before_after_timestamps_pick_generations(self):
        gens = [
            {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "x", "match": match_result([pv("a", verdict="confirmed", s2_verdict="confirmed")])},
            {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "x", "match": match_result([pv("a", verdict="unobserved")])},
            {"base": "g3", "started_at": "2026-01-03T00:00:00Z", "image_id": "x", "match": match_result([pv("a", verdict="confirmed", s2_verdict="confirmed")])},
        ]
        by_container = {"backend": gens}
        rows = ps.before_after_rows(
            by_container, None,
            before_ts=ps.parse_ts("2026-01-01T12:00:00Z"),
            after_ts=ps.parse_ts("2026-01-02T12:00:00Z"),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state_before"], "confirmed")
        self.assertEqual(rows[0]["state_after"], "no_evidence")

    def test_container_filter_restricts_the_table(self):
        by_container = {
            "backend": [
                {"base": "g1", "started_at": "2026-01-01T00:00:00Z", "image_id": "x", "match": match_result([pv("a")])},
                {"base": "g2", "started_at": "2026-01-02T00:00:00Z", "image_id": "x", "match": match_result([pv("a")])},
            ],
            "frontend": [
                {"base": "h1", "started_at": "2026-01-01T00:00:00Z", "image_id": "x", "match": match_result([pv("b")])},
                {"base": "h2", "started_at": "2026-01-02T00:00:00Z", "image_id": "x", "match": match_result([pv("b")])},
            ],
        }
        rows = ps.before_after_rows(by_container, None, container_filter="frontend")
        self.assertEqual({r["container"] for r in rows}, {"frontend"})


class TestParseTs(unittest.TestCase):
    def test_z_suffix(self):
        self.assertIsNotNone(ps.parse_ts("2026-01-01T00:00:00Z"))

    def test_nanosecond_fraction_is_truncated_to_microseconds(self):
        dt = ps.parse_ts("2026-01-01T00:00:00.123456789Z")
        self.assertEqual(dt.microsecond, 123456)

    def test_empty_is_none(self):
        self.assertIsNone(ps.parse_ts(""))
        self.assertIsNone(ps.parse_ts(None))


class TestEndToEnd(unittest.TestCase):
    def test_main_writes_md_and_csv_with_expected_totals_using_real_shaped_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_timeline(tmp, "procfs", "2026-01-01T00:00:00Z")
            write_generation(
                tmp, "backend__prod",
                match_result([REAL_REQUESTS_PV, REAL_CURL_PV], event_state="observed"),
                record("backend", "2026-01-01T00:00:00Z", image_id="sha256:img1"),
            )
            ps.main([tmp])
            md_path = os.path.join(tmp, "prod_summary.md")
            csv_path = os.path.join(tmp, "prod_summary.csv")
            self.assertTrue(os.path.exists(md_path))
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path) as f:
                rows = list(__import__("csv").DictReader(f))
            by_pkg = {r["package"]: r for r in rows}
            # curl has finding_count 4, all confirmed via s2; requests has
            # finding_count 0 and is excluded from the population entirely
            # (see build_rows: only findings with finding_count > 0 count).
            self.assertNotIn("requests", by_pkg, "a package with finding_count 0 must not appear in the HC population")
            self.assertEqual(by_pkg["curl"]["state"], "confirmed")
            self.assertEqual(by_pkg["curl"]["verdict"], "unobserved")
            self.assertEqual(by_pkg["curl"]["s2_verdict"], "confirmed")
            self.assertEqual(by_pkg["curl"]["verdict_tier_used"], "s2")
            with open(md_path) as f:
                md = f.read()
            self.assertIn("sha256:img1", md)

    def test_container_flag_filters_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_timeline(tmp, "procfs", "2026-01-01T00:00:00Z")
            write_generation(tmp, "backend__prod", match_result([pv("a", verdict="confirmed", s2_verdict="confirmed")]),
                              record("backend", "2026-01-01T00:00:00Z"))
            write_generation(tmp, "frontend__prod", match_result([pv("b", verdict="confirmed", s2_verdict="confirmed")]),
                              record("frontend", "2026-01-01T00:00:00Z"))
            ps.main([tmp, "--container", "frontend"])
            with open(os.path.join(tmp, "prod_summary.csv")) as f:
                content = f.read()
            self.assertNotIn("backend", content)
            self.assertIn("frontend", content)


if __name__ == "__main__":
    unittest.main()
