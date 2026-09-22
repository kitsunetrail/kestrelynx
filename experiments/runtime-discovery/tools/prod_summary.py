#!/usr/bin/env python3
"""Summarize a prod-observe.sh run into a three-state evidence breakdown per
HIGH/CRITICAL Finding, per container generation, plus a before/after table
for any container that restarted or was re-created during the run.

Usage:
  prod_summary.py <run dir> [--before <RFC3339 ts>] [--after <RFC3339 ts>] [--container <name>]

  <run dir>   a prod-observe.sh output directory: match/*.match_hc.json,
              collect/*.json, timeline.jsonl (restarts.jsonl is read too,
              but only to tell which generation is which - see below)
  --before/--after
              explicit timestamps naming which generation was the running
              one at that moment (the latest generation that had already
              started by the given time) for the per-package before/after
              table. Without them, "before" is a container's first
              (oldest StartedAt) generation and "after" is its last -
              which is what every container with exactly one restart or
              re-creation during the run needs, and is a no-op (skipped)
              for a container with only one generation.
  --container only summarize this one container name

Writes <run dir>/prod_summary.md and <run dir>/prod_summary.csv.

match evaluates every window three ways - S0 (its first stage's own
sampling rules alone), S1 (S0 plus the read-only file-to-package mapping),
S2 (S1 plus event evidence) - and keeps all three verdicts on every
package (verdict is S0, s1_verdict, s2_verdict). A language package is
routinely "unobserved" at S0 even when an event or a jar's open descriptor
confirms it at S1/S2, so the display classification below is read from
s2_verdict first, falling back to s1_verdict and then to the S0 verdict
only when a later series never ran for this package at all (its field is
empty - not merely "not confirmed"). The original S0 verdict, s1_verdict,
s2_verdict, and this generation's own event_state are always kept as their
own CSV columns, never overwritten by the classification below, and the
CSV also records which tier (s0/s1/s2) the classification actually used.

Classification (exactly one of three states per HIGH/CRITICAL Finding, per
container generation):
  confirmed
      the verdict tier used says "confirmed": positive evidence for this
      generation's image was found, at whichever series first found it.
  undeterminable_started_before_observation
      not confirmed, the package is a language package (class "lang"), and
      this generation's own StartedAt is earlier than the effective
      observation start - the tracer's attach time when events were
      collected, the collector's own start time otherwise (there is one
      such start per run, taken from timeline.jsonl's
      effective_observation_start event). A container that had already
      been running before observation began cannot have its startup-time
      imports confirmed from this window alone; this is a display of that
      observation condition, not a measurement of what happened before the
      window opened.
  no_evidence
      everything else. A sub-reason is recorded (not a fourth state - the
      three-state total below still divides these findings between
      "confirmed" and "no_evidence" only):
        permission_failure   procfs access was refused for a read this
                              package's evidence would have needed.
        no_observation        the container's processes were never actually
                              read at all - gone, or the observation never
                              got underway.
        mapping_unsupported   the SELECTED series' own factor says the
                              package's files could not be resolved to it -
                              no installed-file manifest, an unmappable
                              language package, no package database, or an
                              S1/S2-specific equivalent (an unresolved event
                              path, or a missing mapping input). When the
                              selected series is S0, match's own gap class
                              E2 also counts here - E2 is computed from the
                              S0 verdict/factor only, so it is read this
                              way only while S0 is in fact what is being
                              classified, never applied to an S1/S2
                              classification it was not computed for.
                              Checked before drops, so a confirmed mapping
                              shortfall is never masked by a guess about
                              event loss.
        drops                 a language package, not otherwise explained,
                              whose generation's own event_drops shows a
                              specific, measured, positive loss counter
                              (lost events, a map overflow, unread or
                              truncated paths, an unmatched syscall pair
                              inside the window) - never event_notes, which
                              is free text the converter also uses to
                              explain what it could NOT measure at all (a
                              note can name a counter such as map_overflow
                              purely to say the collection method in use
                              cannot observe that condition, with the
                              counter itself reading zero), and never
                              merely an event_state of "degraded" or
                              "failed" on its own, since both of those are
                              also reported for an attach that never
                              confirmed live or a collection stopped early,
                              neither of which is a loss.
        drops_candidate       the same, language-package case, where
                              event_state is degraded/failed but no
                              structured event_drops counter measures a
                              specific loss - the causal link to lost data
                              is not established, so this is kept as a
                              candidate rather than asserted as "drops".
        unclassified           none of the above applies.

A Finding's original S0 verdict, s1_verdict, s2_verdict, and this
generation's event_state are kept in their own CSV columns, never
overwritten by the three-state classification above.

Every count here is a HIGH/CRITICAL Finding count (a package's finding_count,
matching Trivy's own per-(package, vulnerability) Findings), not a package
count: two different Findings against the same package are two Findings,
because that is the population the three states are required to sum to.
Package-level counts (how many distinct packages, not Findings, landed in
each state) are reported alongside, separately, and are never added to the
Finding totals.
"""
import csv
import glob
import json
import os
import sys
from datetime import datetime

MATCH_SUFFIX = ".match_hc.json"

# match's own per-package "factor" values (see match_types.go / series.go)
# that this script reads to pick a no_evidence sub-reason, grouped by what
# they mean for evidence availability rather than re-derived from scratch.
# The S0-only factors (no_observation, top_failed, proc_gone, no_file_list,
# lang_pkg_unmappable, db_absent, db_error) and the S1/S2-only ones
# (event_no_observation, event_path_unresolved, event_unavailable,
# mapping_input_missing) are both included, because effective_verdict's own
# factor is always the SELECTED series' own field - never S0's regardless
# of which series is being classified - so a set that only understood S0's
# vocabulary would silently fail to recognize the same condition reported
# under S1/S2's own names.
FACTORS_PERMISSION = {"proc_denied", "rootfs_denied"}
FACTORS_NO_OBSERVATION = {"no_observation", "top_failed", "proc_gone", "event_no_observation"}
FACTORS_MAPPING = {
    "no_file_list", "lang_pkg_unmappable", "db_absent", "db_error",
    "mapping_input_missing", "event_path_unresolved",
}

# event_drops fields (see EventDropCounts in events.go) that name a
# specific, measured loss rather than a boundary condition or a plain count
# of what the window covered. enter_exit_unmatched_boundary and
# events_before_filter/events_after_filter are deliberately excluded: the
# first is documented in the harness itself as "a boundary of what the run
# measures, not a loss inside it", and the second two are volume counters,
# not loss counters. These structured counters are the ONLY evidence this
# script accepts for "drops" - event_notes is free text the converter also
# uses to explain what it could NOT measure (e.g. a note naming
# "map_overflow" while that same counter reads zero, because the
# collection method in use cannot observe that condition at all), so
# matching against note text would read an admission of ignorance as proof
# of loss; notes are not consulted here at all.
MEASURED_LOSS_FIELDS = (
    "lost_events", "lost_notifications", "map_overflow",
    "path_read_failures", "path_truncations", "convert_failures",
    "enter_exit_unmatched", "identity_unavailable", "unmatched_identity_unavailable",
)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def parse_ts(s):
    """Parses an RFC3339 timestamp as this harness writes it (a trailing
    Z, and a fractional-second count that varies from file to file)."""
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # A fractional-second count fromisoformat does not accept (not a
        # multiple of 3 digits, or more than 6): pad/truncate to
        # microseconds and retry once, rather than failing the whole
        # summary over one timestamp's formatting.
        if "." in s:
            head, rest = s.split(".", 1)
            frac = rest
            tz = ""
            for i, ch in enumerate(rest):
                if ch in "+-":
                    frac, tz = rest[:i], rest[i:]
                    break
            frac = (frac + "000000")[:6]
            return datetime.fromisoformat(f"{head}.{frac}{tz}")
        raise


def read_timeline(run_dir):
    path = os.path.join(run_dir, "timeline.jsonl")
    events = []
    if not os.path.exists(path):
        return events
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def effective_observation_start(timeline):
    """Returns (mode, datetime) from the run's own recorded
    effective_observation_start event, or (None, None) if it is missing -
    an older or hand-built run directory without a timeline.jsonl, which
    this script must not guess a value for."""
    for e in timeline:
        if e.get("event") == "effective_observation_start":
            at = e.get("at")
            return e.get("mode"), (parse_ts(at) if at else None)
    return None, None


def discover_generations(run_dir):
    """Returns {container_name: [generation, ...]}, each generation sorted
    oldest-StartedAt-first, where a generation is
    {"base": ..., "match": <match_hc.json content>, "record": <collect record content>}.

    A generation is identified by its match_hc.json / collect record pair
    sharing a base filename (prod-observe.sh's own convention), but which
    container and which order they belong to is read from the JSON content
    itself (subject.docker.container_name, subject.started_at) rather than
    parsed out of the filename - a container name may itself contain the
    "__" prod-observe.sh's filenames use as a separator, and the content is
    authoritative regardless.
    """
    by_container = {}
    for match_path in sorted(glob.glob(os.path.join(run_dir, "match", "*" + MATCH_SUFFIX))):
        base = os.path.basename(match_path)[: -len(MATCH_SUFFIX)]
        record_path = os.path.join(run_dir, "collect", base + ".json")
        if not os.path.exists(record_path):
            continue
        match = load_json(match_path)
        record = load_json(record_path)
        name = record.get("subject", {}).get("docker", {}).get("container_name", base)
        started_at = record.get("subject", {}).get("started_at", "") or record.get("docker", {}).get("started_at", "")
        image_id = record.get("subject", {}).get("docker", {}).get("image_id", "")
        by_container.setdefault(name, []).append({
            "base": base, "match": match, "record": record, "started_at": started_at, "image_id": image_id,
        })
    for name in by_container:
        by_container[name].sort(key=lambda g: g["started_at"] or "")
    return by_container


def effective_verdict(pv):
    """Returns (verdict, factor, tier): s2_verdict when this package has
    one, else s1_verdict, else the S0 verdict - and which of the three it
    came from. A series' own field is only ever empty when that series
    never ran for this package at all (its input was missing, or a source
    it needed did not apply); "not confirmed" is itself a non-empty
    verdict value ("unobserved", "unresolved", "not_determined") and is
    never treated as a reason to fall back further."""
    s2 = pv.get("s2_verdict")
    if s2:
        return s2, pv.get("s2_factor") or "", "s2"
    s1 = pv.get("s1_verdict")
    if s1:
        return s1, pv.get("s1_factor") or "", "s1"
    return pv.get("verdict") or "", pv.get("factor") or "", "s0"


def measured_event_loss(event_drops):
    """Reports whether this generation's own event collection shows a
    specific, measured loss, from the structured drop counters alone -
    never from event_notes, which is free text the converter also uses to
    explain what it could NOT measure at all (a note can name a counter,
    such as map_overflow, purely to say the collection method in use
    cannot observe that condition, with the counter itself reading zero;
    matching against that text would read an admission of ignorance as
    proof of loss). event_state being "degraded" or "failed" is also not
    consulted here - see classify, which treats that as at most a
    drops_candidate on its own."""
    event_drops = event_drops or {}
    for field in MEASURED_LOSS_FIELDS:
        if (event_drops.get(field) or 0) > 0:
            return True
    return False


def classify(pv, container_started_at, obs_start, event_state, event_drops=None):
    """Classifies one PackageVerdict into the three states, returning
    (state, subreason, tier). subreason is None for confirmed and for
    undeterminable_started_before_observation; it is always set (possibly
    "unclassified") for no_evidence. tier says which of s2/s1/s0 the
    classification was actually read from (see effective_verdict), and is
    what factor and (implicitly) confirmation_gap_class below are read
    consistently with: confirmation_gap_class is always computed from the
    S0 verdict/factor in match itself (see classifyGap), so it is only
    ever consulted here when tier is "s0" - applying it while classifying
    by s1/s2 would read an S0-only judgement (e.g. E2) as if it described
    the selected series, even where that series' OWN factor already says
    something else (an S1/S2-specific mapping_input_missing or
    event_path_unresolved factor is what is used for those instead, via
    FACTORS_MAPPING - not confirmation_gap_class)."""
    verdict, factor, tier = effective_verdict(pv)
    if verdict == "confirmed":
        return "confirmed", None, tier

    if pv.get("class") == "lang" and container_started_at is not None and obs_start is not None:
        if container_started_at < obs_start:
            return "undeterminable_started_before_observation", None, tier

    if factor in FACTORS_PERMISSION:
        return "no_evidence", "permission_failure", tier
    if factor in FACTORS_NO_OBSERVATION or pv.get("observation_state") == "observation_failed":
        return "no_evidence", "no_observation", tier
    # Checked before drops: a confirmed mapping shortfall (the database
    # knows the package but not its files, or a language package with no
    # route to it at all) is a specific, already-decided reason and must
    # not be re-explained away as a guess about event loss.
    if factor in FACTORS_MAPPING or (tier == "s0" and pv.get("confirmation_gap_class") == "E2"):
        return "no_evidence", "mapping_unsupported", tier
    if pv.get("class") == "lang" and event_state in ("degraded", "failed"):
        if measured_event_loss(event_drops):
            return "no_evidence", "drops", tier
        return "no_evidence", "drops_candidate", tier
    return "no_evidence", "unclassified", tier


def build_rows(run_dir, by_container, obs_start):
    """Returns a flat list of per-Finding-population rows, one per package
    entry that carries at least one HIGH/CRITICAL Finding."""
    rows = []
    for name, gens in by_container.items():
        for gen_index, gen in enumerate(gens, start=1):
            started_at = parse_ts(gen["started_at"]) if gen["started_at"] else None
            m = gen["match"]
            event_state = m.get("event_state")
            event_drops = m.get("event_drops")
            for pv in m.get("packages", []):
                if not pv.get("finding_count"):
                    continue
                state, subreason, tier = classify(pv, started_at, obs_start, event_state, event_drops)
                rows.append({
                    "container": name,
                    "generation": gen_index,
                    "image_id": gen.get("image_id", ""),
                    "container_started_at": gen["started_at"],
                    "package": pv.get("package"),
                    "version": pv.get("installed_version"),
                    "class": pv.get("class"),
                    "finding_count": pv.get("finding_count", 0),
                    "verdict": pv.get("verdict"),
                    "s1_verdict": pv.get("s1_verdict") or "",
                    "s2_verdict": pv.get("s2_verdict") or "",
                    "verdict_tier_used": tier,
                    "event_state": event_state,
                    "observation_state": pv.get("observation_state"),
                    "state": state,
                    "subreason": subreason or "",
                })
    return rows


def counts_by_container_generation(rows):
    """Returns {(container, generation): {"findings": {state: n}, "packages": {state: n}}}."""
    out = {}
    for r in rows:
        key = (r["container"], r["generation"])
        bucket = out.setdefault(key, {"findings": {}, "packages": {}})
        bucket["findings"][r["state"]] = bucket["findings"].get(r["state"], 0) + r["finding_count"]
        bucket["packages"][r["state"]] = bucket["packages"].get(r["state"], 0) + 1
    return out


def first_evidence_for_package(pv):
    """Returns (observed_at, source) for the earliest entry in this
    specific package's own "confirmations" list, or (None, None) if it has
    none. confirmations is read directly off the PackageVerdict that was
    already selected for this exact (class, package, version) - never
    searched for by name across a match result's other packages, which
    could otherwise pick up a different version's evidence."""
    best = None
    for c in pv.get("confirmations", []):
        at = c.get("observed_at")
        if not at:
            continue
        if best is None or at < best[0]:
            best = (at, c.get("source"))
    return best if best else (None, None)


def package_key(pv):
    """The identifier a package is compared and looked up by everywhere in
    this script: class, name and installed version together. Name alone
    collapses two different versions of the same package into one entry
    (silently keeping only whichever the dict happened to see last) and
    would let an evidence lookup for one version return another's."""
    return (pv.get("class") or "", pv.get("package") or "", pv.get("installed_version") or "")


def before_after_rows(by_container, obs_start, before_ts=None, after_ts=None, container_filter=None):
    """Builds the per-package before/after table for every container that
    has more than one generation in this run. before_ts/after_ts (already
    parsed datetimes, or None) pick which generation is "before" and which
    is "after" when given; otherwise the first and last generation are
    used, which is what a single restart or re-creation during the run
    needs.

    Packages are compared by (class, name, version): a package present
    under the same key on both sides is a common target and gets a
    before/after row; one present only before or only after is reported as
    removed or added rather than merged with an unrelated version of the
    same name.
    """
    out = []
    for name, gens in by_container.items():
        if container_filter and name != container_filter:
            continue
        if len(gens) < 2:
            continue
        before_gen, after_gen = gens[0], gens[-1]
        if before_ts is not None:
            candidates = [g for g in gens if g["started_at"] and parse_ts(g["started_at"]) <= before_ts]
            if candidates:
                before_gen = candidates[-1]
        if after_ts is not None:
            # Both before_ts and after_ts answer the same question - which
            # generation was the running one at that moment - just anchored
            # at two different timestamps: the latest generation that had
            # already started by the given time.
            candidates = [g for g in gens if g["started_at"] and parse_ts(g["started_at"]) <= after_ts]
            if candidates:
                after_gen = candidates[-1]
        if before_gen is after_gen:
            continue

        before_index = gens.index(before_gen) + 1
        after_index = gens.index(after_gen) + 1
        before_started = parse_ts(before_gen["started_at"]) if before_gen["started_at"] else None
        after_started = parse_ts(after_gen["started_at"]) if after_gen["started_at"] else None
        before_pkgs = {package_key(pv): pv for pv in before_gen["match"].get("packages", []) if pv.get("finding_count")}
        after_pkgs = {package_key(pv): pv for pv in after_gen["match"].get("packages", []) if pv.get("finding_count")}

        for key in sorted(set(before_pkgs) | set(after_pkgs)):
            pv_before = before_pkgs.get(key)
            pv_after = after_pkgs.get(key)
            cls, pkg_name, _version = key

            state_before = subreason_before = None
            if pv_before is not None:
                state_before, subreason_before, _ = classify(
                    pv_before, before_started, obs_start,
                    before_gen["match"].get("event_state"), before_gen["match"].get("event_drops"))

            state_after = subreason_after = None
            evidence_at, evidence_type = (None, None)
            if pv_after is not None:
                state_after, subreason_after, _ = classify(
                    pv_after, after_started, obs_start,
                    after_gen["match"].get("event_state"), after_gen["match"].get("event_drops"))
                evidence_at, evidence_type = first_evidence_for_package(pv_after)

            if pv_before is None:
                membership = "added"
            elif pv_after is None:
                membership = "removed"
            else:
                membership = "common"

            reason = ""
            if membership == "removed":
                reason = "package no longer carries a HIGH/CRITICAL finding at this version in the generation after"
            elif state_after and state_after != "confirmed":
                reason = subreason_after or state_after

            out.append({
                "container": name,
                "class": cls,
                "package": pkg_name,
                "membership": membership,
                "before_generation": before_index if pv_before is not None else "",
                "after_generation": after_index if pv_after is not None else "",
                "before_image_id": before_gen.get("image_id", "") if pv_before is not None else "",
                "after_image_id": after_gen.get("image_id", "") if pv_after is not None else "",
                "version_before": pv_before.get("installed_version") if pv_before else "",
                "version_after": pv_after.get("installed_version") if pv_after else "",
                "state_before": state_before or "not_present",
                "state_after": state_after or "not_present",
                "first_evidence_time": evidence_at or "",
                "first_evidence_type": evidence_type or "",
                "remaining_reason": reason,
            })
    return out


def render_md(run_dir, by_container, rows, counts, ba_rows, obs_mode, obs_start):
    lines = []
    lines.append("# Production observation summary")
    lines.append("")
    lines.append(f"- run directory: {run_dir}")
    lines.append(f"- effective observation start: {obs_start.isoformat() if obs_start else 'unknown'} (mode: {obs_mode or 'unknown'})")
    lines.append(f"- containers observed: {len(by_container)}")
    total_gens = sum(len(g) for g in by_container.values())
    lines.append(f"- generations observed: {total_gens}")
    lines.append("")
    lines.append("## Per-container-generation counts")
    lines.append("")
    lines.append("HC finding count is the sum of the three states below (a Finding count, not a package count); package counts are separate and do not add to it.")
    lines.append("")
    lines.append("| container | generation | image_id | started_at | HC findings | confirmed | undeterminable (started before observation) | no_evidence | packages: confirmed | packages: undeterminable | packages: no_evidence |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, gens in by_container.items():
        for gen_index, gen in enumerate(gens, start=1):
            c = counts.get((name, gen_index), {"findings": {}, "packages": {}})
            f = c["findings"]; p = c["packages"]
            total = sum(f.values())
            lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                name, gen_index, gen.get("image_id", "") or "unknown", gen["started_at"] or "unknown", total,
                f.get("confirmed", 0), f.get("undeterminable_started_before_observation", 0), f.get("no_evidence", 0),
                p.get("confirmed", 0), p.get("undeterminable_started_before_observation", 0), p.get("no_evidence", 0),
            ))
    lines.append("")

    no_evidence_rows = [r for r in rows if r["state"] == "no_evidence"]
    if no_evidence_rows:
        lines.append("## no_evidence sub-reasons (Finding count)")
        lines.append("")
        sub_counts = {}
        for r in no_evidence_rows:
            sub_counts[r["subreason"]] = sub_counts.get(r["subreason"], 0) + r["finding_count"]
        lines.append("| sub-reason | HC findings |")
        lines.append("| --- | --- |")
        for sub, n in sorted(sub_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {sub} | {n} |")
        lines.append("")

    if ba_rows:
        lines.append("## Before / after a restart or re-creation")
        lines.append("")
        lines.append("Compared by class+name+version: \"common\" is the same key on both sides, \"added\"/\"removed\" is a key present on only one - a version bump between generations shows as one of each rather than a merged row.")
        lines.append("")
        lines.append("| container | class | package | version before | version after | membership | gen before | gen after | state before | state after | first evidence time | first evidence type | remaining reason |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in ba_rows:
            lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                r["container"], r["class"], r["package"], r["version_before"] or "-", r["version_after"] or "-",
                r["membership"], r["before_generation"] or "-", r["after_generation"] or "-",
                r["state_before"], r["state_after"], r["first_evidence_time"] or "-", r["first_evidence_type"] or "-",
                r["remaining_reason"] or "-",
            ))
        lines.append("")

    return "\n".join(lines) + "\n"


def write_csv(path, rows):
    fields = ["container", "generation", "image_id", "container_started_at", "package", "version", "class",
              "finding_count", "verdict", "s1_verdict", "s2_verdict", "verdict_tier_used",
              "event_state", "observation_state", "state", "subreason"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def parse_args(argv):
    if len(argv) < 1:
        raise SystemExit("Usage: prod_summary.py <run dir> [--before <ts>] [--after <ts>] [--container <name>]")
    run_dir = argv[0].rstrip("/")
    before = after = container = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--before" and i + 1 < len(argv):
            before = argv[i + 1]; i += 2
        elif a == "--after" and i + 1 < len(argv):
            after = argv[i + 1]; i += 2
        elif a == "--container" and i + 1 < len(argv):
            container = argv[i + 1]; i += 2
        else:
            raise SystemExit(f"prod_summary.py: unrecognized argument {a!r}")
    return run_dir, before, after, container


def main(argv):
    run_dir, before, after, container = parse_args(argv)
    timeline = read_timeline(run_dir)
    obs_mode, obs_start = effective_observation_start(timeline)
    by_container = discover_generations(run_dir)
    if container:
        by_container = {k: v for k, v in by_container.items() if k == container}
    if not by_container:
        print(f"prod_summary.py: no match/collect record pairs found under {run_dir}", file=sys.stderr)

    rows = build_rows(run_dir, by_container, obs_start)
    counts = counts_by_container_generation(rows)
    before_ts = parse_ts(before) if before else None
    after_ts = parse_ts(after) if after else None
    ba_rows = before_after_rows(by_container, obs_start, before_ts, after_ts, container)

    md = render_md(run_dir, by_container, rows, counts, ba_rows, obs_mode, obs_start)
    with open(os.path.join(run_dir, "prod_summary.md"), "w") as f:
        f.write(md)
    write_csv(os.path.join(run_dir, "prod_summary.csv"), rows)
    print(f"wrote {os.path.join(run_dir, 'prod_summary.md')} and prod_summary.csv "
          f"({len(rows)} finding-carrying package rows across {sum(len(g) for g in by_container.values())} generation(s))")


if __name__ == "__main__":
    main(sys.argv[1:])
