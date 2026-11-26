#!/usr/bin/env python3
"""Compares two ways of picking what to handle first from the same Trivy reports.

Rule A looks at the severity alone: CRITICAL or HIGH.
Rule B looks at two public exploitation signals and not at the severity: the
ID is in the CISA KEV catalog (exploited in the wild), or its EPSS score (the
estimated probability of exploitation in the next 30 days) is at or above a
threshold.

Inputs, as collected by collect.sh:
  raw/scans/*.json        Trivy JSON reports, one per image of images.txt
  raw/kev.json            CISA KEV catalog
  raw/epss.csv.gz         EPSS scores
  raw/trivy-version.json  Trivy and database versions of the scans
  raw/scan-options.txt    options passed to every scan

Outputs, written to --out (records/ by default):
  findings.tsv      every finding with the KEV and EPSS values joined to it
  intel-only.tsv    findings picked by rule B that are neither CRITICAL nor HIGH
  conditions.json   versions, dates, digests and thresholds of this run
  summary.md        the count tables

With --exclude-package the findings of the named packages are dropped before
anything is counted or written, and conditions.json records how many were
dropped. Such a run needs its own --out.

Counting units:
  finding  one entry of a Trivy report: a vulnerability ID on one package at
           one location
  ID       one vulnerability ID in one image; its severity is the highest
           severity among its findings in that image. The same ID in two
           images counts twice.

KEV and EPSS are keyed by CVE ID, and no alias is resolved: a finding whose ID
is not a CVE ID (for example a GHSA ID) has neither value. An empty epss
column means that no score was published for the ID. The ransomware column is
true only when the KEV entry says "Known"; false covers both "Unknown" and
IDs that are not in the catalog.
"""

import argparse
import collections
import csv
import gzip
import hashlib
import json
import math
import pathlib
import re
import sys

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}

FINDING_COLUMNS = [
    "image", "target", "class", "type", "package", "path", "installed", "fixed",
    "status", "severity", "id", "kev", "ransomware", "epss", "percentile",
]

SOURCES = [
    "CISA Known Exploited Vulnerabilities Catalog, https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "EPSS, maintained by the FIRST EPSS SIG, https://www.first.org/epss/; "
    "scores downloaded from https://epss.empiricalsecurity.com/",
]


CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def fail(message):
    sys.exit(f"compare.py: {message}")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_kev(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    entries = {}
    for v in doc.get("vulnerabilities") or []:
        cve = v["cveID"].strip().upper()
        if not CVE_ID.fullmatch(cve):
            fail(f"{path}: {cve!r} is not a CVE ID")
        if cve in entries:
            fail(f"{path}: {cve} is listed twice")
        entries[cve] = v.get("knownRansomwareCampaignUse", "").strip().lower() == "known"
    if not entries:
        fail(f"{path}: no entries")
    meta = {
        "catalog_version": doc.get("catalogVersion"),
        "date_released": doc.get("dateReleased"),
        "entries": len(entries),
        "sha256": sha256(path),
    }
    return entries, meta


def load_epss(path):
    """Returns {CVE ID: (score, percentile)} with both kept as the published text."""
    scores = {}
    meta = {"sha256": sha256(path)}
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        first = f.readline()
        if first.startswith("#"):
            for part in first.lstrip("#").strip().split(","):
                key, _, value = part.partition(":")
                meta[key.strip()] = value.strip()
        else:
            f.seek(0)
        reader = csv.DictReader(f)
        if not {"cve", "epss", "percentile"} <= set(reader.fieldnames or []):
            fail(f"{path}: expected the columns cve, epss and percentile")
        for row in reader:
            cve = row["cve"].strip().upper()
            if not CVE_ID.fullmatch(cve):
                fail(f"{path}: {cve!r} is not a CVE ID")
            if cve in scores:
                fail(f"{path}: {cve} is listed twice")
            for column in ("epss", "percentile"):
                value = float(row[column])
                if not (math.isfinite(value) and 0 <= value <= 1):
                    fail(f"{path}: {cve} has the {column} {row[column]}")
            scores[cve] = (row["epss"], row["percentile"])
    if not scores:
        fail(f"{path}: no scores")
    meta["entries"] = len(scores)
    return scores, meta


def load_report(path, kev, epss):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("SchemaVersion") != 2 or doc.get("ArtifactType") != "container_image":
        fail(f"{path}: not a Trivy schema version 2 report of a container image")
    if not isinstance(doc.get("Results"), list):
        fail(f"{path}: the report has no Results")
    image = doc["ArtifactName"]
    metadata = doc.get("Metadata", {})
    info = {
        "image": image,
        "repo_digests": metadata.get("RepoDigests", []),
        "image_id": metadata.get("ImageID"),
        "os": metadata.get("OS") or {},
        "report_created_at": doc.get("CreatedAt"),
        "report_trivy_version": doc.get("Trivy", {}).get("Version"),
        "report_sha256": sha256(path),
    }
    findings = []
    for result in doc["Results"]:
        for v in result.get("Vulnerabilities") or []:
            vuln_id = v["VulnerabilityID"].strip().upper()
            if not vuln_id:
                fail(f"{path}: a finding has no vulnerability ID")
            severity = v.get("Severity", "UNKNOWN")
            if severity not in SEVERITY_RANK:
                fail(f"{path}: {vuln_id} has the severity {severity!r}")
            score = epss.get(vuln_id)
            findings.append({
                "image": image,
                "target": result.get("Target", ""),
                "class": result.get("Class", ""),
                "type": result.get("Type", ""),
                "package": v.get("PkgName", ""),
                "path": v.get("PkgPath", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
                "status": v.get("Status", ""),
                "severity": severity,
                "id": vuln_id,
                "kev": vuln_id in kev,
                "ransomware": kev.get(vuln_id, False),
                "epss": score[0] if score else "",
                "percentile": score[1] if score else "",
            })
    return info, findings


def collapse_to_ids(findings):
    """One entry per (image, ID), carrying the highest severity of its findings."""
    by_key = {}
    for f in findings:
        key = (f["image"], f["id"])
        kept = by_key.get(key)
        if kept is None or SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[kept["severity"]]:
            by_key[key] = f
    return list(by_key.values())


class Rules:
    def __init__(self, act_now_epss, watch_epss):
        self.act_now_epss = act_now_epss
        self.watch_epss = watch_epss
        self.a_label = "A: CRITICAL or HIGH"
        self.b_label = f"B: KEV or EPSS >= {act_now_epss:g}"
        self.bands = [
            "In KEV",
            f"Not in KEV, EPSS >= {act_now_epss:g}",
            f"Not in KEV, {watch_epss:g} <= EPSS < {act_now_epss:g}",
            f"Not in KEV, EPSS < {watch_epss:g}",
            "Not in KEV, no EPSS",
        ]

    def band(self, f):
        """The exploitation signal of a finding, strongest first."""
        if f["kev"]:
            return self.bands[0]
        if f["epss"] == "":
            return self.bands[4]
        score = float(f["epss"])
        if score >= self.act_now_epss:
            return self.bands[1]
        if score >= self.watch_epss:
            return self.bands[2]
        return self.bands[3]

    def epss_at_least(self, f, threshold):
        return f["epss"] != "" and float(f["epss"]) >= threshold

    def by_intel(self, f):
        return f["kev"] or self.epss_at_least(f, self.act_now_epss)


def critical(f):
    return f["severity"] == "CRITICAL"


def critical_or_high(f):
    return f["severity"] in ("CRITICAL", "HIGH")


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join("---" for _ in header) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def per_image(images, entries, columns):
    """One row per image and a total row; columns are (label, predicate)."""
    rows = []
    for image in images + [None]:
        subset = [e for e in entries if image is None or e["image"] == image]
        rows.append([image or "Total"] + [sum(1 for e in subset if pred(e)) for _, pred in columns])
    return table(["Image"] + [label for label, _ in columns], rows)


def selection_tables(images, entries, rules):
    sizes = per_image(images, entries, [
        ("All", lambda e: True),
        ("CRITICAL", critical),
        (rules.a_label, critical_or_high),
        ("KEV", lambda e: e["kev"]),
        (f"EPSS >= {rules.act_now_epss:g}", lambda e: rules.epss_at_least(e, rules.act_now_epss)),
        (rules.b_label, rules.by_intel),
        (f"EPSS >= {rules.watch_epss:g}", lambda e: rules.epss_at_least(e, rules.watch_epss)),
    ])
    overlaps = []
    for label, by_severity in (("CRITICAL", critical), ("rule A", critical_or_high)):
        overlaps.append((label, per_image(images, entries, [
            ("Picked by both", lambda e, s=by_severity: s(e) and rules.by_intel(e)),
            (f"Only by {label}", lambda e, s=by_severity: s(e) and not rules.by_intel(e)),
            ("Only by rule B", lambda e, s=by_severity: not s(e) and rules.by_intel(e)),
        ])))
    return sizes, overlaps


def cross_table(entries, rules):
    counts = collections.Counter((e["severity"], rules.band(e)) for e in entries)
    rows = []
    for severity in SEVERITIES:
        cells = [counts[(severity, band)] for band in rules.bands]
        rows.append([severity] + cells + [sum(cells)])
    totals = [sum(counts[(s, band)] for s in SEVERITIES) for band in rules.bands]
    if sum(totals) != len(entries):
        fail("the severity table does not add up to the number of entries")
    rows.append(["Total"] + totals + [sum(totals)])
    return table(["Severity"] + rules.bands + ["Total"], rows)


def status_table(findings, rules):
    sets = [
        ("All", lambda f: True),
        (rules.a_label, critical_or_high),
        (rules.b_label, rules.by_intel),
    ]
    statuses = sorted({f["status"] for f in findings})
    rows = []
    for status in statuses:
        rows.append([f"Status {status}" if status else "Status empty"] + [
            sum(1 for f in findings if f["status"] == status and pred(f)) for _, pred in sets
        ])
    rows.append(["Fixed version given"] + [
        sum(1 for f in findings if f["fixed"] and pred(f)) for _, pred in sets
    ])
    rows.append(["No fixed version"] + [
        sum(1 for f in findings if not f["fixed"] and pred(f)) for _, pred in sets
    ])
    return table(["Findings"] + [label for label, _ in sets], rows)


def top_packages_table(images, findings, limit=3):
    rows = []
    for image in images:
        own = [f for f in findings if f["image"] == image]
        counts = collections.Counter(f["package"] for f in own)
        cells = [f"{name} {count} ({100 * count / len(own):.0f}%)"
                 for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]
        rows.append([image, len(counts)] + cells + [""] * (limit - len(cells)))
    return table(["Image", "Packages with findings"]
                 + [f"Most findings, {i + 1}" for i in range(limit)], rows)


def write_tsv(path, columns, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            writer.writerow(["true" if c is True else "false" if c is False else c for c in row])


def main():
    here = pathlib.Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw", type=pathlib.Path, default=here / "raw")
    parser.add_argument("--out", type=pathlib.Path)
    parser.add_argument("--images", type=pathlib.Path, default=here / "images.txt",
                        help="list of the images that must have exactly one report each")
    parser.add_argument("--act-now-epss", type=float, default=0.10)
    parser.add_argument("--watch-epss", type=float, default=0.01)
    parser.add_argument("--exclude-package", action="append", default=[], metavar="NAME",
                        help="drop the findings of this package before counting (repeatable)")
    args = parser.parse_args()
    if not 0 < args.watch_epss <= args.act_now_epss <= 1:
        parser.error("thresholds must satisfy 0 < watch <= act-now <= 1")
    if args.exclude_package and args.out is None:
        parser.error("--exclude-package needs its own --out")
    out = args.out or here / "records"

    rules = Rules(args.act_now_epss, args.watch_epss)
    kev, kev_meta = load_kev(args.raw / "kev.json")
    epss, epss_meta = load_epss(args.raw / "epss.csv.gz")

    infos, findings = [], []
    for path in sorted((args.raw / "scans").glob("*.json")):
        info, rows = load_report(path, kev, epss)
        infos.append(info)
        findings.extend(rows)

    listed = [line.strip() for line in args.images.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.startswith("#")]
    if not listed:
        fail(f"{args.images} lists no image")
    reported = collections.Counter(info["image"] for info in infos)
    problems = (
        [f"no report for {image}" for image in listed if image not in reported]
        + [f"report for {image}, which is not listed" for image in reported if image not in listed]
        + [f"{count} reports for {image}" for image, count in reported.items() if count > 1]
        + [f"{image} is listed twice" for image, count in collections.Counter(listed).items()
           if count > 1]
    )
    if problems:
        fail("reports and " + str(args.images) + " do not match: " + "; ".join(problems))

    with open(args.raw / "trivy-version.json", encoding="utf-8") as f:
        trivy = json.load(f)
    scan_options = (args.raw / "scan-options.txt").read_text(encoding="utf-8").strip()
    if not scan_options:
        fail(f"{args.raw / 'scan-options.txt'} is empty")
    trivy_version = trivy.get("Version")
    if not isinstance(trivy_version, str) or not trivy_version:
        fail(f"{args.raw / 'trivy-version.json'} has no Trivy version")
    for info in infos:
        if info["report_trivy_version"] != trivy_version:
            fail(f"the report of {info['image']} was made by Trivy {info['report_trivy_version']},"
                 f" not {trivy_version}")

    order = {image: i for i, image in enumerate(listed)}
    infos.sort(key=lambda info: order[info["image"]])
    images = [info["image"] for info in infos]

    excluded = collections.Counter(
        f["package"] for f in findings if f["package"] in args.exclude_package)
    findings = [f for f in findings if f["package"] not in args.exclude_package]
    ids = collapse_to_ids(findings)

    intel_only = sorted(
        (f for f in findings if rules.by_intel(f) and not critical_or_high(f)),
        key=lambda f: (order[f["image"]], f["id"], f["package"], f["target"], f["path"]),
    )
    conditions = {
        "trivy": trivy,
        "scan_options": scan_options,
        "kev": kev_meta,
        "epss": epss_meta,
        "sources": SOURCES,
        "thresholds": {"act_now_epss": args.act_now_epss, "watch_epss": args.watch_epss},
        "excluded_packages": {name: excluded[name] for name in args.exclude_package},
        "images": infos,
    }
    overview_rows = []
    for info in infos:
        own = [f for f in findings if f["image"] == info["image"]]
        os_info = info["os"]
        os_label = " ".join(x for x in (os_info.get("Family", ""), os_info.get("Name", "")) if x)
        if os_info.get("EOSL"):
            os_label += " (end of support)"
        by_severity = collections.Counter(f["severity"] for f in own)
        overview_rows.append(
            [info["image"], os_label, len(own), len({f["id"] for f in own})]
            + [by_severity[s] for s in SEVERITIES]
        )
    by_severity = collections.Counter(f["severity"] for f in findings)
    overview_rows.append(
        ["Total", "", len(findings), len(ids)] + [by_severity[s] for s in SEVERITIES])

    missing = per_image(images, findings, [
        ("ID is not a CVE ID", lambda f: not CVE_ID.fullmatch(f["id"])),
        ("CVE ID without EPSS", lambda f: CVE_ID.fullmatch(f["id"]) and f["epss"] == ""),
        ("Severity UNKNOWN", lambda f: f["severity"] == "UNKNOWN"),
    ])

    finding_sizes, finding_overlaps = selection_tables(images, findings, rules)
    id_sizes, id_overlaps = selection_tables(images, ids, rules)

    parts = [
        "# Comparison of severity-only selection with KEV and EPSS",
        "Generated by compare.py. The conditions of the run are in conditions.json.",
        "\n".join([
            "- Rules",
            f"    - Rule {rules.a_label}",
            f"    - Rule {rules.b_label}; rule B does not look at the severity",
            "- Counting units",
            "    - A finding is one entry of a Trivy report",
            "    - An ID is one vulnerability ID in one image, with the highest severity"
            " among its findings in that image",
            f"    - The total of IDs counts an ID once per image; {len({f['id'] for f in findings})}"
            " distinct IDs appear across all images",
            "- Data sources",
        ] + [f"    - {source}" for source in SOURCES]),
    ]
    if args.exclude_package:
        parts.append("Findings of these packages are excluded: "
                     + ", ".join(f"{name} ({excluded[name]})" for name in args.exclude_package) + ".")
    parts += [
        "## Findings per image",
        table(["Image", "OS", "Findings", "IDs"] + SEVERITIES, overview_rows),
        "## Packages with the most findings",
        top_packages_table(images, findings),
        "## Size of each selection, in findings",
        finding_sizes,
        "## Size of each selection, in IDs",
        id_sizes,
    ]
    for unit, overlaps in (("findings", finding_overlaps), ("IDs", id_overlaps)):
        for label, text in overlaps:
            parts += [f"## Overlap of {label} with rule B, in {unit}", text]
    parts += [
        "## Severity by exploitation signal, in findings",
        cross_table(findings, rules),
        "## Severity by exploitation signal, in IDs",
        cross_table(ids, rules),
        "## Fixed versions and Trivy status of the selected findings",
        "The status rows and the two fixed version rows each add up to the same findings.",
        status_table(findings, rules),
        "## Findings with missing information",
        missing,
    ]
    summary = "\n\n".join(parts) + "\n"
    conditions_text = json.dumps(conditions, indent=2, ensure_ascii=False) + "\n"

    # Nothing is written before every table is built and checked.
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / "findings.tsv", FINDING_COLUMNS,
              ([f[c] for c in FINDING_COLUMNS] for f in findings))
    write_tsv(out / "intel-only.tsv", FINDING_COLUMNS,
              ([f[c] for c in FINDING_COLUMNS] for f in intel_only))
    (out / "conditions.json").write_text(conditions_text, encoding="utf-8")
    (out / "summary.md").write_text(summary, encoding="utf-8")
    print(f"{len(infos)} images, {len(findings)} findings, {len(ids)} IDs -> {out}")


if __name__ == "__main__":
    main()
