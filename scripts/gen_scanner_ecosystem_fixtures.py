#!/usr/bin/env python3
"""Regenerate internal/scanner/testdata/real_*.json from real Trivy scans.

These fixtures back internal/scanner/ecosystem_test.go: they must be real
Trivy output, never hand-authored. This script is the reproduction record —
run it end to end to recreate every file under internal/scanner/testdata/
whose name starts with "real_" and ends in one of the ecosystem suffixes
below, from scratch, using only public base images plus a couple of locally
built ones.

Requirements: docker (a local daemon), and the trivy binary on PATH (or set
TRIVY=/path/to/trivy). Tested with Trivy 0.71.2.

Usage:
    python3 scripts/gen_scanner_ecosystem_fixtures.py [--keep-raw DIR]

--keep-raw DIR also writes the untrimmed `trivy image --format json` output
for each target to DIR, for inspection. The trimmed files this script always
writes to internal/scanner/testdata/ are the untrimmed output with:
  - the top-level "Packages" field removed from every Result (scanner.go
    never parses it; it is the single largest contributor to file size —
    the full installed-package list, not just the vulnerable ones)
  - Vulnerabilities capped per Result, keeping every entry for the
    "target" package(s) this fixture exists to demonstrate (see
    TARGETS below) ahead of a few other packages kept only for variety
No Vulnerability entry is edited, reordered relative to its own package, or
fabricated — trimming only ever removes whole entries or the Packages field.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(REPO_ROOT, "internal", "scanner", "testdata")

TRIVY = os.environ.get("TRIVY", "trivy")

# Each entry: (output filename, image ref to scan, build steps or None for a
# plain public image, TARGETS = package names this fixture exists to prove
# out — every Vulnerability for these is kept; KEEP_OTHER = how many extra
# distinct packages' first vulnerability to keep for shape variety).
FIXTURES = [
    {
        "name": "real_alpine_3.19.json",
        "image": "alpine:3.19",
        "build": None,
        "targets": set(),
        "keep_other": 4,
    },
    {
        "name": "real_debian_12-slim.json",
        "image": "debian:12-slim",
        "build": None,
        "targets": set(),
        "keep_other": 4,
    },
    {
        "name": "real_python_3.9.1-slim_langpkg.json",
        "image": "python:3.9.1-slim",
        "build": None,
        # pip is the base image's own only lang-pkgs entry — there is no
        # separately "installed" target dependency to single out here.
        "targets": {"pip"},
        "keep_other": 4,
    },
    {
        "name": "real_node_lodash_nodepkg.json",
        "image": "kl-fixture-node:latest",
        "build": {
            "dockerfile": (
                "FROM node:20-slim\n"
                "WORKDIR /app\n"
                "RUN npm init -y >/dev/null && "
                "npm install lodash@4.17.19 --no-save --no-package-lock "
                "--no-audit --no-fund\n"
            ),
        },
        "targets": {"lodash"},
        "keep_other": 4,
    },
    {
        "name": "real_jar_commons-collections.json",
        "image": "kl-fixture-jar:latest",
        "build": {
            "dockerfile": (
                "FROM eclipse-temurin:17-jdk-jammy\n"
                "WORKDIR /app\n"
                "ADD https://repo1.maven.org/maven2/commons-collections/"
                "commons-collections/3.2.1/commons-collections-3.2.1.jar "
                "/app/commons-collections-3.2.1.jar\n"
            ),
        },
        "targets": {"commons-collections:commons-collections"},
        "keep_other": 4,
    },
    {
        "name": "real_gobinary_golang-x-text.json",
        "image": "kl-fixture-go:latest",
        "build": {
            # gorilla/mux v1.8.0 (the module this fixture was first built
            # around) carries no known CVE in Trivy's vulnerability DB, so a
            # trim that only keeps the first few Vulnerabilities per Result
            # silently drops every line for it and keeps only the Go
            # standard library's own findings instead — which is real Trivy
            # output, but proves nothing about a third-party gobinary
            # dependency. golang.org/x/text@v0.3.6 has real, longstanding
            # CVEs (CVE-2021-38561, CVE-2022-32149) and demonstrates the
            # same gobinary/Target shape.
            "go_get": "golang.org/x/text@v0.3.6",
            "go_import": "golang.org/x/text/language",
            "go_use": 'language.Make("en-US")',
        },
        "targets": {"golang.org/x/text"},
        "keep_other": 2,
    },
]


def run(cmd, **kw):
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, check=True, **kw)


def build_node_or_jar(build, tag, workdir):
    dpath = os.path.join(workdir, "Dockerfile")
    with open(dpath, "w") as f:
        f.write(build["dockerfile"])
    run(["docker", "build", "-t", tag, workdir])


def build_go(build, tag, workdir):
    with open(os.path.join(workdir, "main.go"), "w") as f:
        f.write(
            "package main\n\n"
            'import (\n\t"fmt"\n\n\t"%s"\n)\n\n'
            "func main() {\n\tfmt.Println(%s)\n}\n" % (build["go_import"], build["go_use"])
        )
    with open(os.path.join(workdir, "go.mod"), "w") as f:
        f.write("module example.com/gofixture\n\ngo 1.26.4\n")
    run(["go", "get", build["go_get"]], cwd=workdir)
    run(["go", "mod", "tidy"], cwd=workdir)
    run(["go", "build", "-o", "gofixture", "."], cwd=workdir)
    with open(os.path.join(workdir, "Dockerfile"), "w") as f:
        f.write("FROM scratch\nCOPY gofixture /usr/local/bin/gofixture\n")
    run(["docker", "build", "-t", tag, workdir])


def trim(raw, targets, keep_other):
    """Keep every Vulnerability for a package named in targets, plus exactly
    one Vulnerability each for up to keep_other other distinct packages (in
    the order Trivy listed them) — enough to show the Result's general shape
    without keeping the full per-package vulnerability list."""
    for res in raw.get("Results") or []:
        res.pop("Packages", None)
        vulns = res.get("Vulnerabilities") or []
        kept = []
        other_names_kept = []
        for v in vulns:
            name = v.get("PkgName")
            if name in targets:
                kept.append(v)
                continue
            if name in other_names_kept:
                continue  # already have one Vulnerability for this package
            if len(other_names_kept) >= keep_other:
                continue  # already have enough other packages
            other_names_kept.append(name)
            kept.append(v)
        res["Vulnerabilities"] = kept
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-raw", default=None, help="also save untrimmed scans here")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="kl-fixture-") as tmp:
        for spec in FIXTURES:
            image = spec["image"]
            if spec["build"] is not None:
                workdir = os.path.join(tmp, spec["name"])
                os.makedirs(workdir, exist_ok=True)
                if "go_get" in spec["build"]:
                    build_go(spec["build"], image, workdir)
                else:
                    build_node_or_jar(spec["build"], image, workdir)
            else:
                run(["docker", "pull", image])

            raw_path = os.path.join(tmp, spec["name"] + ".raw.json")
            run([TRIVY, "image", "--format", "json", "--scanners", "vuln", "-q", "-o", raw_path, image])
            with open(raw_path) as f:
                raw = json.load(f)

            if args.keep_raw:
                os.makedirs(args.keep_raw, exist_ok=True)
                with open(os.path.join(args.keep_raw, spec["name"]), "w") as f:
                    json.dump(raw, f, indent=2)

            trimmed = trim(raw, spec["targets"], spec["keep_other"])
            out_path = os.path.join(TESTDATA, spec["name"])
            with open(out_path, "w") as f:
                json.dump(trimmed, f, indent=2)
                f.write("\n")
            print("wrote", out_path, os.path.getsize(out_path), "bytes")


if __name__ == "__main__":
    main()
