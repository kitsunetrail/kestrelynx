#!/usr/bin/env bash
# Runs every test, with the integration tests that need Docker, the real Trivy and
# the network turned on. Those tests skip themselves when their variable is not
# set, so a run that left one out would look like a pass: a skip that names one of
# the variables below counts as a failure here. Run it from the repository root.
#
# KESTRELYNX_REALISTIC_DIR and KESTRELYNX_PNPM_PROJECTS_DIR are left out: their
# tests read sample projects that are not in this repository.
set -euo pipefail

gates='KESTRELYNX_DOCKER_IT|KESTRELYNX_WORKER_IT|KESTRELYNX_MAVEN_IT|KESTRELYNX_GRADLE_IT'
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

status=0
KESTRELYNX_DOCKER_IT=1 KESTRELYNX_WORKER_IT=1 KESTRELYNX_MAVEN_IT=1 KESTRELYNX_GRADLE_IT=1 \
  go test ./cmd/... ./internal/... -count=1 -v -timeout 60m "$@" >"$log" 2>&1 || status=$?
grep -E '^(--- FAIL|FAIL|ok|panic:)|^ +--- FAIL' "$log" || true

if [ "$status" != 0 ]; then
  # The whole log: a test's message comes before its --- FAIL line, and a build
  # failure has no such line at all.
  cat "$log" >&2
  echo "go test failed (exit $status)" >&2
  exit "$status"
fi
if grep -E "set ($gates)=" "$log"; then
  cat "$log" >&2
  echo "an integration test skipped although its variable is set" >&2
  exit 1
fi
grep -E '^ *--- SKIP' "$log" || true
echo "passed: $(grep -c -- '--- PASS' "$log"), skipped: $(grep -c -- '--- SKIP' "$log")"
