#!/usr/bin/env bash
# Collects the inputs of the comparison into raw/:
#   - one Trivy JSON report per image listed in images.txt
#   - the CISA KEV catalog and the current EPSS scores
#
# The vulnerability databases are downloaded on the first run only and every
# image is scanned against that same copy, so the reports are comparable with
# each other. A later run keeps the existing files and scans only the images
# that have no report yet; it stops when Trivy, its databases or the scan
# options are no longer the ones recorded by the first run. Delete raw/ to
# collect everything again.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p raw/scans

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
SCAN_OPTIONS=(--scanners vuln --image-src remote --platform linux/amd64
  --skip-db-update --skip-java-db-update)

fetch() {
  local url="$1" out="$2"
  if [[ ! -s "$out" ]]; then
    curl -fsSL --max-time 300 -o "$out.tmp" "$url"
    mv "$out.tmp" "$out"
  fi
}

fetch "$KEV_URL" raw/kev.json
fetch "$EPSS_URL" raw/epss.csv.gz

if [[ ! -s raw/trivy-version.json && ! -s raw/scan-options.txt ]]; then
  if compgen -G 'raw/scans/*' > /dev/null; then
    echo "raw/scans has reports without recorded conditions; delete raw/ to collect again" >&2
    exit 1
  fi
  trivy image --download-db-only --quiet
  trivy image --download-java-db-only --quiet
  trivy version --format json > raw/trivy-version.json
  printf '%s\n' "${SCAN_OPTIONS[*]}" > raw/scan-options.txt
elif ! trivy version --format json | cmp -s - raw/trivy-version.json; then
  echo "Trivy or its databases differ from raw/trivy-version.json; delete raw/ to collect again" >&2
  exit 1
elif [[ "$(cat raw/scan-options.txt 2>/dev/null)" != "${SCAN_OPTIONS[*]}" ]]; then
  echo "scan options differ from raw/scan-options.txt; delete raw/ to collect again" >&2
  exit 1
fi

failed=0
while read -r image; do
  [[ -z "$image" || "$image" == \#* ]] && continue
  out="raw/scans/$(printf '%s' "$image" | tr '/:' '__').json"
  if [[ -s "$out" ]]; then
    echo "keep  $image"
    continue
  fi
  echo "scan  $image"
  if trivy image --quiet "${SCAN_OPTIONS[@]}" --timeout 30m \
      --format json --output "$out.tmp" "$image" < /dev/null; then
    mv "$out.tmp" "$out"
  else
    echo "FAIL  $image" >&2
    rm -f "$out.tmp"
    failed=1
  fi
done < images.txt

exit "$failed"
