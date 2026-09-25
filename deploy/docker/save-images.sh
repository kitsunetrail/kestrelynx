#!/usr/bin/env bash
# Builds the Sensor probe image for linux/amd64, bundles it with the pinned
# verification-target image and a manifest of both images' IDs into one
# tar, so a VPS running deploy/docker/run-probe.sh --image-tar never needs
# to build Go (15-20 minutes), reach a registry over the network, or trust
# a `docker load` result without checking it against what was actually
# built here.
#
# The target image tag here is kept in sync by hand with
# deploy/docker/probe-targets.sh's own IMAGE variable; if that script's pin
# changes, update the TARGET_IMAGE line below to match, or run-probe.sh's
# verification containers will fall back to pulling it over the network on
# the destination host after all.
#
# Bundle layout (a plain tar, not compressed — `docker save`'s own output
# inside it is already dense): images.tar (docker save's own output for
# both images) and manifest.txt (one "<tag> <image ID>" line per image, the
# ID docker image inspect reported right after this script built/pulled
# it). run-probe.sh --image-tar extracts both, loads images.tar, and
# refuses to proceed if any loaded image's ID does not match manifest.txt.
#
# Usage: deploy/docker/save-images.sh [output-tar-path]
#   output-tar-path defaults to <repo-root>/kestrelynx-probe-bundle.tar
#
# Requires: docker. amd64 is a fixed target regardless of the build host's
# own architecture (--platform linux/amd64) — the VPS this bundle is meant
# for is assumed amd64, which deploy/docker/run-probe.sh's own preflight
# check (uname -m) verifies before loading it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE_TAG="kestrelynx-sensor-probe:local"
TARGET_IMAGE="python:3.12.7-slim-bookworm" # keep in sync with probe-targets.sh's IMAGE

OUT="${1:-$REPO_ROOT/kestrelynx-probe-bundle.tar}"

echo "save-images.sh: building $IMAGE_TAG for linux/amd64" >&2
docker build --platform linux/amd64 -t "$IMAGE_TAG" -f "$REPO_ROOT/Dockerfile" "$REPO_ROOT"

echo "save-images.sh: pulling $TARGET_IMAGE for linux/amd64" >&2
docker pull --platform linux/amd64 "$TARGET_IMAGE"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "save-images.sh: recording image IDs" >&2
: >"$STAGE/manifest.txt"
for tag in "$IMAGE_TAG" "$TARGET_IMAGE"; do
	id="$(docker image inspect -f '{{.Id}}' "$tag")"
	printf '%s %s\n' "$tag" "$id" >>"$STAGE/manifest.txt"
done
cat "$STAGE/manifest.txt" >&2

echo "save-images.sh: saving both images" >&2
docker save -o "$STAGE/images.tar" "$IMAGE_TAG" "$TARGET_IMAGE"

echo "save-images.sh: bundling into $OUT" >&2
tar -cf "$OUT" -C "$STAGE" images.tar manifest.txt
du -h "$OUT" >&2

cat >&2 <<EOF
save-images.sh: done. Copy $OUT to the target host, then run there:
  deploy/docker/run-probe.sh --image-tar $(basename "$OUT")
EOF
