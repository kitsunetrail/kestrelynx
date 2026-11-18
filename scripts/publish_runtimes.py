#!/usr/bin/env python3
"""Checks for publishing internal/worker/runtimes.json as an OCI artifact on GHCR.

The workflow pushes the table with oras; this script holds the decisions around
the push so they can be tested without a registry.

  fixed-tag  print the fixed tag of a table: the schema number, a dash and the
             `updated` time as YYYYMMDDTHHMMSSZ (1-20261116T115854Z)
  compare    compare the table with what tag 1 of the repository holds now and
             write publish=true or publish=false (to $GITHUB_OUTPUT when it is
             set, and to the output); a table that differs from the published
             one must have a strictly later `updated`, or the script fails; a
             repository without tag 1 (the first publication) means publish=true
  verify     fetch tag 1 and its layer the way a running instance does, with no
             credentials, and fail unless the manifest has an artifact type and
             exactly one layer of the table's media type whose sha256 is the
             table's

Any check that fails ends the script with a non-zero status.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

TABLE = "internal/worker/runtimes.json"
MEDIA_TYPE = "application/vnd.kestrelynx.runtimes.v1+json"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MOVING_TAG = "1"
UPDATED_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NOT_FOUND_MARKERS = ("not found", "manifest unknown", "name unknown", "404")


class Failure(Exception):
    pass


# ---- pure functions on tables and manifests ----

def sha256_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_updated(value, what="the table"):
    """The UTC time of an `updated` value, which must be RFC 3339 with seconds and a Z."""
    if not isinstance(value, str) or not UPDATED_RE.match(value):
        raise Failure("%s has no valid updated (want a UTC time like 2026-11-16T11:58:54Z, got %r)" % (what, value))
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Failure("%s has no valid updated (got %r)" % (what, value))


def table_updated(data, what="the table"):
    try:
        table = json.loads(data)
    except ValueError as e:
        raise Failure("%s is not JSON: %s" % (what, e))
    if not isinstance(table, dict):
        raise Failure("%s is not a JSON object" % what)
    return table.get("updated"), table.get("schema")


def fixed_tag(data):
    updated, schema = table_updated(data)
    parse_updated(updated)
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        raise Failure("the table has no valid schema number (got %r)" % (schema,))
    if str(schema) != MOVING_TAG:
        raise Failure("the table has schema %d but the moving tag is %s" % (schema, MOVING_TAG))
    return "%s-%s" % (MOVING_TAG, updated.replace("-", "").replace(":", ""))


def parse_manifest(raw):
    try:
        m = json.loads(raw)
    except ValueError as e:
        raise Failure("the manifest is not JSON: %s" % e)
    if not isinstance(m, dict):
        raise Failure("the manifest is not a JSON object")
    return m


def single_layer(manifest):
    """The one layer descriptor of the manifest, whose media type must be the table's."""
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise Failure("the manifest must have exactly one layer (it has %s)" % (len(layers) if isinstance(layers, list) else "none"))
    layer = layers[0]
    if not isinstance(layer, dict) or layer.get("mediaType") != MEDIA_TYPE:
        raise Failure("the layer must have the media type %s (got %r)" % (MEDIA_TYPE, layer.get("mediaType") if isinstance(layer, dict) else layer))
    if not isinstance(layer.get("digest"), str) or not DIGEST_RE.match(layer["digest"]):
        raise Failure("the layer has no valid digest (got %r)" % (layer.get("digest"),))
    return layer


def check_manifest(manifest, want_digest):
    """Fail unless the manifest is an artifact of the table's type with the table as its only layer."""
    if manifest.get("schemaVersion") != 2:
        raise Failure("the manifest has schemaVersion %r, want 2" % (manifest.get("schemaVersion"),))
    if manifest.get("mediaType") != MANIFEST_MEDIA_TYPE:
        raise Failure("the manifest has mediaType %r, want %s" % (manifest.get("mediaType"), MANIFEST_MEDIA_TYPE))
    if manifest.get("artifactType") != MEDIA_TYPE:
        raise Failure("the manifest has artifactType %r, want %s" % (manifest.get("artifactType"), MEDIA_TYPE))
    layer = single_layer(manifest)
    if layer["digest"] != want_digest:
        raise Failure("the layer is %s but the table is %s" % (layer["digest"], want_digest))
    return layer


def decide(candidate, published_digest, published_data):
    """Whether to publish the candidate table.

    published_digest is None when the repository has no tag 1 yet. published_data
    is the layer the tag holds (read only when its digest differs).
    """
    updated, _ = table_updated(candidate, "the candidate table")
    new = parse_updated(updated, "the candidate table")
    if published_digest is None:
        return True
    if published_digest == sha256_of(candidate):
        return False
    old_updated, _ = table_updated(published_data, "the published table")
    # A published table without a usable updated is older than any table that has one.
    try:
        old = parse_updated(old_updated, "the published table")
    except Failure:
        return True
    if new <= old:
        raise Failure("the table changed but its updated (%s) is not later than the published one (%s); "
                      "a changed table needs a later updated, so publish the correction as a new table "
                      "with a later updated" % (updated, old_updated))
    return True


# ---- registry access ----

def split_repository(ref):
    host, _, path = ref.partition("/")
    if not host or not path:
        raise Failure("the repository %r must look like host/owner/name" % ref)
    return host, path


def run_oras(*args):
    try:
        return subprocess.run(("oras",) + args, capture_output=True)
    except FileNotFoundError:
        raise Failure("oras is not installed")


def published_layer(repository, plain_http, scratch):
    """(digest, data) of the layer tag 1 holds, or (None, None) when the tag does not exist."""
    flags = ["--plain-http"] if plain_http else []
    p = run_oras("manifest", "fetch", *flags, "%s:%s" % (repository, MOVING_TAG))
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip()
        if any(s in err.lower() for s in NOT_FOUND_MARKERS):
            return None, None
        raise Failure("could not fetch the manifest of %s:%s: %s" % (repository, MOVING_TAG, err[-600:]))
    layer = single_layer(parse_manifest(p.stdout))
    out = os.path.join(scratch, "published.json")
    p = run_oras("blob", "fetch", *flags, "--output", out, "%s@%s" % (repository, layer["digest"]))
    if p.returncode != 0:
        raise Failure("could not fetch the published layer: %s" % p.stderr.decode(errors="replace").strip()[-600:])
    with open(out, "rb") as f:
        data = f.read()
    if sha256_of(data) != layer["digest"]:
        raise Failure("the published layer does not match its digest %s" % layer["digest"])
    return layer["digest"], data


def anonymous_get(url, accept, token=None):
    req = urllib.request.Request(url, headers={"Accept": accept})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


DENIED = ("the package kestrelynx-runtimes cannot be read without credentials (%s); make the package "
          "public once in its package settings on GitHub, then run the workflow again")


def verify_anonymously(repository, data, plain_http, fetch=anonymous_get):
    host, path = split_repository(repository)
    base = "%s://%s" % ("http" if plain_http else "https", host)
    token = None
    try:
        if not plain_http:
            q = urllib.parse.urlencode({"scope": "repository:%s:pull" % path, "service": host})
            token = json.loads(fetch("%s/token?%s" % (base, q), "application/json")).get("token")
        raw = fetch("%s/v2/%s/manifests/%s" % (base, path, MOVING_TAG), MANIFEST_MEDIA_TYPE, token)
        layer = check_manifest(parse_manifest(raw), sha256_of(data))
        blob = fetch("%s/v2/%s/blobs/%s" % (base, path, layer["digest"]), "application/octet-stream", token)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 404):
            raise Failure(DENIED % ("HTTP %d" % e.code))
        raise Failure("the anonymous fetch failed: HTTP %d" % e.code)
    except urllib.error.URLError as e:
        raise Failure("the anonymous fetch failed: %s" % e.reason)
    if sha256_of(blob) != layer["digest"]:
        raise Failure("the layer fetched anonymously does not match its digest %s" % layer["digest"])
    if blob != data:
        raise Failure("the layer fetched anonymously is not the table")


# ---- commands ----

def read_table(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise Failure("cannot read the table: %s" % e)


def cmd_fixed_tag(args):
    print(fixed_tag(read_table(args.table)))
    return 0


def cmd_compare(args):
    data = read_table(args.table)
    with tempfile.TemporaryDirectory() as scratch:
        digest, published = published_layer(args.repository, args.plain_http, scratch)
    publish = decide(data, digest, published)
    line = "publish=%s" % ("true" if publish else "false")
    print(line)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(line + "\n")
    return 0


def cmd_verify(args):
    verify_anonymously(args.repository, read_table(args.table), args.plain_http)
    print("verified: %s:%s holds the table as one layer of %s" % (args.repository, MOVING_TAG, MEDIA_TYPE))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fixed-tag")
    f.add_argument("--table", default=TABLE)
    f.set_defaults(fn=cmd_fixed_tag)
    for name, fn in (("compare", cmd_compare), ("verify", cmd_verify)):
        c = sub.add_parser(name)
        c.add_argument("--table", default=TABLE)
        c.add_argument("--repository", required=True, help="host/owner/name, without a tag")
        # Only for a registry on localhost in tests; the workflow does not use it.
        c.add_argument("--plain-http", action="store_true", help=argparse.SUPPRESS)
        c.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Failure as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
