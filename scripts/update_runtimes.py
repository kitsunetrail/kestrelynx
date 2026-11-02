#!/usr/bin/env python3
"""Update internal/worker/runtimes.json from the official Node.js, Python, Go and Gradle images.

The update containers run in the official images the table pins by digest. This
script moves the pins forward and checks that the new images are still safe to
use. It needs the docker CLI (with buildx); Trivy runs from its container image.

  resolve      follow each series tag to its image index, run the image for both
               platforms to read the exact versions, read the image configuration,
               scan the final filesystem for what the job user could write, run
               Trivy, refresh the support dates, and write the candidate table
               and a report (the body of the pull request); it also adds a row
               for each newer series that endoflife.date lists as released and in
               support and whose official image tag exists, through the same
               checks
               The Gradle rows (one for each pair of a Gradle version and a JDK
               the Gradle compatibility matrix allows) are made without pulling
               any layer: the versions come from services.gradle.org, and the
               tags, digests and image configuration from the registry's API.
               A row whose tag still has the digest it was resolved to is left
               as it is.
  mark-tested  record the manifest digest of a platform for the runtimes named
               with --only, the ones whose fixtures passed on it; no other row
               is recorded
  scan-tar     print what a filesystem tar holds that the job user could write

Any check that fails ends the script with a non-zero status and leaves the
table as it was.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request

TABLE = "internal/worker/runtimes.json"
JOB_UID = 10001
PLATFORMS = ("linux/amd64", "linux/arm64")
TRIVY_IMAGE = "aquasec/trivy:0.71.2"
EOL_API = "https://endoflife.date/api/%s.json"
HUB_TAG = "https://hub.docker.com/v2/repositories/library/%s/tags/%s"
# Per kind: the endoflife.date product, the official image and the tag of a series.
KINDS = {
    "node": {"product": "nodejs", "image": "node", "tag": "%s-trixie-slim", "prefix": ""},
    "python": {"product": "python", "image": "python", "tag": "%s-slim-trixie", "prefix": "3."},
    "golang": {"product": "go", "image": "golang", "tag": "%s-trixie", "prefix": "1."},
}
# The environment variable of the image that holds the exact version.
VERSION_ENV = {"node": "NODE_VERSION", "python": "PYTHON_VERSION", "golang": "GOLANG_VERSION"}
# Paths the official images leave writable by everyone; a new row starts from
# them and the scan of the image has to agree.
STANDARD_COVERED_PATHS = ["/tmp", "/var/tmp", "/run/lock"]
# The Go image also leaves its GOPATH writable by everyone.
EXTRA_COVERED_PATHS = {"golang": ["/go"]}
FIELD_ORDER = ["id", "kind", "series", "version", "jdk", "pip", "image", "tag", "exact_tag", "index_digest", "platforms",
               "covered_paths", "volumes_empty", "volumes", "healthcheck", "support", "eol", "eol_month_only", "lts_from",
               "checked", "tested"]


class Failure(Exception):
    pass


class RateLimited(Failure):
    """The registry refused a request because of its limit on pulls."""


def run(*cmd, check=True, input=None):
    p = subprocess.run(cmd, capture_output=True, input=input)
    if check and p.returncode != 0:
        raise Failure("%s failed (%d): %s" % (" ".join(cmd), p.returncode, p.stderr.decode(errors="replace").strip()[-600:]))
    return p


def load(path):
    with open(path) as f:
        return json.load(f)


def save(path, table):
    with open(path, "w") as f:
        json.dump(table, f, indent=2)
        f.write("\n")


# ---- the image index ----

def resolve_index(image, tag):
    """Return (index digest, {platform: manifest digest}) of image:tag."""
    ref = "%s:%s" % (image, tag)
    raw = run("docker", "buildx", "imagetools", "inspect", "--raw", ref).stdout
    index = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    found = {}
    for m in index.get("manifests", []):
        p = m.get("platform", {})
        plat = "%s/%s" % (p.get("os"), p.get("architecture"))
        if plat in PLATFORMS and "vnd.docker.reference.type" not in m.get("annotations", {}):
            if plat in found:
                raise Failure("%s lists %s twice" % (ref, plat))
            found[plat] = m["digest"]
    if set(found) != set(PLATFORMS):
        raise Failure("%s does not have both platforms: %s" % (ref, sorted(found)))
    return digest, found


# ---- running the image ----

def docker_run(pinned, platform, *args):
    return run("docker", "run", "--rm", "--platform", platform, "--network", "none", "--entrypoint", args[0], pinned, *args[1:]).stdout.decode().strip()


def exact_versions(row, pinned, platform):
    """Return (language version, pip version) the image reports for a platform."""
    if row["kind"] == "node":
        out = docker_run(pinned, platform, "node", "--version")
        if not out.startswith("v"):
            raise Failure("node --version printed %r" % out)
        return out[1:], ""
    if row["kind"] == "golang":
        out = docker_run(pinned, platform, "go", "version")
        f = out.split()
        if len(f) != 4 or f[:2] != ["go", "version"] or not f[2].startswith("go") or f[3] != platform:
            raise Failure("go version printed %r" % out)
        return f[2][2:], ""
    if row["kind"] != "python":
        raise Failure("%s: no way to read the version of a %s image" % (row.get("id"), row["kind"]))
    py = "python" + row["series"]
    out = docker_run(pinned, platform, py, "--version")
    if not out.startswith("Python "):
        raise Failure("%s --version printed %r" % (py, out))
    pip = docker_run(pinned, platform, py, "-m", "pip", "--version").split()
    if len(pip) < 2 or pip[0] != "pip":
        raise Failure("pip --version printed %r" % " ".join(pip))
    return out.split()[1], pip[1]


def image_config(pinned, platform):
    """Return the image configuration of pinned, a single-platform manifest
    reference, after checking that the image is of that platform."""
    info = json.loads(run("docker", "image", "inspect", "--format", "{{json .}}", pinned).stdout)
    got = "%s/%s" % (info.get("Os"), info.get("Architecture"))
    if got != platform:
        raise Failure("%s: docker image inspect gave the %s image, not %s" % (pinned, got, platform))
    return info.get("Config") or {}


# ---- the final filesystem ----

def writable_by_job(member):
    """Whether the job user could write the entry, from the tar header alone."""
    if member.issym():
        return member.uid == JOB_UID
    if member.uid == JOB_UID:
        return True
    if member.mode & 0o002:
        return True
    if member.gid == JOB_UID and member.mode & 0o020:
        return True
    acl = member.pax_headers.get("SCHILY.acl.access", "")
    return any(("user:%d:" % JOB_UID) in e and "w" in e.split(":")[-1] for e in acl.split(",") if e)


def scan_stream(fileobj):
    """Return the entries of a filesystem tar the job user could write."""
    found = []
    with tarfile.open(fileobj=fileobj, mode="r|") as tf:
        for m in tf:
            if writable_by_job(m):
                name = m.name[2:] if m.name.startswith("./") else m.name
                found.append("/" + name.rstrip("/"))
    return found


# The engine mounts these when it starts a container; their contents are not
# part of the image.
ENGINE_PATHS = ("/proc", "/sys", "/dev")


def top_paths(paths):
    """Keep the entries not below another entry of the list, and leave out the
    engine's own mount points."""
    out = []
    for p in sorted(set(paths)):
        if any(p == e or p.startswith(e + "/") for e in ENGINE_PATHS):
            continue
        if not any(p == q or p.startswith(q + "/") for q in out):
            out.append(p)
    return out


def scan_image(pinned, platform):
    cid = run("docker", "create", "--platform", platform, pinned).stdout.decode().strip()
    try:
        exp = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        found = scan_stream(exp.stdout)
        exp.stdout.close()
        if exp.wait() != 0:
            raise Failure("docker export failed")
    finally:
        run("docker", "rm", "-f", cid, check=False)
    return top_paths(found)


# ---- Trivy ----

def trivy(pinned, platform):
    """Return the findings Trivy reports for the image. A scan that cannot be
    made or read is a Failure: an image that was not checked is not pinned."""
    p = run("docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", TRIVY_IMAGE, "image", "--quiet",
            "--platform", platform, "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--format", "json", pinned,
            check=False)
    if p.returncode != 0:
        raise Failure("Trivy could not scan %s (%d): %s" % (pinned, p.returncode, p.stderr.decode(errors="replace").strip()[-300:]))
    try:
        results = json.loads(p.stdout).get("Results") or []
    except (ValueError, AttributeError) as e:
        raise Failure("Trivy's report for %s cannot be read: %s" % (pinned, e))
    findings = []
    for r in results:
        for v in r.get("Vulnerabilities") or []:
            findings.append((v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion", ""), v.get("FixedVersion", ""), v.get("Severity", "")))
    return findings


# ---- support dates and new series ----

def fetch_json(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def cycles_of(kind):
    """Return {series: entry} of the release cycles endoflife.date lists."""
    return {str(c["cycle"]): c for c in fetch_json(EOL_API % KINDS[kind]["product"])}


DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def is_date(v):
    """Whether v is a calendar date written YYYY-MM-DD."""
    if not isinstance(v, str) or not DATE_RE.match(v):
        return False
    try:
        datetime.date.fromisoformat(v)
    except ValueError:
        return False
    return True


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def today_utc(now=None):
    """Today's date in UTC, the zone the build judges the end of support in."""
    now = now or now_utc()
    return now.astimezone(datetime.timezone.utc).date().isoformat()


def support_state(kind, entry, today):
    """The maintenance state of a cycle on the date today (ISO date)."""
    if is_date(entry.get("eol")) and entry["eol"] < today:
        return "end_of_life"
    if kind == "golang":
        # Go supports a series until two newer ones are released.
        return "supported"
    if kind == "node":
        in_support = is_date(entry.get("support")) and today < entry["support"]
        if not is_date(entry.get("lts")):
            # A series that never enters long-term support.
            return "current" if in_support else "maintenance"
        if today < entry["lts"]:
            return "current"
        return "lts" if in_support else "maintenance"
    if is_date(entry.get("support")) and today < entry["support"]:
        return "bugfix"
    return "security"


def optional_date(entry, key):
    """Return the date an optional field of a cycle holds, or None when the
    field is absent or false (endoflife.date's way to say there is none). Any
    other value that is not a calendar date, an explicit null included, is a
    Failure: it is not read as "none"."""
    if key not in entry:
        return None
    v = entry[key]
    if v is False:
        return None
    if is_date(v):
        return v
    raise Failure("endoflife.date gives %r as %s of %s" % (v, key, entry.get("cycle")))


def with_estimated_eol(kind, entry):
    """endoflife.date gives a Go series that is still supported no end date
    (false), because it ends when the second newer series is released. The end
    is then taken to be one year after the release, the interval of two
    six-monthly releases; it is replaced by the published date when there is
    one."""
    released = entry.get("releaseDate")
    if kind != "golang" or entry.get("eol") is not False or not is_date(released):
        return entry
    d = datetime.date.fromisoformat(released)
    try:
        end = d.replace(year=d.year + 1)
    except ValueError:
        end = d.replace(year=d.year + 1, day=28)
    return dict(entry, eol=end.isoformat())


def support_facts(kind, entry, today):
    """Return the fields of a row that endoflife.date decides for a cycle: the
    end of support, the start of long-term support (Node.js) and the state.
    The answer has to hold together: the release date and the end of support
    are dates, any other date is a date or false, and release <= start of
    long-term support <= end of support. Otherwise a Failure is raised and none
    of the cycle's answer is used."""
    entry = with_estimated_eol(kind, entry)
    cycle = entry.get("cycle")
    released, eol = entry.get("releaseDate"), entry.get("eol")
    if not is_date(released):
        raise Failure("endoflife.date gives %r as the release date of %s %s" % (released, kind, cycle))
    if not is_date(eol):
        raise Failure("endoflife.date gives %r as the end of support of %s %s" % (eol, kind, cycle))
    lts = optional_date(entry, "lts")
    if entry.get("support") is not True:
        optional_date(entry, "support")
    if released > eol:
        raise Failure("%s %s is released (%s) after its end of support (%s)" % (kind, cycle, released, eol))
    if lts and (lts < released or lts > eol):
        raise Failure("%s %s starts long-term support (%s) outside its release (%s) and end of support (%s)" % (kind, cycle, lts, released, eol))
    facts = {"eol": eol, "support": support_state(kind, entry, today)}
    if kind == "node" and lts:
        facts["lts_from"] = lts
    return facts


def support_dates(today):
    """Return {runtime id: facts} from endoflife.date. The dates are refreshed
    when they can be read; a failure to read them is reported and leaves the
    rows as they are."""
    out = {}
    try:
        for kind, k in KINDS.items():
            for series, entry in cycles_of(kind).items():
                entry = with_estimated_eol(kind, entry)
                if series.startswith(k["prefix"]) and (kind != "node" or series.isdigit()) and entry.get("eol") is not None and not isinstance(entry["eol"], bool):
                    try:
                        out[kind + series] = support_facts(kind, entry, today)
                    except Failure as e:
                        print("support dates of %s%s skipped: %s" % (kind, series, e), file=sys.stderr)
    except Exception as e:
        print("support dates not refreshed: %s" % e, file=sys.stderr)
        return {}
    return out


def series_key(kind, series):
    """Order key of a series: 24 -> (24,), 3.15 -> (3, 15)."""
    return tuple(int(p) for p in series.split("."))


def tag_exists(kind, series):
    """Whether the official image has the series tag. Only a 404 means it has
    not; any other failure to ask is a Failure."""
    k = KINDS[kind]
    url = HUB_TAG % (k["image"], k["tag"] % series)
    try:
        with urllib.request.urlopen(url, timeout=30):
            return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise Failure("Docker Hub answered %d for %s" % (e.code, url))
    except OSError as e:
        raise Failure("Docker Hub could not be asked about %s: %s" % (url, e))


def new_series(table, kind, cycles, today, exists=None):
    """Return (series, facts) of the series newer than every series of the
    table that have been released, are in support, and have an official image
    tag, oldest first."""
    exists = exists or tag_exists
    have = [series_key(kind, r["series"]) for r in table["runtimes"] if r["kind"] == kind]
    top = max(have) if have else ()
    found = []
    for series, entry in cycles.items():
        k = KINDS[kind]
        if not series.startswith(k["prefix"]) or (kind == "node" and not series.isdigit()):
            continue
        if series_key(kind, series) <= top:
            continue
        released = entry.get("releaseDate")
        if not is_date(released) or released > today:
            continue
        entry = with_estimated_eol(kind, entry)
        if not is_date(entry.get("eol")) or entry["eol"] < today:
            continue
        try:
            facts = support_facts(kind, entry, today)
        except Failure as e:
            # An answer that does not hold together adds no row.
            print("%s%s not added: %s" % (kind, series, e), file=sys.stderr)
            continue
        if not exists(kind, series):
            continue
        found.append((series, facts))
    found.sort(key=lambda f: series_key(kind, f[0]))
    return found


def skeleton(kind, series, facts, today):
    """The row of a new series, before its image has been resolved."""
    k = KINDS[kind]
    row = {"id": kind + series, "kind": kind, "series": series, "image": k["image"], "tag": k["tag"] % series,
           "covered_paths": STANDARD_COVERED_PATHS + EXTRA_COVERED_PATHS.get(kind, []), "volumes_empty": True, "healthcheck": False,
           "checked": today, "tested": {}}
    row.update(facts)
    return row


def ordered(row):
    """The row with its fields in the order the table is written in."""
    extra = sorted(k for k in row if k not in FIELD_ORDER)
    return {k: row[k] for k in FIELD_ORDER + extra if k in row}


# ---- Gradle images ----
#
# One row for each pair of a Gradle version and a JDK. Nothing is pulled: the
# registry's API gives the index, the manifest of each platform and the image
# configuration, which is all a row records. The paths the job user could write
# are not scanned for these rows; the table records the ones found in the
# official images (GRADLE_COVERED_PATHS), and the configuration is required to
# declare no volume beyond GRADLE_VOLUMES.

GRADLE_VERSIONS = "https://services.gradle.org/versions/all"
GRADLE_IMAGE = "gradle"
GRADLE_MAJORS = ("8", "9")
# The lowest Gradle version that runs on a JDK, from Gradle's compatibility matrix.
GRADLE_MIN_VERSION = {"17": (8, 0), "21": (8, 5), "25": (9, 1, 0)}
GRADLE_JAVA_HOME = "/opt/java/openjdk"
GRADLE_VOLUMES = ["/home/gradle/.gradle"]
GRADLE_COVERED_PATHS = ["/home/gradle", "/home/gradle/.gradle", "/run/lock", "/tmp", "/var/lib/pebble/default", "/var/tmp"]
REGISTRY = "https://registry-1.docker.io"
REGISTRY_AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/%s:pull"
MANIFEST_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
GRADLE_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def version_key(v):
    return tuple(int(p) for p in v.split("."))


def final_gradle_versions(entries):
    """The versions of the Gradle majors in GRADLE_MAJORS that are releases: not
    a snapshot, nightly, release candidate, milestone or broken release."""
    out = set()
    for e in entries:
        v = e.get("version", "")
        if not GRADLE_VERSION_RE.match(v) or v.split(".")[0] not in GRADLE_MAJORS:
            continue
        if any(e.get(k) for k in ("snapshot", "nightly", "releaseNightly", "broken", "activeRc", "rcFor", "milestoneFor")):
            continue
        out.add(v)
    return sorted(out, key=version_key)


def gradle_pairs(versions):
    """The (version, JDK) pairs on which the version of Gradle itself runs."""
    return [(v, jdk) for v in versions for jdk in GRADLE_MIN_VERSION if version_key(v) >= GRADLE_MIN_VERSION[jdk]]


def gradle_row_id(version, jdk):
    return "gradle%s-jdk%s" % (version, jdk)


def gradle_skeleton(version, jdk, today):
    tag = "%s-jdk%s" % (version, jdk)
    return {"id": gradle_row_id(version, jdk), "kind": "gradle", "series": version.split(".")[0], "version": version, "jdk": jdk,
            "image": GRADLE_IMAGE, "tag": tag, "exact_tag": tag,
            "covered_paths": list(GRADLE_COVERED_PATHS), "volumes": list(GRADLE_VOLUMES), "healthcheck": False,
            "checked": today, "tested": {}}


class NoRedirectAuth(urllib.request.HTTPRedirectHandler):
    """Follow redirects without the registry's token: the blob stores the
    registry redirects to take their own signature and refuse another."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


class Registry:
    """The part of the Docker registry API the Gradle rows need, for the
    official images of Docker Hub. A pull token is asked for once per
    repository; DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, when set, are used to
    get it, which raises the limit on requests."""

    def __init__(self, opener=None):
        self.opener = opener or urllib.request.build_opener(NoRedirectAuth)
        self.tokens = {}

    def token(self, repo):
        if repo not in self.tokens:
            req = urllib.request.Request(REGISTRY_AUTH % repo)
            user, pw = os.environ.get("DOCKERHUB_USERNAME"), os.environ.get("DOCKERHUB_TOKEN")
            if user and pw:
                import base64
                req.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode())
            self.tokens[repo] = json.load(self.opener.open(req, timeout=30))["token"]
        return self.tokens[repo]

    def head(self, repo, tag):
        """Return the digest the tag of library/<repo> points at, or None when
        there is no such tag. A HEAD request is not counted against the limit
        on pulls."""
        req = urllib.request.Request("%s/v2/library/%s/manifests/%s" % (REGISTRY, repo, tag), method="HEAD")
        req.add_header("Authorization", "Bearer " + self.token(repo))
        req.add_header("Accept", MANIFEST_TYPES)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.headers.get("Docker-Content-Digest")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                raise RateLimited("Docker Hub's limit on requests was reached asking for the tag %s/%s" % (repo, tag))
            raise Failure("the registry answered %d for the tag %s/%s" % (e.code, repo, tag))
        except OSError as e:
            raise Failure("the registry could not be asked about the tag %s/%s: %s" % (repo, tag, e))

    def get(self, repo, kind, ref):
        """Return (status, headers, body) of a manifest (kind "manifests") or
        blob (kind "blobs") of library/<repo>. 404 is an answer; a limit on
        requests or any other failure is a Failure."""
        req = urllib.request.Request("%s/v2/library/%s/%s/%s" % (REGISTRY, repo, kind, ref))
        req.add_header("Authorization", "Bearer " + self.token(repo))
        req.add_header("Accept", MANIFEST_TYPES)
        try:
            with self.opener.open(req, timeout=60) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, {}, b""
            if e.code == 429:
                raise RateLimited("Docker Hub's limit on requests was reached asking for %s/%s" % (repo, ref))
            raise Failure("the registry answered %d for %s/%s" % (e.code, repo, ref))
        except OSError as e:
            raise Failure("the registry could not be asked about %s/%s: %s" % (repo, ref, e))


def gradle_image(registry, tag):
    """Return (index digest, {platform: manifest digest}, {platform: image
    config}) of gradle:tag, or None when the tag does not exist. The image
    needs both platforms. The configuration of each is read from its config
    blob."""
    status, _, raw = registry.get(GRADLE_IMAGE, "manifests", tag)
    if status == 404:
        return None
    index = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    found = {}
    for m in index.get("manifests", []):
        p = m.get("platform", {})
        plat = "%s/%s" % (p.get("os"), p.get("architecture"))
        if plat in PLATFORMS and "vnd.docker.reference.type" not in m.get("annotations", {}):
            if plat in found:
                raise Failure("gradle:%s lists %s twice" % (tag, plat))
            if not DIGEST_RE.match(m.get("digest", "")):
                raise Failure("gradle:%s lists %s with the digest %r" % (tag, plat, m.get("digest")))
            found[plat] = m["digest"]
    if set(found) != set(PLATFORMS):
        # A tag of one platform only is not a row: both are needed.
        return None
    configs = {}
    for plat, d in found.items():
        status, _, body = registry.get(GRADLE_IMAGE, "manifests", d)
        if status != 200:
            raise Failure("gradle:%s: the manifest %s of %s is not served (%d)" % (tag, d, plat, status))
        if "sha256:" + hashlib.sha256(body).hexdigest() != d:
            raise Failure("gradle:%s: the manifest of %s does not match its digest %s" % (tag, plat, d))
        cfg_digest = json.loads(body).get("config", {}).get("digest", "")
        if not DIGEST_RE.match(cfg_digest):
            raise Failure("gradle:%s: the manifest of %s has no config digest" % (tag, plat))
        status, _, blob = registry.get(GRADLE_IMAGE, "blobs", cfg_digest)
        if status != 200 or "sha256:" + hashlib.sha256(blob).hexdigest() != cfg_digest:
            raise Failure("gradle:%s: the configuration of %s cannot be read or does not match its digest" % (tag, plat))
        cfg = json.loads(blob)
        got = "%s/%s" % (cfg.get("os"), cfg.get("architecture"))
        if got != plat:
            raise Failure("gradle:%s: the configuration of %s is of %s" % (tag, plat, got))
        configs[plat] = cfg.get("config") or {}
    return digest, found, configs


def check_gradle_config(row, plat, cfg):
    """A Gradle image is a row only when its configuration says what the table
    records: the Gradle version and the JDK location in its environment, no
    health check, and no volume other than the one the table covers."""
    rid = row["id"]
    env = dict(e.split("=", 1) for e in cfg.get("Env") or [])
    if env.get("GRADLE_VERSION") != row["version"]:
        raise Failure("%s %s: GRADLE_VERSION is %r, the row is for %s" % (rid, plat, env.get("GRADLE_VERSION"), row["version"]))
    if env.get("JAVA_HOME") != GRADLE_JAVA_HOME:
        raise Failure("%s %s: JAVA_HOME is %r, not %s" % (rid, plat, env.get("JAVA_HOME"), GRADLE_JAVA_HOME))
    if not re.match(r"^jdk-%s[.+]" % row["jdk"], env.get("JAVA_VERSION", "")):
        raise Failure("%s %s: JAVA_VERSION is %r, the row is for JDK %s" % (rid, plat, env.get("JAVA_VERSION"), row["jdk"]))
    if cfg.get("Healthcheck"):
        raise Failure("%s %s declares a health check" % (rid, plat))
    extra = sorted(set(cfg.get("Volumes") or {}) - set(GRADLE_VOLUMES))
    if extra:
        raise Failure("%s %s declares volumes the table does not cover: %s" % (rid, plat, extra))


def resolve_gradle_row(registry, row, today, report):
    """Return the row as the registry has it now, or None when the tag does not
    exist (both platforms are needed). The row is kept as it is when the tag
    still points at its index digest."""
    rid = row["id"]
    if row.get("index_digest") and registry.head(GRADLE_IMAGE, row["tag"]) == row["index_digest"]:
        return dict(row, checked=today)
    found = gradle_image(registry, row["tag"])
    if found is None:
        report.append("- %s: no image for both platforms under the tag %s" % (rid, row["tag"]))
        return None
    index, manifests, configs = found
    if not row.get("index_digest"):
        # The tag of a release that later had patch releases (8.0, 8.1, 8.2)
        # points at the newest patch release: the image is not the exact
        # version of the row.
        for plat, cfg in configs.items():
            env = dict(e.split("=", 1) for e in cfg.get("Env") or [])
            if env.get("GRADLE_VERSION") != row["version"]:
                report.append("- %s: the tag %s is the image of Gradle %s, not of %s" % (rid, row["tag"], env.get("GRADLE_VERSION"), row["version"]))
                return None
    for plat, cfg in configs.items():
        check_gradle_config(row, plat, cfg)
    new = dict(row)
    new.update(index_digest=index, platforms=manifests, checked=today)
    if (index, manifests) != (row.get("index_digest"), row.get("platforms")):
        new["tested"] = {}
        report.append("- %s: %s" % (rid, ("added, " if "index_digest" not in row else "image changed, ") + index[:19]))
    return new


def cmd_resolve_gradle(table, only, today, report, registry=None, versions=None):
    """Add the Gradle rows that are missing and refresh the others. Returns
    whether the table changed. When the registry's limit on pulls is reached
    the rows done so far are kept and the pairs left are reported: the next run
    goes on from them, because a row whose tag still has its digest costs no
    pull. Any other failure ends the run with the table as it was."""
    registry = registry or Registry()
    if versions is None:
        versions = final_gradle_versions(fetch_json(GRADLE_VERSIONS))
    rows = table["runtimes"]
    by_id = {r["id"]: r for r in rows}
    changed = False
    for version, jdk in gradle_pairs(versions):
        rid = gradle_row_id(version, jdk)
        if only is not None and rid not in only:
            continue
        old = by_id.get(rid)
        row = old or gradle_skeleton(version, jdk, today)
        try:
            new = resolve_gradle_row(registry, row, today, report)
        except RateLimited as e:
            left = [gradle_row_id(*p) for p in gradle_pairs(versions) if (only is None or gradle_row_id(*p) in only)]
            left = left[left.index(rid):]
            report.append("- stopped at %s: %s; %d row(s) not looked at yet (set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, or run again later)" % (rid, e, len(left)))
            print("warning: " + report[-1], file=sys.stderr)
            break
        if new is None:
            continue
        if old is None:
            rows.append(ordered(new))
            by_id[rid] = rows[-1]
            changed = True
        else:
            if {k: v for k, v in new.items() if k != "checked"} != {k: v for k, v in old.items() if k != "checked"}:
                changed = True
            old.clear()
            old.update(ordered(new))
    return changed


# ---- the commands ----

IMAGE_FIELDS = ("version", "pip", "exact_tag", "index_digest", "platforms")


def add_new_series(table, only, today, report):
    """Add a skeleton row for each newer series that is released, in support
    and has an official image tag. Returns whether a row was added."""
    added = False
    for kind in KINDS:
        try:
            cycles = cycles_of(kind)
        except Exception as e:
            print("new %s series not looked for: %s" % (kind, e), file=sys.stderr)
            continue
        for series, facts in new_series(table, kind, cycles, today):
            rid = kind + series
            if only and rid not in only:
                continue
            rows = table["runtimes"]
            last = max((i for i, r in enumerate(rows) if r["kind"] == kind), default=len(rows) - 1)
            rows.insert(last + 1, skeleton(kind, series, facts, today))
            report.append("- %s: added (end of support %s, %s)" % (rid, facts["eol"], facts["support"]))
            added = True
    return added


def refresh_facts(row, facts):
    """Set the support fields endoflife.date decides; a month-only date of
    an earlier table is replaced by the full date."""
    row.update(facts)
    row.pop("eol_month_only", None)
    if "lts_from" not in facts:
        row.pop("lts_from", None)


def resolve_row(row, facts, today, report):
    """Run every check on the image of a row and return the row as it is now."""
    rid = row["id"]
    index, manifests = resolve_index(row["image"], row["tag"])
    # Each platform is pulled, run and read by its own manifest digest: a
    # Docker engine without the containerd image store keeps one image per
    # reference, so the index digest cannot name both platforms locally.
    pinned = {plat: "%s@%s" % (row["image"], manifests[plat]) for plat in PLATFORMS}
    versions = set()
    for plat in PLATFORMS:
        run("docker", "pull", "--quiet", "--platform", plat, pinned[plat])
        versions.add(exact_versions(row, pinned[plat], plat))
        cfg = image_config(pinned[plat], plat)
        if cfg.get("Volumes"):
            raise Failure("%s %s declares volumes: %s" % (rid, plat, sorted(cfg["Volumes"])))
        if cfg.get("Healthcheck"):
            raise Failure("%s %s declares a health check" % (rid, plat))
        env = dict(e.split("=", 1) for e in cfg.get("Env") or [])
        key = VERSION_ENV[row["kind"]]
        if env.get(key) != next(iter(versions))[0]:
            raise Failure("%s %s: %s is %r, the executable reports %r" % (rid, plat, key, env.get(key), next(iter(versions))[0]))
        writable = scan_image(pinned[plat], plat)
        if sorted(writable) != sorted(row["covered_paths"]):
            raise Failure("%s %s: the job user could write %s, the table covers %s" % (rid, plat, writable, row["covered_paths"]))
    if len(versions) != 1:
        raise Failure("%s: the platforms report different versions: %s" % (rid, sorted(versions)))
    version, pip = versions.pop()
    findings = trivy(pinned["linux/amd64"], "linux/amd64")
    new = dict(row)
    new.update(version=version, index_digest=index, platforms=manifests, exact_tag=version + row["tag"][len(row["series"]):])
    if row["kind"] == "python":
        new["pip"] = pip
    if facts:
        refresh_facts(new, facts)
    image_changed = any(new.get(f) != row.get(f) for f in IMAGE_FIELDS)
    if image_changed:
        new["tested"] = {}
        report.append("- %s: %s (pip %s) %s -> %s" % (rid, version, pip or "-", row.get("index_digest", "")[:19], index[:19]))
    elif new != row:
        report.append("- %s: support dates refreshed (end of support %s, %s)" % (rid, new["eol"], new["support"]))
    else:
        # The findings below belong to a row too when its image stays.
        report.append("- %s: unchanged, %s (pip %s)" % (rid, version, pip or "-"))
    new["checked"] = today
    report.append("  - Trivy (HIGH, CRITICAL, fixed): %d finding(s)%s" % (len(findings), "".join("\n    - %s %s %s -> %s" % (f[0], f[1], f[2], f[3]) for f in findings[:20])))
    return new


def cmd_resolve(args):
    table = load(args.table)
    today = today_utc()
    dates = support_dates(today)
    report = ["# Runtime table update", ""]
    changed = add_new_series(table, args.only, today, report)
    for row in table["runtimes"]:
        rid = row["id"]
        if row.get("kind") == "gradle":
            continue
        if args.only and rid not in args.only:
            continue
        if "image" not in row:
            if rid in dates and dates[rid]["eol"] != row["eol"]:
                report.append("- %s: end of support %s -> %s" % (rid, row["eol"], dates[rid]["eol"]))
                row["eol"], changed = dates[rid]["eol"], True
            continue
        new = resolve_row(row, dates.get(rid), today, report)
        if {k: v for k, v in new.items() if k != "checked"} != {k: v for k, v in row.items() if k != "checked"}:
            changed = True
        row.clear()
        row.update(ordered(new))
    if cmd_resolve_gradle(table, args.only or None, today, report):
        changed = True
        table["runtimes"].sort(key=lambda r: (1, version_key(r["version"]), int(r["jdk"])) if r["kind"] == "gradle" else (0, (), 0))
    if not changed:
        print("no change")
        return 0
    save(args.table, table)
    with open(args.report, "w") as f:
        f.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


def cmd_mark_tested(args):
    table = load(args.table)
    for row in table["runtimes"]:
        if row.get("image") and row["id"] in args.only:
            row.setdefault("tested", {})[args.platform] = row["platforms"][args.platform]
    save(args.table, table)
    return 0


def cmd_scan_tar(args):
    with open(args.file, "rb") as f:
        print("\n".join(top_paths(scan_stream(f))))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--table", default=TABLE)
    r.add_argument("--report", default="runtimes-report.md")
    r.add_argument("--only", nargs="*", help="update only these runtime ids")
    r.set_defaults(fn=cmd_resolve)
    m = sub.add_parser("mark-tested")
    m.add_argument("--table", default=TABLE)
    m.add_argument("--platform", default="linux/amd64", choices=PLATFORMS)
    m.add_argument("--only", nargs="+", required=True,
                   help="the runtimes whose fixtures were run; only these are recorded")
    m.set_defaults(fn=cmd_mark_tested)
    s = sub.add_parser("scan-tar")
    s.add_argument("file")
    s.set_defaults(fn=cmd_scan_tar)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Failure as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
