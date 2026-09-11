"""Notify IndexNow about pages that changed since the previous deployment.

Every build writes a manifest of page content hashes into the site output.
The next build fetches the manifest published by the previous deployment,
compares the two, and submits only the added, updated, and removed URLs.

Usage:
    python scripts/docs_indexnow.py diff site \
        --previous https://kestrelynx.dev/indexnow-manifest.json \
        --output indexnow-changes.json
    python scripts/docs_indexnow.py submit indexnow-changes.json \
        --host kestrelynx.dev --key KEY [--dry-run]

Build English into site/ and Japanese into site/ja/ before running diff.
The manifest is written to site/indexnow-manifest.json and must be deployed
with the rest of the site so that the next build can fetch it.

Omit --previous to submit every page again, for example after a failed
submission: the deployed manifest already reflects that build, so the next
diff would not list those URLs a second time.
"""

import argparse
import hashlib
import json
import http.client
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

MANIFEST_NAME = "indexnow-manifest.json"
MANIFEST_VERSION = 1
SITEMAPS = ("sitemap.xml", "ja/sitemap.xml")
SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
INDEXNOW_ENDPOINT = "https://api.indexnow.org/indexnow"
TIMEOUT = 30
SUBMIT_ATTEMPTS = 3
RETRY_DELAY = 10

# Only the parts of a page that matter to search engines feed the hash, so
# navigation or footer changes shared by every page do not trigger a resend.
CONTENT_PATTERNS = (
    re.compile(r"<title>.*?</title>", re.DOTALL),
    re.compile(r'<meta name="description"[^>]*>'),
    re.compile(r"<article\b.*?</article>", re.DOTALL),
)


def page_hash(html):
    parts = []
    for pattern in CONTENT_PATTERNS:
        match = pattern.search(html)
        if match:
            parts.append(match.group(0))
    content = "\n".join(parts) if parts else html
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def build_manifest(site_dir):
    pages = {}
    for sitemap in SITEMAPS:
        locs = ET.parse(site_dir / sitemap).findall(f".//{SITEMAP_NS}loc")
        if not locs:
            raise SystemExit(f"Empty sitemap: {site_dir / sitemap}")
        for entry in locs:
            url = entry.text.strip()
            output = site_dir / urlsplit(url).path.lstrip("/")
            if output.is_dir():
                output /= "index.html"
            pages[url] = page_hash(output.read_text(encoding="utf-8"))
    return {"version": MANIFEST_VERSION, "pages": pages}


def load_previous(source):
    """Return the previous manifest, or None when every page must be resent."""
    if not source:
        return None
    try:
        if urlsplit(source).scheme in ("http", "https"):
            # Bypass CDN caches so the manifest of the latest deployment is compared.
            request = urllib.request.Request(
                f"{source}?t={int(time.time())}",
                headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
            )
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                data = json.load(response)
        else:
            path = Path(source)
            if not path.is_file():
                print(f"No previous manifest at {path}; submitting every page.")
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(f"No previous manifest at {source}; submitting every page.")
        else:
            print(f"Warning: fetching {source} failed with HTTP {error.code}; submitting every page.")
        return None
    except (OSError, http.client.HTTPException, ValueError) as error:
        print(f"Warning: reading {source} failed ({error}); submitting every page.")
        return None

    if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION or not isinstance(data.get("pages"), dict):
        print("Previous manifest has an incompatible format; submitting every page.")
        return None
    return data


def diff_manifests(previous, current):
    old_pages = previous["pages"] if previous else {}
    new_pages = current["pages"]
    return {
        "added": sorted(url for url in new_pages if url not in old_pages),
        "updated": sorted(url for url in new_pages if url in old_pages and old_pages[url] != new_pages[url]),
        "removed": sorted(url for url in old_pages if url not in new_pages),
    }


def command_diff(args):
    site_dir = Path(args.site_dir)
    current = build_manifest(site_dir)
    previous = load_previous(args.previous)
    changes = diff_manifests(previous, current)

    (site_dir / MANIFEST_NAME).write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.output).write_text(json.dumps(changes, indent=2) + "\n", encoding="utf-8")

    for kind in ("added", "updated", "removed"):
        for url in changes[kind]:
            print(f"{kind}: {url}")
    total = sum(len(urls) for urls in changes.values())
    print(f"{len(current['pages'])} pages in manifest, {total} URLs to submit.")


def command_submit(args):
    changes = json.loads(Path(args.changes).read_text(encoding="utf-8"))
    urls = sorted({url for kind in ("added", "updated", "removed") for url in changes.get(kind, [])})
    if not urls:
        print("No changed URLs; skipping IndexNow submission.")
        return
    if len(urls) > 10000:
        raise SystemExit(f"IndexNow accepts at most 10000 URLs per request, got {len(urls)}.")

    payload = {
        "host": args.host,
        "key": args.key,
        "keyLocation": f"https://{args.host}/{args.key}.txt",
        "urlList": urls,
    }
    print(f"Submitting {len(urls)} URLs to IndexNow.")
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return

    request = urllib.request.Request(
        INDEXNOW_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    for attempt in range(1, SUBMIT_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                result = f"HTTP {response.status}"
                ok = response.status in (200, 202)
        except urllib.error.HTTPError as error:
            result = f"HTTP {error.code}"
            # Client errors such as an invalid key will not succeed on retry.
            ok = False
            if 400 <= error.code < 500:
                print(f"IndexNow response: {result}")
                raise SystemExit(1)
        except (OSError, http.client.HTTPException) as error:
            result = str(error)
            ok = False
        print(f"IndexNow response (attempt {attempt}/{SUBMIT_ATTEMPTS}): {result}")
        if ok:
            return
        if attempt < SUBMIT_ATTEMPTS:
            time.sleep(RETRY_DELAY)
    raise SystemExit(1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    diff = commands.add_parser("diff", help="write the manifest and the list of changed URLs")
    diff.add_argument("site_dir", help="built site directory containing sitemap.xml and ja/sitemap.xml")
    diff.add_argument("--previous", help="URL or path of the previously deployed manifest")
    diff.add_argument("--output", required=True, help="path of the JSON file listing changed URLs")
    diff.set_defaults(func=command_diff)

    submit = commands.add_parser("submit", help="submit the changed URLs to IndexNow")
    submit.add_argument("changes", help="JSON file written by the diff command")
    submit.add_argument("--host", required=True)
    submit.add_argument("--key", required=True)
    submit.add_argument("--dry-run", action="store_true", help="print the payload instead of sending it")
    submit.set_defaults(func=command_submit)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main(sys.argv[1:] if len(sys.argv) > 1 else ["--help"])
