"""HTTP server for case 5: importing cryptography loads its
compiled Rust extension (_rust.abi3.so) into the process, which should then
appear as an executable, file-backed mapping in /proc/<pid>/maps even though
the harness's first stage cannot match it back to the cryptography
lang-pkgs Finding by path (Trivy's PkgPath for a lang package names a
dist-info metadata file, not the mapped .so).

It also writes the ground-truth usage log every self-built test image in
this matrix writes, /var/log/usage.jsonl, one JSON object per line:

    {"ts": <RFC3339Nano>, "pid": <int>, "starttime": <int>,
     "event": "exec"|"open", "path": <absolute path>, "ok": true|false}

The "open" events are generated from /proc/self/maps snapshots — once right
after startup (so the interpreter's own already-resolved dependencies are
recorded at a known time) and then periodically for the rest of the run, so
a sampling window that starts later still finds in-window positives. A maps
snapshot is a point-in-time record of what is loaded, which is exactly what
an "open" event means here: this file was loaded at this moment.
"""

import http.server
import json
import os
import re
import socketserver
import threading
import time

import cryptography.hazmat.bindings._rust  # noqa: F401  (load the compiled extension)

PORT = 8000
LOG_PATH = "/var/log/usage.jsonl"
SNAPSHOT_INTERVAL_SECONDS = 5

# One /proc/<pid>/maps line: address perms offset dev inode [pathname].
_MAPS_LINE = re.compile(r"^\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\d+)\s+(\S.*)$")


def self_starttime() -> int:
    """Field 22 (starttime) of /proc/self/stat. The comm field is
    parenthesized and may itself contain ")", so parsing starts after the
    last ")" rather than splitting the whole line on whitespace."""
    with open("/proc/self/stat", encoding="utf-8", errors="replace") as f:
        content = f.read()
    tail = content[content.rfind(")") + 1 :].split()
    if len(tail) <= 19:
        return 0
    try:
        return int(tail[19])
    except ValueError:
        return 0


def log_event(starttime: int, event: str, path: str, ok: bool) -> None:
    # One clock reading supplies both halves of the timestamp: reading the
    # seconds and the fractional part separately can straddle a second
    # boundary and produce a stamp that never existed.
    now_ns = time.time_ns()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_ns // 1_000_000_000))
    record = {
        "ts": "%s.%09dZ" % (stamp, now_ns % 1_000_000_000),
        "pid": os.getpid(),
        "starttime": starttime,
        "event": event,
        "path": path,
        "ok": ok,
    }
    # Separators without spaces: the readers of this log match on the
    # compact form, and json.dumps' default ", "/": " spacing would make
    # every one of those searches miss.
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def mapped_files() -> list:
    """Every executable, file-backed mapping currently in /proc/self/maps,
    deduplicated — the same selection the collector makes from the outside,
    so the ground truth and the observation describe the same set."""
    out = []
    seen = set()
    with open("/proc/self/maps", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _MAPS_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            perms, _dev, inode, pathname = m.groups()
            if len(perms) < 3 or perms[2] != "x":
                continue
            if inode == "0" or not pathname.startswith("/"):
                continue
            pathname = pathname.removesuffix(" (deleted)")
            if pathname in seen:
                continue
            seen.add(pathname)
            out.append(pathname)
    return out


def snapshot(starttime: int) -> None:
    for path in mapped_files():
        log_event(starttime, "open", path, True)


def snapshot_loop(starttime: int) -> None:
    while True:
        time.sleep(SNAPSHOT_INTERVAL_SECONDS)
        snapshot(starttime)


def main() -> None:
    starttime = self_starttime()
    # Truncate rather than append: each container start is its own run, and
    # a stale log from a previous run would be ground truth for nothing.
    with open(LOG_PATH, "w", encoding="utf-8"):
        pass
    log_event(starttime, "exec", os.path.realpath("/proc/self/exe"), True)
    snapshot(starttime)
    threading.Thread(target=snapshot_loop, args=(starttime,), daemon=True).start()

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", PORT), handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
