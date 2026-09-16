"""Imports a package that carries a compiled extension, on a signal, and
records each import individually.

Two logs are written, and they answer different questions.

  /var/log/usage.jsonl records, in the shared format, that a file was
  loaded at a moment in time. Its "open" records are taken from this
  process's own list of mapped files, which is a point-in-time statement of
  what is loaded — not a record of file-open calls, and it is not used as
  one.

  /var/log/occurrences.jsonl records each individual import with an
  identifier of its own: the span it covered, whether it succeeded,
  whether it read any file at all, and which files it resolved. The
  "read any file at all" field is the important one. An import of something
  already in memory succeeds without reading anything, so counting it would
  record a missing observation for a file read that never happened. This
  program imports the same package twice on purpose, so both cases appear.

The import is deliberately deferred to the moment the signal arrives.
Importing at startup would put the whole thing before the observation is in
place, where a collector that works perfectly would still see nothing.
"""

import http.server
import importlib
import json
import os
import re
import socketserver
import sys
import threading
import time

PORT = 8000
USAGE_LOG = "/var/log/usage.jsonl"
OCCURRENCE_LOG = "/var/log/occurrences.jsonl"
FIRE_DIR = os.environ.get("FIRE_DIR", "/run/fire")
CASE_ID = os.environ.get("CASE_ID", "15")
TARGET_MODULE = os.environ.get("TARGET_MODULE", "cryptography.hazmat.bindings._rust")
SNAPSHOT_INTERVAL_SECONDS = 5

# One mapped-file line: address perms offset device inode [path].
_MAPS_LINE = re.compile(r"^\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\d+)\s+(\S.*)$")

_container_id = ""


def self_starttime() -> int:
    """Field 22 of this process's status line. Field 2 is parenthesized and
    may itself contain ")", so parsing starts after the last one."""
    with open("/proc/self/stat", encoding="utf-8", errors="replace") as f:
        content = f.read()
    tail = content[content.rfind(")") + 1 :].split()
    if len(tail) <= 19:
        return 0
    try:
        return int(tail[19])
    except ValueError:
        return 0


def stamp() -> str:
    # One clock reading supplies both halves: reading the seconds and the
    # fraction separately can straddle a second boundary and produce a
    # timestamp that never existed.
    now_ns = time.time_ns()
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_ns // 1_000_000_000))
    return "%s.%09dZ" % (base, now_ns % 1_000_000_000)


def append(path: str, record: dict) -> None:
    # Compact separators: the readers of these logs match on the compact
    # form, and the default spacing would make every one of those searches
    # miss.
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def log_usage(starttime: int, event: str, path: str, ok: bool) -> None:
    append(USAGE_LOG, {
        "ts": stamp(), "pid": os.getpid(), "starttime": starttime,
        "event": event, "path": path, "ok": ok,
    })


_occurrence_seq = 0


def log_import_occurrence(starttime: int, start: str, end: str, ok: bool,
                          cache_hit: bool, files: list) -> None:
    global _occurrence_seq
    _occurrence_seq += 1
    append(OCCURRENCE_LOG, {
        "id": "%s-load-%06d" % (CASE_ID, _occurrence_seq),
        "kind": "load",
        "pid": os.getpid(),
        "tid": threading.get_native_id(),
        "starttime": starttime,
        "start": start, "end": end,
        "ok": ok, "cache_hit": cache_hit,
        "files": files,
        "container_id": _container_id,
    })


def mapped_files() -> list:
    """Every executable, file-backed mapping currently in this process,
    deduplicated — the same selection a collector makes from the outside,
    so the two describe the same set."""
    out, seen = [], set()
    with open("/proc/self/maps", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _MAPS_LINE.match(line.rstrip("\n"))
            if not m:
                continue
            perms, _dev, inode, path = m.groups()
            if len(perms) < 3 or perms[2] != "x":
                continue
            if inode == "0" or not path.startswith("/"):
                continue
            path = path.removesuffix(" (deleted)")
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def snapshot(starttime: int) -> None:
    for path in mapped_files():
        log_usage(starttime, "open", path, True)


def snapshot_loop(starttime: int) -> None:
    while True:
        time.sleep(SNAPSHOT_INTERVAL_SECONDS)
        snapshot(starttime)


def module_files(before: set) -> list:
    """The files behind every module that appeared during an import. A
    module already present before it started contributed no file read, and
    is not in this list."""
    files = []
    for name, module in list(sys.modules.items()):
        if name in before or module is None:
            continue
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not origin:
            origin = getattr(module, "__file__", None)
        if origin and origin.startswith("/"):
            files.append(origin)
    return sorted(set(files))


def do_import(starttime: int, module_name: str) -> None:
    """Imports a module and records exactly what that import did.

    Whether the import read anything is decided by whether any module
    appeared that was not there before, not by whether the import
    succeeded: the second is true of a cached import too."""
    before = set(sys.modules)
    cached = module_name in before
    start = stamp()
    ok = True
    try:
        importlib.import_module(module_name)
    except Exception:  # noqa: BLE001 - a failed import is a recorded outcome
        ok = False
    end = stamp()
    files = module_files(before)
    log_import_occurrence(starttime, start, end, ok, cached or not files, files)
    for path in files:
        log_usage(starttime, "open", path, ok)


def wait_for_signal() -> None:
    """Blocks on a pipe until something is written to it. A blocking read
    runs nothing while it waits, so the wait adds nothing to what is being
    counted."""
    fifo = os.path.join(FIRE_DIR, "fire")
    if not os.path.exists(fifo):
        return
    with open(fifo, encoding="utf-8") as f:
        f.readline()


def read_container_id() -> str:
    path = os.path.join(FIRE_DIR, "container-id")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def main() -> None:
    global _container_id
    starttime = self_starttime()
    # Each container start is its own run; a log left by a previous one
    # would be ground truth for nothing.
    for path in (USAGE_LOG, OCCURRENCE_LOG):
        with open(path, "w", encoding="utf-8"):
            pass
    log_usage(starttime, "exec", os.path.realpath("/proc/self/exe"), True)

    wait_for_signal()
    _container_id = read_container_id()
    log_usage(starttime, "stage", "fired", True)

    # The first import reads the files; the second finds the module
    # already in memory and reads nothing. Both are recorded, and only the
    # first belongs in a denominator of expected file reads.
    do_import(starttime, TARGET_MODULE)
    do_import(starttime, TARGET_MODULE)

    snapshot(starttime)
    threading.Thread(target=snapshot_loop, args=(starttime,), daemon=True).start()

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", PORT), handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
