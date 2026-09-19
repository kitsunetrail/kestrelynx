"""Coverage-validation case 26: a small Flask web application bundling
about 28 pip distributions across three declared groups — used_at_startup,
used_lazily, and unused (see the case definition's coverage_plan) — run as
a workload for measuring how much of a package inventory this harness's
sampling, added mapping, and event evidence can independently confirm.

Four logs are written, and they answer different questions.

  /var/log/usage.jsonl records, in the shared format, that a file was
  loaded. Its "open" records come from a before/after diff of this
  process's own sys.modules, taken around each block of startup or lazy
  code — not a record of file-open calls, and it is not used as one.

  /var/log/occurrences.jsonl records each individual import block with an
  identifier of its own, mirroring case 15's per-import occurrences.

  /var/log/operations.jsonl records each step of the firing procedure
  itself (the requests this program issues against its own server, and
  nothing about the packages those requests load) with an identifier and a
  timestamp, so an independently obtained ground-truth run started from
  the same image can be checked against the same operation sequence.

  /var/log/runtime-modules.jsonl is this runtime's own introspection: one
  record per sys.modules entry, naming the file it was loaded from (or its
  import spec's origin, when the module carries no __file__ at all). It is
  written at the startup, after-lazy, and periodic checkpoints below, and
  is the ground-truth tool's own independent source — never read by this
  harness's ordinary sampling or event collection.

The used_lazily group is deliberately not imported until this program
calls its own /lazy/* routes after firing: importing at module load would
put the whole thing before the observation is in place, where a collector
that works perfectly would still see nothing.
"""

import importlib
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.request

# Imported at module load, before the firing signal: this is the
# used_at_startup group. Flask itself pulls in werkzeug, jinja2,
# markupsafe, itsdangerous, click, and blinker.
import flask
import certifi  # noqa: F401 - imported for its own sake, not through flask

USAGE_LOG = "/var/log/usage.jsonl"
OCCURRENCE_LOG = "/var/log/occurrences.jsonl"
OPERATIONS_LOG = "/var/log/operations.jsonl"
RUNTIME_MODULES_LOG = "/var/log/runtime-modules.jsonl"
FIRE_DIR = os.environ.get("FIRE_DIR", "/run/fire")
CASE_ID = os.environ.get("CASE_ID", "26")
PORT = 8000
PERIODIC_DUMP_SECONDS = 30

LAZY_MODULES = {
    "requests": "requests",
    "sqlalchemy": "sqlalchemy",
    "cryptography": "cryptography.fernet",
    "yaml": "yaml",
}

_container_id = ""
_occurrence_seq = 0
_operation_seq = 0


def self_starttime() -> int:
    with open("/proc/self/stat", encoding="utf-8", errors="replace") as f:
        content = f.read()
    tail = content[content.rfind(")") + 1 :].split()
    if len(tail) <= 19:
        return 0
    try:
        return int(tail[19])
    except ValueError:
        return 0


_STARTTIME = 0


def stamp() -> str:
    now_ns = time.time_ns()
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_ns // 1_000_000_000))
    return "%s.%09dZ" % (base, now_ns % 1_000_000_000)


def append(path: str, record: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def log_usage(event: str, path: str, ok: bool) -> None:
    append(USAGE_LOG, {
        "ts": stamp(), "pid": os.getpid(), "starttime": _STARTTIME,
        "event": event, "path": path, "ok": ok,
    })


def log_operation(op: str, ok: bool, detail: str = "") -> None:
    global _operation_seq
    _operation_seq += 1
    record = {
        "id": "%s-op-%06d" % (CASE_ID, _operation_seq),
        "ts": stamp(), "op": op, "ok": ok,
    }
    if detail:
        record["detail"] = detail
    append(OPERATIONS_LOG, record)


def module_files(before: set) -> list:
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


def run_import_block(label: str, action) -> None:
    """Runs one block of import-triggering code and records exactly what
    it did, the same way case 15's do_import records one import: whether
    anything was read is decided by which modules appeared in sys.modules,
    not by whether the call succeeded."""
    global _occurrence_seq
    before = set(sys.modules)
    start = stamp()
    ok = True
    try:
        action()
    except Exception:  # noqa: BLE001 - a failed block is a recorded outcome
        ok = False
    end = stamp()
    files = module_files(before)
    _occurrence_seq += 1
    append(OCCURRENCE_LOG, {
        "id": "%s-load-%06d" % (CASE_ID, _occurrence_seq),
        "kind": "load", "pid": os.getpid(), "tid": threading.get_native_id(),
        "starttime": _STARTTIME, "start": start, "end": end,
        "ok": ok, "cache_hit": not files, "files": files,
        "container_id": _container_id,
    })
    for path in files:
        log_usage("open", path, ok)
    log_operation(label, ok)


def startup_use() -> None:
    """Exercises the used_at_startup group beyond the bare import: a
    template render actually invokes jinja2's compiler and markupsafe's
    escaping, rather than leaving them merely imported."""
    with flask.Flask(__name__).app_context():
        flask.render_template_string("hello {{ name }}", name="case26")


def lazy_requests() -> None:
    import requests
    requests.get("http://127.0.0.1:%d/health" % PORT, timeout=5)


def lazy_sqlalchemy() -> None:
    import sqlalchemy
    engine = sqlalchemy.create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(sqlalchemy.text("SELECT 1"))


def lazy_cryptography() -> None:
    from cryptography.fernet import Fernet
    Fernet(Fernet.generate_key()).encrypt(b"case26")


def lazy_yaml() -> None:
    import yaml
    yaml.safe_load("case: 26\n")


app = flask.Flask("case26")


@app.route("/health")
def health():
    return "ok\n"


@app.route("/lazy/<name>")
def lazy(name):
    actions = {
        "requests": lazy_requests, "sqlalchemy": lazy_sqlalchemy,
        "cryptography": lazy_cryptography, "yaml": lazy_yaml,
    }
    action = actions.get(name)
    if action is None:
        flask.abort(404)
    run_import_block("request_lazy_%s" % name, action)
    return "ok %s\n" % name


def dump_runtime_modules(phase: str) -> None:
    ts = stamp()
    for name, module in sorted(sys.modules.items()):
        if module is None:
            continue
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None) if spec is not None else None
        file_ = getattr(module, "__file__", None)
        record = {"ts": ts, "phase": phase, "runtime": "python", "module": name}
        resolved = file_ or origin
        if resolved and str(resolved).startswith("/"):
            record["file"] = resolved
            record["resolved"] = True
        else:
            # Two more shapes never have a single resolvable file either,
            # the same "no possible file" state "built-in" names for an
            # interpreter-compiled module, just reached differently: a
            # module with no __spec__ at all (never created through
            # Python's own import machinery - most commonly a native
            # extension's own C-level module init), and a namespace
            # package (PEP 420 - a spec with submodule_search_locations
            # but no origin at all, by definition spread across
            # directories rather than backed by one file). Both are
            # recorded under the identical label rather than a bare
            # empty string that would read as an unexplained gap.
            is_namespace_package = spec is not None and getattr(spec, "submodule_search_locations", None) is not None
            if spec is None or is_namespace_package:
                record["origin"] = "built-in"
            else:
                record["origin"] = origin or ""
            record["resolved"] = False
        append(RUNTIME_MODULES_LOG, record)


def periodic_dump_loop() -> None:
    while True:
        time.sleep(PERIODIC_DUMP_SECONDS)
        dump_runtime_modules("periodic")


def final_dump(signum, frame):  # noqa: ARG001 - signal handler signature
    dump_runtime_modules("final")
    sys.exit(0)


def wait_for_signal() -> None:
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


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)


def main() -> None:
    global _container_id, _STARTTIME
    _STARTTIME = self_starttime()
    for path in (USAGE_LOG, OCCURRENCE_LOG, OPERATIONS_LOG, RUNTIME_MODULES_LOG):
        with open(path, "w", encoding="utf-8"):
            pass
    log_usage("exec", os.path.realpath("/proc/self/exe"), True)
    dump_runtime_modules("startup")

    signal.signal(signal.SIGTERM, final_dump)

    wait_for_signal()
    _container_id = read_container_id()
    log_usage("stage", "fired", True)
    log_operation("fired", True)

    run_import_block("render_startup_template", startup_use)

    server_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True),
        daemon=True,
    )
    server_thread.start()
    wait_for_port(PORT)

    for name in ("requests", "sqlalchemy", "cryptography", "yaml"):
        urllib.request.urlopen("http://127.0.0.1:%d/lazy/%s" % (PORT, name), timeout=5).read()

    dump_runtime_modules("after_lazy")
    threading.Thread(target=periodic_dump_loop, daemon=True).start()

    server_thread.join()


if __name__ == "__main__":
    main()
