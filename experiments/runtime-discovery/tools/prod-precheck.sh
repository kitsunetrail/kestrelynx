#!/usr/bin/env bash
# What: read-only environment check for observing already-running production containers on
# this host: kernel/BTF/tracepoints/bpftrace-bpftool versions, cgroup2, procfs mount options,
# the sysctls and LSM state that gate unprivileged and privileged BPF use, the AppArmor status
# and this shell's own profile, the Docker daemon's version and cgroup driver, every currently
# running container's identity, free disk on the output filesystem, and a bpftrace --dry-run of
# each event-collection script prod-observe.sh can select. It writes <out dir>/precheck.json and
# precheck.md and exits non-zero when a hard requirement is missing.
#
# This script never creates, starts, stops or otherwise modifies a container, and never writes
# to a sysctl or any other kernel-tunable file: everything it reports is read, not set. It is
# deliberately not check-tracing.sh run against production — that script creates a throwaway
# container to prove tracing end-to-end, which is appropriate on a development host and not
# appropriate here.
#
# Usage (from the repository root, on the target host, as root):
#   sudo bash experiments/runtime-discovery/tools/prod-precheck.sh <out dir> [pages]
#   out dir = a directory prod-precheck.sh may create/write into (created if missing)
#   pages   = 64 | 256 | 512 | none (default: 512, matching prod-observe.sh's default) - only
#             chooses which single bpftrace script's dry-run is reported as "selected"; every
#             script prod-observe.sh could be pointed at is still dry-run and reported.
#
# Prerequisites: run as root (sudo), bpftrace installed, the native Docker Engine daemon (not
# Docker Desktop) reachable at /var/run/docker.sock. bpftool is checked but not required: its
# absence is recorded, not a hard failure, since nothing here depends on it succeeding.
set -uo pipefail
cd "$(dirname "$0")/../../.."
E=experiments/runtime-events

USAGE="Usage: sudo bash experiments/runtime-discovery/tools/prod-precheck.sh <out dir> [64|256|512|none]"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
OUT="$1"; PAGES="${2:-512}"
case "$PAGES" in 64|256|512|none) ;; *) echo "pages must be 64, 256, 512 or none" >&2; exit 2;; esac
[ "$(id -u)" = 0 ] || { echo "prod-precheck: must run as root (sudo)" >&2; exit 2; }

RAW="$OUT/raw"; mkdir -p "$RAW" || { echo "prod-precheck: cannot create $OUT" >&2; exit 2; }
log(){ echo "$(date -u +%FT%T.%NZ) $*"; }

log "## versions and kernel"
uname -srvm > "$RAW/uname.txt" 2>&1
{ command -v bpftrace >/dev/null && bpftrace --version || echo "bpftrace: not installed"; } > "$RAW/bpftrace-version.txt" 2>&1
{ command -v bpftool >/dev/null && bpftool version || echo "bpftool: not installed"; } > "$RAW/bpftool-version.txt" 2>&1

log "## BTF"
if [ -s /sys/kernel/btf/vmlinux ]; then
  { echo "present"; stat -c '%s bytes' /sys/kernel/btf/vmlinux; } > "$RAW/btf.txt" 2>&1
else
  echo "absent" > "$RAW/btf.txt"
fi

log "## tracepoints"
# The bpftrace scripts prod-observe.sh can select (runtime-events-nofilter{,-256p,-512p}.bt)
# attach to sys_enter_open/openat/openat2 (and their sys_exit_* counterparts, to pair
# entry/exit for the path argument) and sched:sched_process_exec — not sys_enter_execve, which
# is checked here too only so a reader can see it was considered and found unused.
TP_DIR=/sys/kernel/tracing/events
[ -d "$TP_DIR" ] || TP_DIR=/sys/kernel/debug/tracing/events
: > "$RAW/tracepoints.txt"
check_tp(){ # group name required(0|1)
  local group="$1" name="$2" required="$3" present=false
  [ -d "$TP_DIR/$group/$name" ] && present=true
  echo "$group:$name present=$present required=$required" >> "$RAW/tracepoints.txt"
}
check_tp syscalls sys_enter_open 1
check_tp syscalls sys_exit_open 1
check_tp syscalls sys_enter_openat 1
check_tp syscalls sys_exit_openat 1
check_tp syscalls sys_enter_openat2 1
check_tp syscalls sys_exit_openat2 1
check_tp sched sched_process_exec 1
check_tp syscalls sys_enter_execve 0

log "## cgroup2"
{ stat -f -c '%T' /sys/fs/cgroup 2>&1; mount | grep ' /sys/fs/cgroup ' || true; } > "$RAW/cgroup2.txt"

log "## procfs mount options"
{ findmnt -no OPTIONS /proc 2>/dev/null || mount | grep ' /proc '; } > "$RAW/procfs.txt"

log "## sysctls"
: > "$RAW/sysctls.txt"
for f in kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid kernel/yama/ptrace_scope; do
  path="/proc/sys/$f"
  if [ -r "$path" ]; then echo "$f=$(cat "$path")" >> "$RAW/sysctls.txt"
  else echo "$f=unavailable" >> "$RAW/sysctls.txt"; fi
done

log "## lockdown"
if [ -r /sys/kernel/security/lockdown ]; then cat /sys/kernel/security/lockdown > "$RAW/lockdown.txt"
else echo "unavailable" > "$RAW/lockdown.txt"; fi

log "## AppArmor"
{
  if [ -r /sys/module/apparmor/parameters/enabled ]; then echo "module_enabled=$(cat /sys/module/apparmor/parameters/enabled)"
  else echo "module_enabled=unavailable"; fi
  if command -v aa-status >/dev/null 2>&1; then aa-status --enabled 2>&1; echo "aa-status_exit=$?"
  else echo "aa-status=not installed"; fi
  if [ -r /proc/self/attr/current ]; then echo "this_shell_profile=$(cat /proc/self/attr/current)"
  else echo "this_shell_profile=unavailable"; fi
} > "$RAW/apparmor.txt" 2>&1

log "## docker"
{
  echo "server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
  echo "operating_system=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)"
  echo "cgroup_driver=$(docker info --format '{{.CgroupDriver}}' 2>/dev/null)"
  echo "cgroup_version=$(docker info --format '{{.CgroupVersion}}' 2>/dev/null)"
} > "$RAW/docker.txt" 2>&1
# A reachable check independent of the fields above: an empty OperatingSystem means the
# daemon could not be reached at all (socket absent, permission denied, wrong context).
DAEMON_OS=$(grep '^operating_system=' "$RAW/docker.txt" | cut -d= -f2-)

log "## running containers (read-only: docker ps + docker inspect, nothing started or stopped)"
if [ -n "$DAEMON_OS" ]; then
  IDS=$(docker ps -q)
  if [ -n "$IDS" ]; then docker inspect $IDS > "$RAW/containers_inspect.json" 2>"$RAW/containers_inspect.err"
  else echo "[]" > "$RAW/containers_inspect.json"; fi
else
  echo "[]" > "$RAW/containers_inspect.json"
fi

log "## free disk on the output filesystem"
df --output=avail -B1 "$OUT" 2>/dev/null | tail -n1 | tr -d ' ' > "$RAW/free_bytes.txt"

log "## bpftrace --dry-run of every script prod-observe.sh could select"
declare -A SCRIPTS=([64]="$E/bpftrace/runtime-events-nofilter.bt" [256]="$E/bpftrace/runtime-events-nofilter-256p.bt" [512]="$E/bpftrace/runtime-events-nofilter-512p.bt")
: > "$RAW/dryrun_summary.txt"
if command -v bpftrace >/dev/null 2>&1; then
  for p in 64 256 512; do
    f="${SCRIPTS[$p]}"
    out="$RAW/dryrun-$p.txt"
    if env -u BPFTRACE_MAX_STRLEN -u BPFTRACE_PERF_RB_PAGES -u BPFTRACE_ON_STACK_LIMIT bpftrace -v --dry-run "$f" > "$out" 2>&1; then
      echo "$p ok" >> "$RAW/dryrun_summary.txt"
    else
      echo "$p failed: $(grep -m1 -i error "$out")" >> "$RAW/dryrun_summary.txt"
    fi
  done
else
  echo "bpftrace not installed: no dry-run performed" >> "$RAW/dryrun_summary.txt"
fi

log "## assembling precheck.json / precheck.md"
python3 - "$OUT" "$PAGES" <<'PY'
import json, re, sys, os, datetime

out, pages = sys.argv[1], sys.argv[2]
raw = os.path.join(out, "raw")

def read(name):
    p = os.path.join(raw, name)
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return ""

hard_failures = []

kernel = read("uname.txt").strip()

btf_text = read("btf.txt")
btf_present = btf_text.startswith("present")
if not btf_present:
    hard_failures.append("BTF is not present at /sys/kernel/btf/vmlinux")

tracepoints = {}
for line in read("tracepoints.txt").splitlines():
    m = re.match(r"([\w.]+):(\w+) present=(True|False|true|false) required=([01])", line)
    if not m:
        continue
    key = f"{m.group(1)}:{m.group(2)}"
    present = m.group(3).lower() == "true"
    required = m.group(4) == "1"
    tracepoints[key] = {"present": present, "required": required}
    if required and not present:
        hard_failures.append(f"required tracepoint {key} is not present")

cgroup2_text = read("cgroup2.txt")
cgroup2_ok = cgroup2_text.splitlines()[0].strip() == "cgroup2fs" if cgroup2_text.splitlines() else False
if not cgroup2_ok:
    hard_failures.append("/sys/fs/cgroup is not a cgroup2 (unified) mount")

docker_fields = {}
for line in read("docker.txt").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        docker_fields[k] = v
docker_reachable = bool(docker_fields.get("operating_system"))
if not docker_reachable:
    hard_failures.append("the Docker daemon could not be reached (docker info returned no OperatingSystem)")
elif "desktop" in docker_fields.get("operating_system", "").lower():
    hard_failures.append(f"the Docker socket belongs to Docker Desktop ({docker_fields['operating_system']}); production observation needs the native daemon")

bpftrace_version = read("bpftrace-version.txt").strip()
bpftrace_installed = "not installed" not in bpftrace_version
if not bpftrace_installed and pages != "none":
    hard_failures.append("bpftrace is not installed, and pages != none was requested")

sysctls = {}
for line in read("sysctls.txt").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        sysctls[k] = v

apparmor = {}
for line in read("apparmor.txt").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        apparmor.setdefault(k, v)

try:
    containers_raw = json.loads(read("containers_inspect.json") or "[]")
except json.JSONDecodeError:
    containers_raw = []
containers = []
for c in containers_raw:
    containers.append({
        "name": (c.get("Name") or "").lstrip("/"),
        "id": c.get("Id", ""),
        "image_id": c.get("Image", ""),
        "started_at": (c.get("State") or {}).get("StartedAt", ""),
    })

free_bytes_text = read("free_bytes.txt").strip()
free_bytes = int(free_bytes_text) if free_bytes_text.isdigit() else None

dryrun = {}
for line in read("dryrun_summary.txt").splitlines():
    parts = line.split(" ", 1)
    if len(parts) == 2 and parts[0] in ("64", "256", "512"):
        dryrun[parts[0] + "p"] = parts[1]
    elif line:
        dryrun["_note"] = line

# The dry-run of every script prod-observe.sh could select is informational
# on its own (a page size this run will never use failing its dry-run is
# not this run's problem), but the SELECTED page size's own dry-run is a
# hard requirement whenever events will actually be collected: a script
# that cannot even be parsed and loaded is not going to attach for real
# either, and reporting ok=true here would send an operator past this
# check into a run that cannot work.
if pages != "none":
    selected_result = dryrun.get(pages + "p")
    if selected_result is None:
        hard_failures.append(f"the selected script ({pages} pages) was never dry-run (bpftrace missing, or the dry-run step did not reach it)")
    elif not selected_result.startswith("ok"):
        hard_failures.append(f"the selected script ({pages} pages) failed its dry-run: {selected_result}")

report = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "selected_pages": pages,
    "kernel": kernel,
    "btf": {"present": btf_present, "detail": btf_text.strip()},
    "tracepoints": tracepoints,
    "bpftrace_version": bpftrace_version,
    "bpftool_version": read("bpftool-version.txt").strip(),
    "cgroup2": {"ok": cgroup2_ok, "detail": cgroup2_text.strip()},
    "procfs_mount_options": read("procfs.txt").strip(),
    "sysctls": sysctls,
    "lockdown": read("lockdown.txt").strip(),
    "apparmor": apparmor,
    "docker": docker_fields,
    "running_containers": containers,
    "free_bytes_on_output_filesystem": free_bytes,
    "dry_run": dryrun,
    "hard_failures": hard_failures,
    "ok": len(hard_failures) == 0,
}

with open(os.path.join(out, "precheck.json"), "w") as f:
    json.dump(report, f, indent=2, sort_keys=False)
    f.write("\n")

lines = []
lines.append("# Production environment precheck")
lines.append("")
lines.append(f"- generated_at: {report['generated_at']}")
lines.append(f"- kernel: {kernel}")
lines.append(f"- selected pages: {pages}")
lines.append(f"- overall: {'OK' if report['ok'] else 'FAILED'}")
if hard_failures:
    lines.append("")
    lines.append("## Hard failures")
    for h in hard_failures:
        lines.append(f"- {h}")
lines.append("")
lines.append("## BTF")
lines.append(f"- present: {btf_present}")
lines.append("")
lines.append("## Tracepoints")
for k, v in sorted(tracepoints.items()):
    lines.append(f"- {k}: present={v['present']} required={v['required']}")
lines.append("")
lines.append("## bpftrace / bpftool")
lines.append(f"- bpftrace: {bpftrace_version}")
lines.append(f"- bpftool: {report['bpftool_version']}")
lines.append("")
lines.append("## cgroup2")
lines.append(f"- ok: {cgroup2_ok}")
lines.append(f"- detail: {cgroup2_text.strip()}")
lines.append("")
lines.append("## procfs mount options")
lines.append(f"- {report['procfs_mount_options']}")
lines.append("")
lines.append("## sysctls")
for k, v in sysctls.items():
    lines.append(f"- {k} = {v}")
lines.append("")
lines.append(f"## lockdown: {report['lockdown']}")
lines.append("")
lines.append("## AppArmor")
for k, v in apparmor.items():
    lines.append(f"- {k} = {v}")
lines.append("")
lines.append("## Docker")
for k, v in docker_fields.items():
    lines.append(f"- {k} = {v}")
lines.append("")
lines.append(f"## Running containers ({len(containers)})")
for c in containers:
    lines.append(f"- {c['name']} id={c['id'][:12]} image_id={c['image_id']} started_at={c['started_at']}")
lines.append("")
lines.append(f"## Free disk on output filesystem: {free_bytes if free_bytes is not None else 'unknown'} bytes")
lines.append("")
lines.append("## bpftrace dry-run")
for k, v in dryrun.items():
    lines.append(f"- {k}: {v}")

with open(os.path.join(out, "precheck.md"), "w") as f:
    f.write("\n".join(lines) + "\n")

sys.exit(0 if report["ok"] else 1)
PY
RC=$?
if [ "$RC" = 0 ]; then log "## precheck OK -> $OUT/precheck.json, $OUT/precheck.md"
else log "## precheck FAILED (see $OUT/precheck.json hard_failures) -> exit $RC"; fi
exit "$RC"
