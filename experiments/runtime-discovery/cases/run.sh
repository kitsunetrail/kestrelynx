#!/usr/bin/env bash
# Starts and stops the 1-12 test-matrix containers for the runtime
# discovery measurement harness, waits for each case's own readiness
# condition, and runs the 8/10 pre-sampling checks their case definitions
# require. Every startup command and readiness check is taken from the test
# matrix that specifies this harness; this script exists only to save
# re-typing them, not to decide what they should be.
#
# Usage:
#   run.sh up <case>       # e.g. run.sh up 1 (builds first if the case needs a local image)
#   run.sh down <case>
#   run.sh up-all
#   run.sh down-all
#   run.sh preflight-8     # confirm deleted exe/maps entries are actually visible
#   run.sh preflight-10    # confirm the dlopen/dlclose mapping actually disappears while unloaded
#   run.sh fixture-check <case>
#   run.sh ready-run-id <ready file> [timeout] [collector start]  # print the current run's identifier
#   run.sh wait-ready <ready file> <run id> [timeout]  # block until that run has accepted every registered target
#   run.sh register-cgroups <table>  # refresh the control group table, after the container starts and before firing
#   run.sh attach-check <trace>      # confirm the tracer's probes are live by causing a known event
#   run.sh fire <case>     # tell a waiting container to start working
#   run.sh dump-logs <case> <directory>       # copy a container's own logs out of it
#   run.sh host-run <log> [iterations] [interval]  # run the same program on the host, for the attribution control
#
# 5/6/7a/7b/8/9/10 build a local image first; the rest run an upstream
# image directly. Containers are named case<number> (case1, case7a, ...)
# so `collect -containers` and match's inputs can find them.
#
# Every readiness check, fixture check and preflight check exits non-zero
# when it fails. A failed check must stop a run rather than print a warning
# into a log nobody reads before the measurement starts.
#
# The fixture and preflight checks read the host's own procfs
# (/proc/<host pid>/...) through the PIDs Docker reports, rather than
# running commands inside the containers. Three reasons: distroless images
# have no shell to run anything in; `docker exec` adds a process to the
# container and changes the very PID set the collector is measuring; and a
# check that went through the collector's own path could not tell a broken
# fixture from a collector that misreads a working one. This means the
# checks need the same privileges the collector does — run them as root, or
# with CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# container_main_pid prints the host PID of a container's main process.
container_main_pid() {
	local pid
	pid="$(docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null || true)"
	if [ -z "$pid" ] || [ "$pid" = "0" ]; then
		echo "no host PID for container $1 (is it running?)" >&2
		return 1
	fi
	echo "$pid"
}

# container_pids prints every host PID Docker attributes to a container.
container_pids() {
	docker top "$1" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' | grep -E '^[0-9]+$' || true
}

# effective_uid prints the effective UID (field 2 of the Uid: line) of a
# host PID, as the kernel presents it to this reader.
effective_uid() {
	awk '/^Uid:/{print $3; exit}' "/proc/$1/status" 2>/dev/null
}

# container_usage_log prints the host path of a container's usage log,
# reached through its own root filesystem view.
container_usage_log() {
	local pid
	pid="$(container_main_pid "$1")" || return 1
	echo "/proc/$pid/root/var/log/usage.jsonl"
}

wait_http_200() {
	# wait_http_200 <url> <timeout_seconds>
	local url="$1" timeout="${2:-30}" waited=0
	while [ "$waited" -lt "$timeout" ]; do
		if [ "$(curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)" = "200" ]; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: $url never returned 200 within ${timeout}s" >&2
	return 1
}

wait_log_contains() {
	# wait_log_contains <container> <pattern> <timeout_seconds>
	local container="$1" pattern="$2" timeout="${3:-30}" waited=0
	while [ "$waited" -lt "$timeout" ]; do
		if docker logs "$container" 2>&1 | grep -q "$pattern"; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: $container logs never matched '$pattern' within ${timeout}s" >&2
	return 1
}

# python3 is used to read the usage logs as JSON where it is available.
# The fallback is a whitespace-tolerant regular expression, so a host
# without python3 still reads the logs correctly rather than matching one
# particular JSON writer's spacing.
PY3="$(command -v python3 2>/dev/null || true)"

# count_usage_events <log> <event name>
# Counts the records whose "event" field equals the given name.
count_usage_events() {
	local log="$1" event="$2"
	if [ ! -r "$log" ]; then
		echo 0
		return 0
	fi
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import json, sys
path, want = sys.argv[1], sys.argv[2]
n = 0
with open(path, encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("event") == want:
            n += 1
print(n)
' "$log" "$event"
	else
		grep -cE "\"event\"[[:space:]]*:[[:space:]]*\"$event\"" "$log" 2>/dev/null || true
	fi
}

# count_verified_unloads <log>
# Counts the dlclose records whose own post-dlclose maps read confirmed the
# mapping was gone — case 10's definition of a non-loaded period.
count_verified_unloads() {
	local log="$1"
	if [ ! -r "$log" ]; then
		echo 0
		return 0
	fi
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import json, sys
n = 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("event") == "dlclose" and record.get("maps_unloaded") is True:
            n += 1
print(n)
' "$log"
	else
		grep -cE '"maps_unloaded"[[:space:]]*:[[:space:]]*true' "$log" 2>/dev/null || true
	fi
}

wait_usage_events() {
	# wait_usage_events <container> <event name> <min_count> <timeout_seconds> <description>
	local container="$1" event="$2" min="$3" timeout="${4:-30}" what="$5" waited=0 log n
	while [ "$waited" -lt "$timeout" ]; do
		log="$(container_usage_log "$container" 2>/dev/null || true)"
		if [ -n "$log" ]; then
			n="$(count_usage_events "$log" "$event")"
			if [ "${n:-0}" -ge "$min" ]; then
				return 0
			fi
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: $container did not record $min $what within ${timeout}s" >&2
	return 1
}

wait_verified_unloads() {
	# wait_verified_unloads <container> <min_count> <timeout_seconds>
	local container="$1" min="$2" timeout="${3:-60}" waited=0 log n
	while [ "$waited" -lt "$timeout" ]; do
		log="$(container_usage_log "$container" 2>/dev/null || true)"
		if [ -n "$log" ]; then
			n="$(count_verified_unloads "$log")"
			if [ "${n:-0}" -ge "$min" ]; then
				return 0
			fi
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: $container did not record $min verified unloaded phase(s) within ${timeout}s" >&2
	return 1
}

# ---------------------------------------------------------------------------
# The V-series cases start their work on a signal rather than at startup.
#
# The reason is structural: a module loaded once when a program starts is
# loaded before an observation started afterwards can see it, and a
# collector that works perfectly would still report nothing. So the
# container is started with its program waiting, the observation is given
# time to take hold, and only then is the program told to begin.
#
# The signal is a named pipe in a directory shared with the container. A
# blocking read on it runs nothing while it waits, which matters because
# these cases count executions: a polling loop in a shell would run an
# external command on every turn and every one of those would be counted.
# Adding a process to the container to signal it would do the same, and
# would also change the very set of processes being measured.
#
# The same directory carries the container's own identifier, written after
# the container starts and before it is fired, so the container's logs can
# say which container their contents belong to.
FIRE_ROOT="${FIRE_ROOT:-$here/../out/fire}"

fire_dir() { echo "$FIRE_ROOT/$1"; }

# prepare_fire creates the signalling directory and its pipe. It is created
# before the container starts, because the container's first act is to open
# the pipe.
prepare_fire() {
	local dir
	dir="$(fire_dir "$1")"
	rm -rf "$dir"
	mkdir -p "$dir"
	mkfifo "$dir/fire"
	chmod 0777 "$dir" "$dir/fire"
	echo "$dir"
}

# record_container_id writes the started container's identifier where the
# container itself can read it, so its own logs can name it. A container
# cannot learn its full identifier any other way, and the short name it
# does have would not compare against the identifier an observation
# reports.
record_container_id() {
	local dir
	dir="$(fire_dir "$1")"
	docker inspect -f '{{.Id}}' "$1" >"$dir/container-id"
	chmod 0644 "$dir/container-id"
}

# fire_case tells a waiting container to start. Everything the observation
# needs must already be in place: a run fired before the collector accepted
# the target is not a measurement of the collector, and is recorded as
# invalid rather than kept.
fire_case() {
	local dir
	dir="$(fire_dir "case$1")"
	if [ ! -p "$dir/fire" ]; then
		echo "fire: no signalling pipe for $1 (was it started with run.sh up?)" >&2
		return 1
	fi
	printf 'go\n' >"$dir/fire"
	echo "fired $1 at $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
}

# wait_ready blocks until the collector's readiness file says every target
# it was told to expect has been accepted. This is the condition the firing
# signal waits on; without it the ordering the V-series cases depend on is
# a race.
#
# A file left behind by an earlier run of the same case would report ready
# the moment it is read, and the workload would begin with no observation
# in place at all. The run identifier is therefore required, not inferred:
# guessing it from whatever the file said when the wait began treats the
# current run's own file as a leftover whenever the collector got there
# first, and waits out the timeout for a run that is already ready.
#
# The identifier comes from the collector's own output. Read it from the
# readiness file once the collector has written one, and pass it here:
#
#   started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"   # before the collector starts
#   run_id="$(run.sh ready-run-id ./out/collect/ready.json 60 "$started")"
#   run.sh wait-ready ./out/collect/ready.json "$run_id" 120
#
# Usage: wait_ready <ready file> <expected run id> [timeout seconds]
wait_ready() {
	local file="$1" want_run="$2" timeout="${3:-120}" waited=0
	if [ -z "$want_run" ]; then
		echo "wait-ready: the expected run identifier is required. A file from an earlier run of the same case reports ready at once, and the workload would begin with nothing observing it" >&2
		return 2
	fi
	while [ "$waited" -lt "$timeout" ]; do
		if [ -r "$file" ] && [ "$(ready_field "$file" run_id)" = "$want_run" ] && ready_flag "$file"; then
			echo "ready: every registered target accepted (run $want_run, $(ready_field "$file" updated_at))"
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "wait-ready FAILED: $file did not report run $want_run ready within ${timeout}s" >&2
	[ -r "$file" ] && cat "$file" >&2
	return 1
}

# ready_run_id prints the run identifier the collector wrote, which is what
# wait_ready is then told to wait for. Run it once the collector has
# started and before the container is fired.
#
# A file left behind by an earlier run of the same case carries that run's
# identifier, and taking it would have the wait succeed against a collector
# that is no longer there. So the report has to have been produced at or
# after the instant the current collector was started, which the caller
# passes in. Without it, the identifier is returned with a warning: the
# check cannot be made, and that is said rather than assumed away.
#
# Usage: ready_run_id <ready file> [timeout seconds] [collector start, RFC3339]
ready_run_id() {
	local file="$1" timeout="${2:-60}" not_before="${3:-}" waited=0 run generated
	while [ "$waited" -lt "$timeout" ]; do
		if [ -r "$file" ]; then
			run="$(ready_field "$file" run_id)"
			generated="$(ready_field "$file" generated_at)"
			if [ -n "$run" ]; then
				if [ -z "$not_before" ]; then
					echo "ready-run-id: no collector start time was given, so this identifier cannot be shown to be the current run's" >&2
					echo "$run"
					return 0
				fi
				if not_older_than "$generated" "$not_before"; then
					echo "$run"
					return 0
				fi
			fi
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "ready-run-id FAILED: $file carried no run identifier produced at or after ${not_before:-the start of this wait} within ${timeout}s" >&2
	return 1
}

# not_older_than compares two RFC3339 instants, and refuses to answer when
# it cannot parse them: a comparison that silently succeeded would be worse
# than none.
not_older_than() {
	local have="$1" want="$2"
	[ -n "$have" ] || return 1
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import sys
from datetime import datetime
def parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
try:
    sys.exit(0 if parse(sys.argv[1]) >= parse(sys.argv[2]) else 1)
except ValueError:
    sys.exit(1)
' "$have" "$want"
	else
		# Lexicographic order is chronological order for these, as long as
		# both are in the same zone and shape.
		[ "$have" ">" "$want" ] || [ "$have" = "$want" ]
	fi
}

ready_flag() {
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        sys.exit(0 if json.load(f).get("ready") is True else 1)
except (OSError, ValueError):
    sys.exit(1)
' "$1"
	else
		grep -qE '"ready"[[:space:]]*:[[:space:]]*true' "$1"
	fi
}

# ready_field prints one field of the readiness file, or nothing when it
# cannot be read.
ready_field() {
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        print(json.load(f).get(sys.argv[2], "") or "")
except (OSError, ValueError):
    print("")
' "$1" "$2"
	else
		sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -1
	fi
}

# attach_check confirms that the tracer's attachment points are actually
# live, by causing a known event and waiting for it to come out.
#
# The tracer printing its first line says it started, not that it attached.
# Without this check, a collection that came up and attached nothing is
# indistinguishable from a window in which nothing happened — and the
# second reads as a real measurement while the first is a failure.
#
# Usage: attach_check <trace file> [timeout seconds]
attach_check() {
	local trace="$1" timeout="${2:-30}" waited=0 marker probe
	marker="kl-attach-probe-$$"
	probe="${TMPDIR:-/tmp}/$marker"
	cp /bin/true "$probe" 2>/dev/null || {
		echo "attach-check: could not create a probe program" >&2
		return 1
	}
	chmod +x "$probe"
	"$probe" || true
	while [ "$waited" -lt "$timeout" ]; do
		if [ -r "$trace" ] && grep -q "$marker" "$trace"; then
			rm -f "$probe"
			echo "attach-check OK: the probe execution reached the trace"
			return 0
		fi
		"$probe" || true
		sleep 1
		waited=$((waited + 1))
	done
	rm -f "$probe"
	echo "attach-check FAILED: no probe execution reached $trace within ${timeout}s; the tracer started but nothing is attached" >&2
	return 1
}

# register_cgroups refreshes the control group correspondence table. It has
# to run after the container starts and before the workload is told to
# begin: a container created after the table was built is not in it, and
# every event it produces during the window would be attributed to nothing.
#
# Usage: register_cgroups <table path> [runtime-events binary]
register_cgroups() {
	local table="$1" tool="${2:-runtime-events}"
	if ! command -v "$tool" >/dev/null 2>&1 && [ ! -x "$tool" ]; then
		echo "register-cgroups: $tool not found; build it from experiments/runtime-events first" >&2
		return 1
	fi
	if [ -r "$table" ]; then
		"$tool" cgroup-map -merge "$table" -out "$table"
	else
		"$tool" cgroup-map -out "$table"
	fi
	echo "register-cgroups: refreshed $table"
}

# dump_logs copies a container's own logs out of it through its root
# filesystem, rather than by running a command inside it: adding a process
# would change the process set being measured, and some of these images
# have no shell to run one in.
dump_logs() {
	local case_id="$1" dest="$2" pid
	pid="$(container_main_pid "case$case_id")" || return 1
	mkdir -p "$dest"
	local found=0
	for name in usage.jsonl occurrences.jsonl; do
		if [ -r "/proc/$pid/root/var/log/$name" ]; then
			cp "/proc/$pid/root/var/log/$name" "$dest/$case_id.$name"
			found=1
		fi
	done
	if [ "$found" -eq 0 ]; then
		echo "dump-logs: no logs found for $case_id (run this as root, or with the privileges the collector needs)" >&2
		return 1
	fi
	echo "dump-logs: wrote $dest/$case_id.*.jsonl"
}

# count_occurrences counts the individually identified occurrences of one
# kind in a container's own log.
count_occurrences() {
	local log="$1" kind="$2"
	if [ ! -r "$log" ]; then
		echo 0
		return 0
	fi
	if [ -n "$PY3" ]; then
		"$PY3" -c '
import json, sys
n = 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("kind") == sys.argv[2]:
            n += 1
print(n)
' "$log" "$kind"
	else
		grep -cE "\"kind\"[[:space:]]*:[[:space:]]*\"$kind\"" "$log" 2>/dev/null || true
	fi
}

container_occurrence_log() {
	local pid
	pid="$(container_main_pid "$1")" || return 1
	echo "/proc/$pid/root/var/log/occurrences.jsonl"
}

up_case_13() {
	local dir
	docker build -t kl-case13 -f "$here/13/Dockerfile" "$here/images/13-short-lived"
	dir="$(prepare_fire case13)"
	docker run -d --name case13 -v "$dir:/run/fire" kl-case13
	record_container_id case13
}

up_case_14() {
	local dir
	docker build -t kl-case14 -f "$here/14/Dockerfile" "$here/images/14-dlopen-loop"
	dir="$(prepare_fire case14)"
	docker run -d --name case14 -v "$dir:/run/fire" kl-case14
	record_container_id case14
}

# The two case 15/16 conditions differ only in whether the compiled-module
# cache exists. Building without it and running without writing it back are
# both needed: otherwise the first import recreates the cache and the
# condition measures nothing.
up_case_15() {
	local dir
	docker build -t kl-case15 -f "$here/15/Dockerfile" "$here/images/15-python-import"
	dir="$(prepare_fire case15)"
	docker run -d --name case15 -p 127.0.0.1:18100:8000 -v "$dir:/run/fire" kl-case15
	record_container_id case15
}

up_case_16() {
	local dir
	docker build -t kl-case16 --build-arg PYC_CACHE=0 -f "$here/15/Dockerfile" "$here/images/15-python-import"
	dir="$(prepare_fire case16)"
	# The built image inherits case 15's ENV CASE_ID from its Dockerfile;
	# override it so this container's own occurrences are recorded as 16.
	docker run -d --name case16 -p 127.0.0.1:18101:8000 \
		-e PYTHONDONTWRITEBYTECODE=1 -e CASE_ID=16 -v "$dir:/run/fire" kl-case16
	record_container_id case16
}

up_case_17() {
	local dir
	docker build -t kl-case17 -f "$here/17/Dockerfile" "$here/images/17-node-require"
	dir="$(prepare_fire case17)"
	docker run -d --name case17 -p 127.0.0.1:18102:8080 -v "$dir:/run/fire" kl-case17
	record_container_id case17
}

up_case_18() {
	local dir
	docker build -t kl-case18 -f "$here/18/Dockerfile" "$here/images/17-node-require"
	dir="$(prepare_fire case18)"
	docker run -d --name case18 -p 127.0.0.1:18103:8080 -v "$dir:/run/fire" kl-case18
	record_container_id case18
}

up_case_19() {
	local dir
	docker build -t kl-case19 -f "$here/19/Dockerfile" "$here/images/19-jvm-jar"
	dir="$(prepare_fire case19)"
	docker run -d --name case19 -p 127.0.0.1:18104:8080 -v "$dir:/run/fire" kl-case19
	record_container_id case19
}

up_case_20() {
	local dir
	docker build -t kl-case20 -f "$here/20/Dockerfile" "$here/images/19-jvm-jar"
	dir="$(prepare_fire case20)"
	docker run -d --name case20 -p 127.0.0.1:18105:8080 -v "$dir:/run/fire" kl-case20
	record_container_id case20
}

# The late-open condition: the archive is not on the class path, so the
# runtime does not open it at startup and the load itself is what opens the
# file. Without this condition the case only ever measures loads whose file
# was already open, where there is no opening to observe.
up_case_21() {
	local dir
	docker build -t kl-case21 -f "$here/21/Dockerfile" "$here/images/19-jvm-jar"
	dir="$(prepare_fire case21)"
	docker run -d --name case21 -p 127.0.0.1:18107:8080 -v "$dir:/run/fire" kl-case21
	record_container_id case21
}

up_case_22() {
	local dir
	docker build -t kl-case22 -f "$here/22/Dockerfile" "$here/images/22-static-go"
	dir="$(prepare_fire case22)"
	docker run -d --name case22 -p 127.0.0.1:18106:8080 -v "$dir:/run/fire" kl-case22
	record_container_id case22
}

# The attribution control runs the first case's image twice, so the two
# containers run the same programs from the same paths at the same times
# and nothing but the attribution distinguishes them.
# Each container runs with its own case identifier, so an occurrence
# identifier names one run in one container. Sharing one identifier across
# both would make two different runs indistinguishable, and telling them
# apart is the whole of what this control checks.
up_case_23() {
	local dir
	docker build -t kl-case13 -f "$here/13/Dockerfile" "$here/images/13-short-lived"
	dir="$(prepare_fire case23)"
	docker run -d --name case23 -e CASE_ID=23 -v "$dir:/run/fire" kl-case13
	record_container_id case23
}

up_case_24() {
	local dir
	docker build -t kl-case13 -f "$here/13/Dockerfile" "$here/images/13-short-lived"
	dir="$(prepare_fire case24)"
	docker run -d --name case24 -e CASE_ID=24 -v "$dir:/run/fire" kl-case13
	record_container_id case24
}

# host_run is the fourth condition of the attribution control: the same
# program, at the same path, run outside any container. Without it, a
# collector that credits everything to whichever container it knows about
# would look correct.
host_run() {
	CASE_ID=23+host "$here/images/23-host/host-run.sh" "$@"
}

up_case_1() {
	docker run -d --name case1 -p 0.0.0.0:18080:80 nginx:1.27
	wait_http_200 http://127.0.0.1:18080 30
}

up_case_2() {
	docker run -d --name case2 -p 127.0.0.1:16379:6379 redis:7-alpine
	wait_log_contains case2 "Ready to accept connections" 30
}

up_case_3() {
	docker run -d --name case3 --network host nginx:1.27
	wait_http_200 http://127.0.0.1:80 30
}

up_case_4() {
	docker run -d --name case4 -e POSTGRES_PASSWORD=x postgres:16
	local waited=0
	while [ "$waited" -lt 60 ]; do
		if docker exec case4 pg_isready >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: case4 pg_isready never succeeded within 60s" >&2
	return 1
}

up_case_5() {
	docker build -t kl-case5 -f "$here/5/Dockerfile" "$here/images/5-cryptography"
	docker run -d --name case5 -p 127.0.0.1:18000:8000 kl-case5
	wait_http_200 http://127.0.0.1:18000 30
	wait_usage_events case5 open 1 30 "maps-snapshot open events"
}

up_case_6() {
	docker build -t kl-case6 -f "$here/6/Dockerfile" "$here/images/6-dynamic-server"
	docker run -d --name case6 -p 127.0.0.1:18086:8080 kl-case6
	wait_http_200 http://127.0.0.1:18086 30
	wait_usage_events case6 open 1 30 "maps-snapshot open events"
}

up_case_7a() {
	docker build -t kl-case7a -f "$here/7a/Dockerfile" "$here/images/7-static-server"
	docker run -d --name case7a -p 0.0.0.0:18081:8080 kl-case7a
	wait_http_200 http://127.0.0.1:18081 30
}

up_case_7b() {
	docker build -t kl-case7b -f "$here/7b/Dockerfile" "$here/images/7-static-server"
	docker run -d --name case7b -p 0.0.0.0:18082:8080 kl-case7b
	wait_http_200 http://127.0.0.1:18082 30
}

up_case_8() {
	docker build -t kl-case8 -f "$here/8/Dockerfile" "$here/images/8-delete-replace"
	docker run -d --name case8 kl-case8
	# Ready means all three operations are finished, not merely that three
	# lines exist: the unlinked and replaced files this case exists to
	# create do not exist until the operations that create them complete.
	wait_usage_events case8 stage 3 60 "completed operation stages"
}

up_case_9() {
	docker build -t kl-case9 -f "$here/9/Dockerfile" "$here/images/9-short-lived"
	docker run -d --name case9 kl-case9
	wait_usage_events case9 exit 1 60 "completed exec/exit pairs"
}

up_case_10() {
	docker build -t kl-case10 -f "$here/10/Dockerfile" "$here/images/10-dlopen-loop"
	docker run -d --name case10 kl-case10
	# Ready means a dlclose whose own maps re-read confirmed the mapping is
	# gone: the non-loaded period this case measures is defined by that
	# read succeeding, not by the dlclose call returning.
	wait_verified_unloads case10 1 60
}

up_case_11() {
	docker run -d --name case11 -p 127.0.0.1:18088:8080 nginxinc/nginx-unprivileged:1.27-alpine
	wait_http_200 http://127.0.0.1:18088 30
}

up_case_12() {
	docker run -d --name case12 -p 0.0.0.0:18090:80 --cap-add NET_ADMIN --cap-drop NET_RAW nginx:1.27
	wait_http_200 http://127.0.0.1:18090 30
}

# preflight_case_8 confirms, once, that the (deleted) marker this case relies
# on actually appears — required by this case's own success condition, since
# a storage driver or kernel that doesn't surface "(deleted)" the way this
# harness expects would otherwise fail silently rather than reporting
# ordinary "not confirmed" results.
preflight_case_8() {
	local pid found_exe=0 found_maps=0 target
	echo "case 8 preflight: checking for a deleted exe entry..."
	for pid in $(container_pids case8); do
		target="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
		case "$target" in
		*" (deleted)") found_exe=1 ;;
		esac
		if grep -q " (deleted)" "/proc/$pid/maps" 2>/dev/null; then
			found_maps=1
		fi
	done
	if [ "$found_exe" -eq 1 ]; then
		echo "case 8 preflight OK: found a deleted exe entry"
	else
		echo "case 8 preflight FAILED: no deleted exe entry found; the delete/replace scenario did not reproduce" >&2
		return 1
	fi
	if [ "$found_maps" -eq 1 ]; then
		echo "case 8 preflight OK: found a deleted maps entry"
	else
		echo "case 8 preflight FAILED: no deleted maps entry found; the delete/replace scenario did not reproduce" >&2
		return 1
	fi
}

# preflight_case_10 confirms, once, that the loaded/unloaded cycle actually
# produces a maps entry that disappears — the case's own definition of
# "non-loaded period" depends on that being true, per this harness's
# design.
preflight_case_10() {
	# Where in its cycle the container is when this runs is unknown, so the
	# check polls for an unloaded phase rather than assuming one has been
	# reached by some fixed time. Both halves of the evidence are required:
	# the program's own post-dlclose maps read, and an independent read of
	# the same maps file from the host.
	local pid log waited=0 seen_host=0 timeout=30
	pid="$(container_main_pid case10)" || return 1
	log="$(container_usage_log case10)" || return 1
	if [ ! -r "/proc/$pid/maps" ]; then
		echo "case 10 preflight FAILED: /proc/$pid/maps is not readable (run this as root)" >&2
		return 1
	fi
	echo "case 10 preflight: polling for an unloaded phase (up to ${timeout}s)..."
	while [ "$waited" -lt "$timeout" ]; do
		if ! grep -q libsqlite3 "/proc/$pid/maps" 2>/dev/null; then
			seen_host=1
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done
	if [ "$seen_host" -ne 1 ]; then
		echo "case 10 preflight FAILED: the libsqlite3 mapping never disappeared within ${timeout}s, so no non-loaded period exists to measure" >&2
		return 1
	fi
	echo "case 10 preflight OK: libsqlite3 is absent from /proc/$pid/maps during the unloaded phase"
	if [ "$(count_verified_unloads "$log")" -ge 1 ]; then
		echo "case 10 preflight OK: the container's own post-dlclose maps read agrees"
	else
		echo "case 10 preflight FAILED: the container recorded no dlclose whose own maps read confirmed the unload" >&2
		return 1
	fi
}

# mapped_shared_libraries prints the executable, file-backed mappings of a
# host PID that are shared libraries — the same selection the collector
# makes, read independently of it.
mapped_shared_libraries() {
	awk '$2 ~ /x/ && $6 ~ /^\// {print $6}' "/proc/$1/maps" 2>/dev/null | grep -E '\.so($|\.)' || true
}

# fixture_check reports each case's own fixture-success condition,
# independent of anything collect/match determine: a case can have a
# working fixture (the intended state genuinely exists) whose observation
# the harness still gets wrong, and that distinction only holds if fixture
# checking never goes through the harness's own collection path.
fixture_check() {
	local case_id="$1" cn="case$1" pid n uid user log
	case "$case_id" in
	1 | 3 | 12)
		n="$(docker top "$cn" 2>/dev/null | tail -n +2 | wc -l)"
		echo "$case_id: $n process row(s) in top (want >= 2 for master+worker)"
		[ "$n" -ge 2 ] || return 1
		;;
	2)
		pid="$(container_main_pid case2)" || return 1
		uid="$(effective_uid "$pid")"
		if [ -n "$uid" ] && [ "$uid" != "0" ]; then
			echo "2: redis-server (host pid $pid) runs with effective UID $uid: OK"
		else
			echo "2: redis-server (host pid $pid) effective UID is '${uid:-unreadable}': FAIL" >&2
			return 1
		fi
		;;
	4)
		n="$(docker top case4 2>/dev/null | tail -n +2 | wc -l)"
		echo "4: $n process row(s) in top (want >= 3)"
		[ "$n" -ge 3 ] || return 1
		pid="$(container_main_pid case4)" || return 1
		uid="$(effective_uid "$pid")"
		# Resolve the UID through the container's own passwd file: the name
		# only means anything in the container's own user database.
		user="$(awk -F: -v u="$uid" '$3 == u {print $1; exit}' "/proc/$pid/root/etc/passwd" 2>/dev/null || true)"
		if [ "$user" = "postgres" ]; then
			echo "4: postmaster runs as postgres (uid $uid): OK"
		else
			echo "4: postmaster runs as '${user:-uid $uid}', want postgres: FAIL" >&2
			return 1
		fi
		;;
	5)
		log="$(container_usage_log case5)" || return 1
		n="$(count_usage_events "$log" open)"
		if [ "${n:-0}" -ge 1 ]; then
			echo "5: usage.jsonl has $n startup maps-snapshot open event(s): OK"
		else
			echo "5: usage.jsonl has no maps-snapshot open event: FAIL" >&2
			return 1
		fi
		;;
	6)
		pid="$(container_main_pid case6)" || return 1
		if [ -z "$(mapped_shared_libraries "$pid")" ]; then
			echo "6: no shared library mapping found in /proc/$pid/maps: FAIL" >&2
			return 1
		fi
		echo "6: glibc shared libraries are mapped: OK"
		if [ -n "$(ls -A "/proc/$pid/root/var/lib/dpkg/status.d" 2>/dev/null || true)" ]; then
			echo "6: status.d populated: OK"
		else
			echo "6: status.d missing/empty: FAIL" >&2
			return 1
		fi
		;;
	7a | 7b)
		pid="$(container_main_pid "$cn")" || return 1
		if [ ! -r "/proc/$pid/maps" ]; then
			echo "$case_id: /proc/$pid/maps is not readable (run this as root): FAIL" >&2
			return 1
		fi
		if [ -n "$(mapped_shared_libraries "$pid")" ]; then
			echo "$case_id: the server maps shared libraries, but this case requires none: FAIL" >&2
			mapped_shared_libraries "$pid" >&2
			return 1
		fi
		echo "$case_id: no shared library mapping: OK"
		;;
	8)
		log="$(container_usage_log case8)" || return 1
		n="$(count_usage_events "$log" stage)"
		echo "8: ${n:-0} completed operation stage(s) recorded (want 3)"
		[ "${n:-0}" -ge 3 ] || return 1
		;;
	9)
		log="$(container_usage_log case9)" || return 1
		if [ "$(count_usage_events "$log" exec)" -ge 1 ] && [ "$(count_usage_events "$log" open)" -ge 1 ]; then
			echo "9: usage.jsonl records both an exec and a loader-resolved library open: OK"
		else
			echo "9: usage.jsonl is missing an exec or a dependency-library open: FAIL" >&2
			return 1
		fi
		;;
	10)
		log="$(container_usage_log case10)" || return 1
		n="$(count_verified_unloads "$log")"
		if [ "${n:-0}" -ge 1 ]; then
			echo "10: $n dlclose(s) were followed by a maps read showing the mapping gone: OK"
		else
			echo "10: no verified unloaded phase recorded: FAIL" >&2
			return 1
		fi
		;;
	11)
		pid=""
		for pid in $(container_pids case11); do
			uid="$(effective_uid "$pid")"
			if [ -z "$uid" ]; then
				echo "11: could not read /proc/$pid/status (run this as root): FAIL" >&2
				return 1
			fi
			if [ "$uid" = "0" ]; then
				echo "11: host pid $pid runs with effective UID 0: FAIL" >&2
				return 1
			fi
		done
		if [ -z "$pid" ]; then
			echo "11: docker top returned no PIDs: FAIL" >&2
			return 1
		fi
		echo "11: all processes non-root: OK"
		;;
	13 | 23 | 24)
		log="$(container_occurrence_log "$cn")" || return 1
		n="$(count_occurrences "$log" exec)"
		if [ "${n:-0}" -ge 1 ]; then
			echo "$case_id: $n individually identified execution(s) recorded: OK"
		else
			echo "$case_id: no individually identified execution recorded; was the container fired?" >&2
			return 1
		fi
		;;
	14 | 15 | 16 | 17 | 18 | 19 | 20 | 21)
		log="$(container_occurrence_log "$cn")" || return 1
		n="$(count_occurrences "$log" load)"
		# Two loads are expected: the first reads the files, the second
		# finds them already in memory. Both have to be there, because the
		# second is what shows the case can tell a read from a lookup — and
		# a case that cannot tell them apart must not be measured.
		if [ "${n:-0}" -ge 2 ]; then
			echo "$case_id: $n individually identified load(s) recorded, including the cached repeat: OK"
		else
			echo "$case_id: fewer than two loads recorded (${n:-0}); the case cannot distinguish a file read from a lookup" >&2
			return 1
		fi
		;;
	22)
		log="$(container_occurrence_log case22)" || return 1
		n="$(count_occurrences "$log" exec)"
		if [ "${n:-0}" -lt 1 ]; then
			echo "22: no individually identified execution recorded; was the container fired?" >&2
			return 1
		fi
		pid="$(container_main_pid case22)" || return 1
		if [ -n "$(mapped_shared_libraries "$pid")" ]; then
			echo "22: the server maps shared libraries, but this case requires none: FAIL" >&2
			mapped_shared_libraries "$pid" >&2
			return 1
		fi
		echo "22: execution recorded and no shared library mapped: OK"
		;;
	*)
		echo "fixture_check: no check defined for case $case_id" >&2
		return 1
		;;
	esac
}

down_case() { docker rm -f "case$1" >/dev/null 2>&1 || true; }

all_cases() { echo 1 2 3 4 5 6 7a 7b 8 9 10 11 12; }

# The V-series cases are not in up-all: each one has to be started while an
# observation is already running and then fired by hand once the collector
# reports itself ready, so starting them in a batch would defeat the
# ordering they exist to establish.
v_cases() { echo 13 14 15 16 17 18 19 20 21 22 23 24; }

usage() {
	cat >&2 <<'EOF'
usage: run.sh up <case> | down <case> | up-all | down-all | preflight-8 | preflight-10
       run.sh fixture-check <case>
       run.sh ready-run-id <ready file> [timeout seconds] [collector start, RFC3339]
       run.sh wait-ready <ready file> <expected run id> [timeout seconds]
       run.sh register-cgroups <table path> [runtime-events binary]
       run.sh attach-check <trace file> [timeout seconds]
       run.sh fire <case>
       run.sh dump-logs <case> <directory>
       run.sh host-run <log> [iterations] [interval seconds]

cases: 1 2 3 4 5 6 7a 7b 8 9 10 11 12
       13 14 15 16 17 18 19 20 21 22 23 24

Cases 13-24 wait for a signal before doing anything, so each one is
started, then fired once the collector reports every registered target
accepted:

  runtime-events cgroup-map -out ./out/cgroup-map.json
  sudo bpftrace bpftrace/runtime-events-nofilter.bt > ./out/trace.txt 2> ./out/trace.err &
  run.sh attach-check ./out/trace.txt                # starting is not attaching
  collector_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  runtime-discovery collect -case-variant 17 -sync startup -expect case17 -config-id bpftrace-v2-nofilter-64p ... &
  run.sh up 17
  run.sh register-cgroups ./out/cgroup-map.json     # the container exists only now
  run_id="$(run.sh ready-run-id ./out/collect/ready.json 60 "$collector_started")"
  run.sh wait-ready ./out/collect/ready.json "$run_id"
  run.sh fire 17

The control group table is refreshed after the container starts and before
it is fired: a container created after the table was built is not in it,
and every event it produced during the window would be attributed to
nothing.
EOF
}

main() {
	case "${1:-}" in
	up)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		# Function names cannot start with a digit, so each case's startup
		# function is prefixed with "case_" (e.g. case 13 is up_case_13).
		"up_case_$2"
		;;
	down)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		down_case "$2"
		;;
	up-all)
		for c in $(all_cases); do "up_case_$c"; done
		;;
	down-all)
		for c in $(all_cases) $(v_cases); do down_case "$c"; done
		;;
	preflight-8)
		preflight_case_8
		;;
	preflight-10)
		preflight_case_10
		;;
	fixture-check)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		fixture_check "$2"
		;;
	fire)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		fire_case "$2"
		;;
	wait-ready)
		[ -n "${2:-}" ] && [ -n "${3:-}" ] || {
			usage
			exit 2
		}
		wait_ready "$2" "$3" "${4:-120}"
		;;
	ready-run-id)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		ready_run_id "$2" "${3:-60}" "${4:-}"
		;;
	register-cgroups)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		register_cgroups "$2" "${3:-runtime-events}"
		;;
	attach-check)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		attach_check "$2" "${3:-30}"
		;;
	dump-logs)
		[ -n "${2:-}" ] && [ -n "${3:-}" ] || {
			usage
			exit 2
		}
		dump_logs "$2" "$3"
		;;
	host-run)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		shift
		host_run "$@"
		;;
	*)
		usage
		exit 2
		;;
	esac
}

main "$@"
