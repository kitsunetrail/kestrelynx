#!/usr/bin/env bash
# Starts and stops the R1-R12 test-matrix containers for the runtime
# discovery measurement harness, waits for each case's own readiness
# condition, and runs the R8/R10 pre-sampling checks their case definitions
# require. Every startup command and readiness check is taken from the test
# matrix that specifies this harness; this script exists only to save
# re-typing them, not to decide what they should be.
#
# Usage:
#   run.sh up <case>       # e.g. run.sh up r1 (builds first if the case needs a local image)
#   run.sh down <case>
#   run.sh up-all
#   run.sh down-all
#   run.sh preflight-r8    # confirm deleted exe/maps entries are actually visible
#   run.sh preflight-r10   # confirm the dlopen/dlclose mapping actually disappears while unloaded
#   run.sh fixture-check <case>
#
# R5/R6/R7a/R7b/R8/R9/R10 build a local image first; the rest run an
# upstream image directly. Containers are named after their case ID so
# `collect -containers` and match's inputs can find them.
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
# mapping was gone — R10's definition of a non-loaded period.
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

up_r1() {
	docker run -d --name r1 -p 0.0.0.0:18080:80 nginx:1.27
	wait_http_200 http://127.0.0.1:18080 30
}

up_r2() {
	docker run -d --name r2 -p 127.0.0.1:16379:6379 redis:7-alpine
	wait_log_contains r2 "Ready to accept connections" 30
}

up_r3() {
	docker run -d --name r3 --network host nginx:1.27
	wait_http_200 http://127.0.0.1:80 30
}

up_r4() {
	docker run -d --name r4 -e POSTGRES_PASSWORD=x postgres:16
	local waited=0
	while [ "$waited" -lt 60 ]; do
		if docker exec r4 pg_isready >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		waited=$((waited + 1))
	done
	echo "readiness FAILED: r4 pg_isready never succeeded within 60s" >&2
	return 1
}

up_r5() {
	docker build -t kl-r5 -f "$here/r5/Dockerfile" "$here/images/r5-cryptography"
	docker run -d --name r5 -p 127.0.0.1:18000:8000 kl-r5
	wait_http_200 http://127.0.0.1:18000 30
	wait_usage_events r5 open 1 30 "maps-snapshot open events"
}

up_r6() {
	docker build -t kl-r6 -f "$here/r6/Dockerfile" "$here/images/r6-dynamic-server"
	docker run -d --name r6 -p 127.0.0.1:18086:8080 kl-r6
	wait_http_200 http://127.0.0.1:18086 30
	wait_usage_events r6 open 1 30 "maps-snapshot open events"
}

up_r7a() {
	docker build -t kl-r7a -f "$here/r7a/Dockerfile" "$here/images/r7-static-server"
	docker run -d --name r7a -p 0.0.0.0:18081:8080 kl-r7a
	wait_http_200 http://127.0.0.1:18081 30
}

up_r7b() {
	docker build -t kl-r7b -f "$here/r7b/Dockerfile" "$here/images/r7-static-server"
	docker run -d --name r7b -p 0.0.0.0:18082:8080 kl-r7b
	wait_http_200 http://127.0.0.1:18082 30
}

up_r8() {
	docker build -t kl-r8 -f "$here/r8/Dockerfile" "$here/images/r8-delete-replace"
	docker run -d --name r8 kl-r8
	# Ready means all three operations are finished, not merely that three
	# lines exist: the unlinked and replaced files this case exists to
	# create do not exist until the operations that create them complete.
	wait_usage_events r8 stage 3 60 "completed operation stages"
}

up_r9() {
	docker build -t kl-r9 -f "$here/r9/Dockerfile" "$here/images/r9-short-lived"
	docker run -d --name r9 kl-r9
	wait_usage_events r9 exit 1 60 "completed exec/exit pairs"
}

up_r10() {
	docker build -t kl-r10 -f "$here/r10/Dockerfile" "$here/images/r10-dlopen-loop"
	docker run -d --name r10 kl-r10
	# Ready means a dlclose whose own maps re-read confirmed the mapping is
	# gone: the non-loaded period this case measures is defined by that
	# read succeeding, not by the dlclose call returning.
	wait_verified_unloads r10 1 60
}

up_r11() {
	docker run -d --name r11 -p 127.0.0.1:18088:8080 nginxinc/nginx-unprivileged:1.27-alpine
	wait_http_200 http://127.0.0.1:18088 30
}

up_r12() {
	docker run -d --name r12 -p 0.0.0.0:18090:80 --cap-add NET_ADMIN --cap-drop NET_RAW nginx:1.27
	wait_http_200 http://127.0.0.1:18090 30
}

# preflight_r8 confirms, once, that the (deleted) marker this case relies on
# actually appears — required by this case's own success condition, since a
# storage driver or kernel that doesn't surface "(deleted)" the way this
# harness expects would otherwise fail silently rather than reporting
# ordinary "not confirmed" results.
preflight_r8() {
	local pid found_exe=0 found_maps=0 target
	echo "R8 preflight: checking for a deleted exe entry..."
	for pid in $(container_pids r8); do
		target="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
		case "$target" in
		*" (deleted)") found_exe=1 ;;
		esac
		if grep -q " (deleted)" "/proc/$pid/maps" 2>/dev/null; then
			found_maps=1
		fi
	done
	if [ "$found_exe" -eq 1 ]; then
		echo "R8 preflight OK: found a deleted exe entry"
	else
		echo "R8 preflight FAILED: no deleted exe entry found; the delete/replace scenario did not reproduce" >&2
		return 1
	fi
	if [ "$found_maps" -eq 1 ]; then
		echo "R8 preflight OK: found a deleted maps entry"
	else
		echo "R8 preflight FAILED: no deleted maps entry found; the delete/replace scenario did not reproduce" >&2
		return 1
	fi
}

# preflight_r10 confirms, once, that the loaded/unloaded cycle actually
# produces a maps entry that disappears — the case's own definition of
# "non-loaded period" depends on that being true, per this harness's
# design.
preflight_r10() {
	# Where in its cycle the container is when this runs is unknown, so the
	# check polls for an unloaded phase rather than assuming one has been
	# reached by some fixed time. Both halves of the evidence are required:
	# the program's own post-dlclose maps read, and an independent read of
	# the same maps file from the host.
	local pid log waited=0 seen_host=0 timeout=30
	pid="$(container_main_pid r10)" || return 1
	log="$(container_usage_log r10)" || return 1
	if [ ! -r "/proc/$pid/maps" ]; then
		echo "R10 preflight FAILED: /proc/$pid/maps is not readable (run this as root)" >&2
		return 1
	fi
	echo "R10 preflight: polling for an unloaded phase (up to ${timeout}s)..."
	while [ "$waited" -lt "$timeout" ]; do
		if ! grep -q libsqlite3 "/proc/$pid/maps" 2>/dev/null; then
			seen_host=1
			break
		fi
		sleep 1
		waited=$((waited + 1))
	done
	if [ "$seen_host" -ne 1 ]; then
		echo "R10 preflight FAILED: the libsqlite3 mapping never disappeared within ${timeout}s, so no non-loaded period exists to measure" >&2
		return 1
	fi
	echo "R10 preflight OK: libsqlite3 is absent from /proc/$pid/maps during the unloaded phase"
	if [ "$(count_verified_unloads "$log")" -ge 1 ]; then
		echo "R10 preflight OK: the container's own post-dlclose maps read agrees"
	else
		echo "R10 preflight FAILED: the container recorded no dlclose whose own maps read confirmed the unload" >&2
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
	local case_id="$1" pid n uid user log
	case "$case_id" in
	r1 | r3 | r12)
		n="$(docker top "$case_id" 2>/dev/null | tail -n +2 | wc -l)"
		echo "$case_id: $n process row(s) in top (want >= 2 for master+worker)"
		[ "$n" -ge 2 ] || return 1
		;;
	r2)
		pid="$(container_main_pid r2)" || return 1
		uid="$(effective_uid "$pid")"
		if [ -n "$uid" ] && [ "$uid" != "0" ]; then
			echo "r2: redis-server (host pid $pid) runs with effective UID $uid: OK"
		else
			echo "r2: redis-server (host pid $pid) effective UID is '${uid:-unreadable}': FAIL" >&2
			return 1
		fi
		;;
	r4)
		n="$(docker top r4 2>/dev/null | tail -n +2 | wc -l)"
		echo "r4: $n process row(s) in top (want >= 3)"
		[ "$n" -ge 3 ] || return 1
		pid="$(container_main_pid r4)" || return 1
		uid="$(effective_uid "$pid")"
		# Resolve the UID through the container's own passwd file: the name
		# only means anything in the container's own user database.
		user="$(awk -F: -v u="$uid" '$3 == u {print $1; exit}' "/proc/$pid/root/etc/passwd" 2>/dev/null || true)"
		if [ "$user" = "postgres" ]; then
			echo "r4: postmaster runs as postgres (uid $uid): OK"
		else
			echo "r4: postmaster runs as '${user:-uid $uid}', want postgres: FAIL" >&2
			return 1
		fi
		;;
	r5)
		log="$(container_usage_log r5)" || return 1
		n="$(count_usage_events "$log" open)"
		if [ "${n:-0}" -ge 1 ]; then
			echo "r5: usage.jsonl has $n startup maps-snapshot open event(s): OK"
		else
			echo "r5: usage.jsonl has no maps-snapshot open event: FAIL" >&2
			return 1
		fi
		;;
	r6)
		pid="$(container_main_pid r6)" || return 1
		if [ -z "$(mapped_shared_libraries "$pid")" ]; then
			echo "r6: no shared library mapping found in /proc/$pid/maps: FAIL" >&2
			return 1
		fi
		echo "r6: glibc shared libraries are mapped: OK"
		if [ -n "$(ls -A "/proc/$pid/root/var/lib/dpkg/status.d" 2>/dev/null || true)" ]; then
			echo "r6: status.d populated: OK"
		else
			echo "r6: status.d missing/empty: FAIL" >&2
			return 1
		fi
		;;
	r7a | r7b)
		pid="$(container_main_pid "$case_id")" || return 1
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
	r8)
		log="$(container_usage_log r8)" || return 1
		n="$(count_usage_events "$log" stage)"
		echo "r8: ${n:-0} completed operation stage(s) recorded (want 3)"
		[ "${n:-0}" -ge 3 ] || return 1
		;;
	r9)
		log="$(container_usage_log r9)" || return 1
		if [ "$(count_usage_events "$log" exec)" -ge 1 ] && [ "$(count_usage_events "$log" open)" -ge 1 ]; then
			echo "r9: usage.jsonl records both an exec and a loader-resolved library open: OK"
		else
			echo "r9: usage.jsonl is missing an exec or a dependency-library open: FAIL" >&2
			return 1
		fi
		;;
	r10)
		log="$(container_usage_log r10)" || return 1
		n="$(count_verified_unloads "$log")"
		if [ "${n:-0}" -ge 1 ]; then
			echo "r10: $n dlclose(s) were followed by a maps read showing the mapping gone: OK"
		else
			echo "r10: no verified unloaded phase recorded: FAIL" >&2
			return 1
		fi
		;;
	r11)
		pid=""
		for pid in $(container_pids r11); do
			uid="$(effective_uid "$pid")"
			if [ -z "$uid" ]; then
				echo "r11: could not read /proc/$pid/status (run this as root): FAIL" >&2
				return 1
			fi
			if [ "$uid" = "0" ]; then
				echo "r11: host pid $pid runs with effective UID 0: FAIL" >&2
				return 1
			fi
		done
		if [ -z "$pid" ]; then
			echo "r11: docker top returned no PIDs: FAIL" >&2
			return 1
		fi
		echo "r11: all processes non-root: OK"
		;;
	*)
		echo "fixture_check: no check defined for case $case_id" >&2
		return 1
		;;
	esac
}

down_case() { docker rm -f "$1" >/dev/null 2>&1 || true; }

all_cases() { echo r1 r2 r3 r4 r5 r6 r7a r7b r8 r9 r10 r11 r12; }

usage() {
	cat >&2 <<'EOF'
usage: run.sh up <case> | down <case> | up-all | down-all | preflight-r8 | preflight-r10 | fixture-check <case>
EOF
}

main() {
	case "${1:-}" in
	up)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		"up_$2"
		;;
	down)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		down_case "$2"
		;;
	up-all)
		for c in $(all_cases); do "up_$c"; done
		;;
	down-all)
		for c in $(all_cases); do down_case "$c"; done
		;;
	preflight-r8)
		preflight_r8
		;;
	preflight-r10)
		preflight_r10
		;;
	fixture-check)
		[ -n "${2:-}" ] || {
			usage
			exit 2
		}
		fixture_check "$2"
		;;
	*)
		usage
		exit 2
		;;
	esac
}

main "$@"
