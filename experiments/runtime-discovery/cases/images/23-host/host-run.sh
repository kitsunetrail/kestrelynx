#!/usr/bin/env bash
# Runs, on the host itself, a program with the same name and the same path
# as one the containers run, and records each run as an individually
# identified occurrence attributed to the host.
#
# This is the control for attribution. Two containers running the same
# program show whether one container's work is ever credited to the other;
# this shows whether work done outside any container is credited to one.
# Without it, a collector that attributes everything to whichever container
# it knows about would look correct.
#
# The occurrences are written with the host as their owner, which is what
# the checking compares each event's claimed container against.
#
# Usage: host-run.sh <output log> [iterations] [interval seconds]
set -euo pipefail

log="${1:?usage: host-run.sh <output log> [iterations] [interval seconds]}"
iterations="${2:-10}"
interval="${3:-5}"
program="${HOST_PROGRAM:-/usr/bin/curl}"
case_id="${CASE_ID:-23+host}"

if [ ! -x "$program" ]; then
	echo "host-run: $program is not executable here, so there is no host-side run to compare against" >&2
	exit 1
fi

: >"$log"

# The PID namespace this script itself runs in. Every child it forks below
# stays in the same namespace, so this is read once here rather than once
# per iteration. Recorded so an event's own pid_ns can be compared against
# it: NSPID/NSTID alone can collide with a task in some other namespace,
# and only the two together settle whether an event is really this run.
pid_ns="$(readlink /proc/self/ns/pid)"
pid_ns="${pid_ns#pid:[}"
pid_ns="${pid_ns%]}"

now_ts() {
	date -u +%Y-%m-%dT%H:%M:%S.%NZ
}

starttime_of() {
	# Field 22 of the process's status line. Field 2 is parenthesized and
	# may itself contain ")", so the greedy match finds the last one and
	# the remaining field 20 is overall field 22.
	awk '{match($0, /.*\)/); $0 = substr($0, RLENGTH + 1); print $20}' "/proc/$1/stat" 2>/dev/null || echo 0
}

for i in $(seq 1 "$iterations"); do
	"$program" -s -o /dev/null https://example.com &
	pid=$!
	st="$(starttime_of "$pid")"
	ts="$(now_ts)"
	# The owner is the host, not a container. An event that claims a
	# container for one of these is a wrong attribution, which is exactly
	# what this exists to detect.
	printf '{"id":"%s-host-exec-%06d","kind":"exec","pid":%s,"tid":%s,"starttime":%s,"pid_ns":%s,"ts":"%s","ok":true,"path":"%s","container_id":"host"}\n' \
		"$case_id" "$i" "$pid" "$pid" "$st" "$pid_ns" "$ts" "$program" >>"$log"
	wait "$pid" || true
	sleep "$interval"
done
