#!/bin/sh
# Runs curl, git and openssl briefly every five seconds, independently of
# the firing signal, as this case's short-lived OS-package activity. This
# script itself is the case's "operational scheduler": it runs for the
# whole life of the container, so it belongs to the resident subject
# category even though every command it launches is itself short-lived.
#
# Two logs are written, mirroring the resident program's own: usage.jsonl
# records each exec/exit in the shared format, and occurrences.jsonl
# records each individual run with an identifier of its own. A third,
# operations.jsonl, records that the operation happened at all, so an
# independently obtained ground-truth run can be checked against the same
# operation sequence as a measurement run of the same image.
set -u

LOG=/var/log/usage.jsonl
OCC=/var/log/occurrences.jsonl
OPS=/var/log/operations.jsonl
FIRE_DIR=${FIRE_DIR:-/run/fire}
CASE=${CASE_ID:-26}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8000/health}
GIT_REPO=/opt/fixture-repo
DIGEST_INPUT=/opt/fixture-repo/digest-input.txt

PID_NS="$(readlink /proc/self/ns/pid)"
PID_NS="${PID_NS#pid:[}"
PID_NS="${PID_NS%]}"

now_ts() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

starttime_of() {
	# Field 22 (starttime) of /proc/<pid>/stat; field 2 is parenthesized
	# and may itself contain ")", so the greedy match finds the last one.
	awk '{match($0, /.*\)/); $0 = substr($0, RLENGTH + 1); print $20}' "/proc/$1/stat" 2>/dev/null || echo 0
}

OCC_N=0
run_cmd() {
	# $1=label $2=path, remaining args are passed through to it.
	label="$1"
	path="$2"
	shift 2
	"$path" "$@" >/dev/null 2>&1 &
	pid=$!
	st="$(starttime_of "$pid")"
	ts="$(now_ts)"
	OCC_N=$((OCC_N + 1))
	printf '{"id":"%s-exec-osops-%06d","kind":"exec","pid":%s,"tid":%s,"starttime":%s,"pid_ns":%s,"ts":"%s","ok":true,"path":"%s","container_id":"%s"}\n' \
		"$CASE" "$OCC_N" "$pid" "$pid" "$st" "$PID_NS" "$ts" "$path" "$CID" >>"$OCC"
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exec","path":"%s","ok":true}\n' "$ts" "$pid" "$st" "$path" >>"$LOG"
	wait "$pid"
	rc=$?
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exit","path":"%s","ok":true,"status":%s}\n' \
		"$(now_ts)" "$pid" "$st" "$path" "$rc" >>"$LOG"
	printf '{"id":"%s-op-osops-%06d","ts":"%s","op":"osops_%s","ok":%s}\n' \
		"$CASE" "$OCC_N" "$ts" "$label" "$([ "$rc" -eq 0 ] && echo true || echo false)" >>"$OPS"
}

container_id() {
	if [ -r "$FIRE_DIR/container-id" ]; then
		cat "$FIRE_DIR/container-id"
	else
		echo ""
	fi
}

# The shared container-id file is written right after the container
# starts (before the firing signal), so this only has to wait out the
# short race against that write, not the firing signal itself.
while [ ! -s "$FIRE_DIR/container-id" ]; do sleep 1; done
CID="$(container_id)"

while true; do
	run_cmd curl /usr/bin/curl -s -o /dev/null "$HEALTH_URL"
	# --git-dir names the repository by absolute path directly; -C instead
	# opens its own files relative to the process's own cwd, which this
	# design's strace-based ground truth cannot resolve back to a path.
	run_cmd git /usr/bin/git --git-dir="$GIT_REPO/.git" log -1 --format=%H
	run_cmd openssl /usr/bin/openssl dgst -sha256 "$DIGEST_INPUT"
	sleep 5
done
