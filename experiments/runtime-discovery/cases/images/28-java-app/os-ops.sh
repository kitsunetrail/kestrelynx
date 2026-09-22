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
# operation sequence as a measurement run of the same image. Each
# operations.jsonl record also carries the instance's own end_ts,
# duration_ms, exit_code, clock_source and clock_resolution_ms, added
# alongside the original id/ts/op/ok fields rather than in place of them,
# so a reader built against the original fields keeps working unchanged.
set -u

LOG=/var/log/usage.jsonl
OCC=/var/log/occurrences.jsonl
OPS=/var/log/operations.jsonl
FIRE_DIR=${FIRE_DIR:-/run/fire}
CASE=${CASE_ID:-28}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8080/health}
GIT_REPO=/opt/fixture-repo
DIGEST_INPUT=/opt/fixture-repo/digest-input.txt
OPTIME=/usr/local/bin/optime

PID_NS="$(readlink /proc/self/ns/pid)"
PID_NS="${PID_NS#pid:[}"
PID_NS="${PID_NS%]}"

# json_field extracts one field's value from a single-line JSON object by simple pattern
# matching (sed), which optime's own fixed, single-line, non-nested output shape makes
# safe without a real JSON parser: $1=the JSON text, $2=the field name, $3=1 if the value
# is itself a JSON string (quoted; strips the quotes), unset/0 for a bare number.
json_field() {
	if [ "${3:-0}" = 1 ]; then
		printf '%s' "$1" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p"
	else
		printf '%s' "$1" | sed -n "s/.*\"$2\":\\(-\\{0,1\\}[0-9][0-9]*\\).*/\\1/p"
	fi
}

OCC_N=0
run_cmd() {
	# $1=label $2=path, remaining args are passed through to it.
	label="$1"
	path="$2"
	shift 2
	# optime (built from experiments/runtime-discovery/cmd/optime) runs $path as its own
	# child, times it with CLOCK_MONOTONIC (microsecond resolution) entirely inside its own
	# process, and prints one JSON line with that duration plus the child's own pid and
	# /proc/<pid>/stat starttime - the same (pid, starttime) identity occurrences.jsonl and
	# usage.jsonl already key on, read by optime itself before the child exits rather than
	# reconstructed here after the fact. Nothing in this shell runs between the child
	# starting and finishing: optime's own invocation IS the timed interval, so no logging
	# or bookkeeping this script does can ever land inside it.
	result="$("$OPTIME" -- "$path" "$@" 2>/dev/null)"
	pid="$(json_field "$result" pid)"
	st="$(json_field "$result" starttime)"
	ts="$(json_field "$result" start_wall 1)"
	end_ts="$(json_field "$result" end_wall 1)"
	dur_us="$(json_field "$result" duration_us)"
	rc="$(json_field "$result" exit_code)"
	dur_ms="$(awk -v us="${dur_us:-0}" 'BEGIN{printf "%.3f", us/1000}')"
	OCC_N=$((OCC_N + 1))
	printf '{"id":"%s-exec-osops-%06d","kind":"exec","pid":%s,"tid":%s,"starttime":%s,"pid_ns":%s,"ts":"%s","ok":true,"path":"%s","container_id":"%s"}\n' \
		"$CASE" "$OCC_N" "$pid" "$pid" "$st" "$PID_NS" "$ts" "$path" "$CID" >>"$OCC"
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exec","path":"%s","ok":true}\n' "$ts" "$pid" "$st" "$path" >>"$LOG"
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exit","path":"%s","ok":true,"status":%s}\n' \
		"$end_ts" "$pid" "$st" "$path" "$rc" >>"$LOG"
	printf '{"id":"%s-op-osops-%06d","ts":"%s","op":"osops_%s","ok":%s,"end_ts":"%s","duration_ms":%s,"exit_code":%s,"clock_source":"CLOCK_MONOTONIC","clock_resolution_ms":0.001}\n' \
		"$CASE" "$OCC_N" "$ts" "$label" "$([ "$rc" = 0 ] && echo true || echo false)" "$end_ts" "$dur_ms" "$rc" >>"$OPS"
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
