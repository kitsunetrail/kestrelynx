#!/bin/sh
# Runs curl and git briefly every 5 seconds, after being told to start.
#
# Two logs are written, and they answer different questions.
#
#   /var/log/usage.jsonl records, in the shared format, that a package's
#   files were in use during a span of time. It is what decides whether a
#   package counts as used in a window.
#
#   /var/log/occurrences.jsonl records each individual run, with an
#   identifier of its own. It is what makes it possible to ask how many
#   runs happened and how many of them were seen — a question the first log
#   cannot answer, because it collapses to a per-package true or false.
#
# Nothing starts until the signal arrives. The observation has to be in
# place first: a run that happens while the collector is still starting up
# would be missed by a collector that works perfectly, and the measurement
# would record that as a failure to capture.
#
# The wait is a blocking read on a pipe rather than a polling loop, because
# a polling loop in a shell runs an external sleep on every turn, and every
# one of those is an execution this case is counting.
#
# Two properties the loop has to preserve, because the ground truth is
# otherwise wrong rather than merely coarse:
#
#   * Timestamps carry sub-second precision. curl and git finish in
#     milliseconds, so whole-second stamps would put a run's start and end
#     at the same instant and collapse its interval to zero length.
#   * The loader's trace is consumed while the child is still running, so a
#     library's recorded load time is close to when it was actually loaded
#     rather than when the run was tidied up afterwards.
#
# An exit's ok field records that the exit was observed, not that the
# command succeeded: a non-zero exit is still a real end of the interval,
# and reporting it as not-ok would make a reader discard the endpoint. The
# exit code goes in its own field.
set -u

LOG=/var/log/usage.jsonl
OCC=/var/log/occurrences.jsonl
FIRE_DIR=${FIRE_DIR:-/run/fire}
CASE=${CASE_ID:-13}
: >"$LOG"
: >"$OCC"

# The PID namespace this script itself runs in — the container's own,
# since this runs inside it. Recorded on each occurrence so it can be
# compared against an event's own pid_ns: NSPID/NSTID alone can collide
# with a task in some other namespace, and only the two together settle
# whether an event is really this run.
PID_NS="$(readlink /proc/self/ns/pid)"
PID_NS="${PID_NS#pid:[}"
PID_NS="${PID_NS%]}"

now_ts() {
	date -u +%Y-%m-%dT%H:%M:%S.%NZ
}

starttime_of() {
	# Field 22 (starttime) of /proc/<pid>/stat. Field 2 is parenthesized
	# and may contain ")" itself, so the greedy match finds the last one
	# and the remaining field 20 is overall field 22.
	awk '{match($0, /.*\)/); $0 = substr($0, RLENGTH + 1); print $20}' "/proc/$1/stat" 2>/dev/null || echo 0
}

container_id() {
	if [ -r "$FIRE_DIR/container-id" ]; then
		cat "$FIRE_DIR/container-id"
	else
		echo ""
	fi
}

log_event() {
	# $1=pid $2=starttime $3=event $4=path $5=ok
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"%s","path":"%s","ok":%s}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" "$5" >>"$LOG"
}

log_event_at() {
	# $1=ts $2=pid $3=starttime $4=event $5=path $6=ok
	#
	# The time is passed in rather than read now. Whether a run succeeded
	# is only settled once it has finished, but the run happened when it
	# started — and the usage interval is built from this timestamp, so
	# writing the later instant would move the interval past the run and
	# change what a window ending in between concludes.
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"%s","path":"%s","ok":%s}\n' \
		"$1" "$2" "$3" "$4" "$5" "$6" >>"$LOG"
}

log_exit() {
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exit","path":"%s","ok":true,"status":%s}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" >>"$LOG"
}

OCC_N=0
log_occurrence_exec() {
	# $1=pid $2=starttime $3=path $4=ts $5=ok. The thread identifier equals
	# the process identifier: this is a freshly started process's first
	# thread, so the process generation is its own.
	OCC_N=$((OCC_N + 1))
	printf '{"id":"%s-exec-%06d","kind":"exec","pid":%s,"tid":%s,"starttime":%s,"pid_ns":%s,"ts":"%s","ok":%s,"path":"%s","container_id":"%s"}\n' \
		"$CASE" "$OCC_N" "$1" "$1" "$2" "$PID_NS" "$4" "$5" "$3" "$CID" >>"$OCC"
}

run_with_ld_debug() {
	path="$1"
	shift
	fifo="/tmp/ld-debug.$$"
	rm -f "$fifo"
	mkfifo "$fifo" || return 1

	# The redirection to the pipe happens in the background child, so this
	# shell is not blocked waiting for a reader; the child blocks on its
	# own open until the read loop below opens the other end.
	LD_DEBUG=libs "$path" "$@" >/dev/null 2>"$fifo" &
	pid=$!
	st="$(starttime_of "$pid")"
	ts="$(now_ts)"

	# Whether the program was actually reached is checked, not assumed. A
	# start that failed — the file missing, the wrong architecture — still
	# produces a process here, and recording it as a successful execution
	# would put something in the denominator that never happened and count
	# the collection as having missed it.
	started=false
	if [ -r "/proc/$pid/exe" ]; then
		real="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
		case "$real" in
		"$path" | "$path "*) started=true ;;
		esac
	fi
	if [ "$started" != true ]; then
		# The process may simply have finished already, which is the
		# ordinary case for a command that takes milliseconds. Its exit
		# status is what settles it, so the decision is deferred.
		started=pending
	fi

	# Each "calling init:" line names one shared object the loader actually
	# activated for this run, not merely one it considered. A run that
	# never reached the program produces none of them.
	while IFS= read -r line; do
		case "$line" in
		*"calling init: "*)
			lib="${line##*calling init: }"
			[ -n "$lib" ] && log_event "$pid" "$st" "open" "$lib" "true"
			;;
		esac
	done <"$fifo"

	wait "$pid"
	rc=$?
	# A start that never reached the program exits 126 or 127 in every
	# shell that implements it; those are recorded as failed executions and
	# stay out of the denominator.
	case "$rc" in
	126 | 127) started=false ;;
	*) [ "$started" = pending ] && started=true ;;
	esac
	log_event_at "$ts" "$pid" "$st" "exec" "$path" "$started"
	log_occurrence_exec "$pid" "$st" "$path" "$ts" "$started"
	if [ "$started" = true ]; then
		log_exit "$pid" "$st" "$path" "$rc"
	fi
	rm -f "$fifo"
}

# Wait to be told to start. The read blocks without running anything, so
# the wait itself produces none of the executions this case counts.
if [ -p "$FIRE_DIR/fire" ]; then
	read -r _ <"$FIRE_DIR/fire"
fi
CID="$(container_id)"
printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"stage","path":"fired","ok":true}\n' \
	"$(now_ts)" "$$" "$(starttime_of $$)" >>"$LOG"

while true; do
	run_with_ld_debug /usr/bin/curl -s -o /dev/null https://example.com
	run_with_ld_debug /usr/bin/git --version
	sleep 5
done
