#!/bin/sh
# Runs curl and git briefly every 5 seconds under LD_DEBUG=libs, logging
# both the exec/exit lifecycle and the dynamic loader's own dependency
# resolution to /var/log/usage.jsonl in the common format:
#   {"ts":...,"pid":...,"starttime":...,"event":"exec|open|exit","path":...,"ok":true|false}
# LD_DEBUG=libs is used because exec/exit alone never records which shared
# libraries the dynamic loader actually activated for that run — only its
# own debug trace does.
#
# Two properties this loop has to preserve, because the ground truth is
# otherwise wrong rather than merely coarse:
#
#   * Timestamps carry sub-second precision. curl and git finish in
#     milliseconds, so whole-second stamps would put a run's exec and exit
#     at the same instant and collapse its usage interval to zero length.
#   * The loader's trace is consumed while the child is still running (via
#     a FIFO read in the foreground), so an "open" event's timestamp is
#     close to when the library was actually loaded rather than when the
#     run was post-processed. Every such event carries the child's own pid
#     and starttime, so it belongs to the same process generation as the
#     exec/exit pair around it.
#
# An "exit" event's ok field records that the exit was observed at all, not
# whether the command succeeded: a non-zero exit is still a real end of the
# usage interval, and reporting it as ok=false would make a consumer
# discard the interval's endpoint. The exit code goes in its own "status"
# field.
set -u

LOG=/var/log/usage.jsonl
: >"$LOG"

now_ts() {
	# RFC3339 with nanoseconds; GNU date's %N is what supplies the
	# sub-second part this case depends on.
	date -u +%Y-%m-%dT%H:%M:%S.%NZ
}

starttime_of() {
	# Field 22 (starttime) of /proc/<pid>/stat. Field 2 (comm) is
	# parenthesized and may contain ")" itself, so the greedy match finds
	# the *last* ")" and the remaining field 20 is overall field 22.
	awk '{match($0, /.*\)/); $0 = substr($0, RLENGTH + 1); print $20}' "/proc/$1/stat" 2>/dev/null || echo 0
}

log_event() {
	# $1=pid $2=starttime $3=event $4=path $5=ok
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"%s","path":"%s","ok":%s}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" "$5" >>"$LOG"
}

log_exit() {
	# $1=pid $2=starttime $3=path $4=exit status. ok is always true: the
	# fact recorded is that the process was observed to exit.
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"exit","path":"%s","ok":true,"status":%s}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" >>"$LOG"
}

run_with_ld_debug() {
	# $1=path, remaining args are passed through to it.
	path="$1"
	shift
	fifo="/tmp/ld-debug.$$"
	rm -f "$fifo"
	mkfifo "$fifo" || return 1

	# The redirection to the FIFO happens in the background child, so this
	# shell is not blocked waiting for a reader; the child blocks on its
	# open until the read loop below opens the other end.
	LD_DEBUG=libs "$path" "$@" >/dev/null 2>"$fifo" &
	pid=$!
	st="$(starttime_of "$pid")"
	log_event "$pid" "$st" "exec" "$path" "true"

	# Each "calling init:" line names one shared object the loader actually
	# activated for this invocation (not merely one it considered). Reading
	# the FIFO in the foreground means each is logged as it is emitted,
	# while the child still runs.
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
	log_exit "$pid" "$st" "$path" "$rc"
	rm -f "$fifo"
}

while true; do
	run_with_ld_debug /usr/bin/curl -s -o /dev/null https://example.com
	run_with_ld_debug /usr/bin/git --version
	sleep 5
done
