#!/usr/bin/env bash
# What: small shell helpers shared by load-run.sh, watch-run.sh and privilege-run.sh.
# This file is sourced, never run directly: `. experiments/runtime-discovery/tools/load-lib.sh`
# from a script that already has `set -uo pipefail` in effect. Every reading function prints
# nothing and returns non-zero on failure, so a caller can tell a real zero from a file it
# could not read (never silently substituting one for the other).
#
# Cgroup v2 directory creation, controller enablement, process placement and safe removal
# (via cgroup.events' own "populated" flag, never a file-size-based emptiness guess - see
# the Go source for exactly why cgroup.procs' own stat size cannot be used for this) all
# live in the Go `supervise` subcommand now (experiments/runtime-discovery/supervise.go),
# not here: a bash-level reimplementation of that same lifecycle around a subshell's own
# "$$" cannot actually place a process into a cgroup atomically at all (bash's "$$" inside
# "( ... )" is the PARENT shell's pid, not the subshell's own - "$BASHPID" would be, but
# even that still runs a shell between the write and the exec, an inherent race a Go
# clone3(CLONE_INTO_CGROUP) call does not have). cgroup_cpu_usage_usec below remains here
# only because watch-run.sh polls a cgroup's live CPU on its own 10-second schedule, a
# different need from the four fixed checkpoints load-run.sh reads via the `cgroup-stat`
# subcommand (which also reads memory.peak and cgroup.events - watch-run.sh does not need
# either, so no bash-level equivalent of those two is kept here).

# cgroup_cpu_usage_usec prints cpu.stat's usage_usec for the given cgroup v2 directory.
# This field is populated by the cgroup core itself and is present whether or not the "cpu"
# controller is enabled, so no controller needs to be requested for this one.
cgroup_cpu_usage_usec() {
	local dir="$1" line
	line=$(awk '/^usage_usec/{print $2}' "$dir/cpu.stat" 2>/dev/null)
	[ -n "$line" ] || return 1
	printf '%s\n' "$line"
}

# dir_size_bytes prints a directory's total on-disk size in bytes, or nothing (and a
# non-zero exit) when it does not exist yet.
dir_size_bytes() {
	[ -d "$1" ] || return 1
	du -sb "$1" 2>/dev/null | awk '{print $1}'
}

# fs_free_bytes prints the free space (bytes) of the filesystem containing the given path.
fs_free_bytes() {
	df --output=avail -B1 "$1" 2>/dev/null | tail -n1 | tr -d ' '
}

# count_lost_notifications counts lines matching bpftrace's own loss-notification message
# ("Lost <N> events") in a trace stderr log, regardless of the UTC timestamp this harness
# prefixes each line with. It returns 0 (with output "0") for a file that exists but has no
# such line, and fails only when the file itself cannot be read.
count_lost_notifications() {
	local f="$1"
	[ -r "$f" ] || return 1
	grep -cE 'Lost [0-9]+ events' "$f" 2>/dev/null || true
}

# sum_lost_events adds up the <N> in every "Lost <N> events" line of a trace stderr log,
# the actual count of events those notifications stand for (see count_lost_notifications
# for the notification count itself, a different and always-smaller number).
sum_lost_events() {
	local f="$1"
	[ -r "$f" ] || return 1
	grep -oE 'Lost [0-9]+ events' "$f" 2>/dev/null | awk '{s+=$2} END{print s+0}'
}

# stop_process sends signal $2 to pid $1, waits up to $3 seconds (default 15) for it to
# actually exit, and sends SIGKILL as a last resort if it has not - the bounded-wait/
# kill-as-last-resort path every stop this harness performs on a process it started should
# go through, rather than firing a signal and moving on without ever confirming the process
# actually left. Prints its own progress to stderr (never assumes a caller-defined "log"
# function); a caller that wants these lines in its own log file pipes/tees this call.
# Usage: stop_process <pid> <signal> [timeout seconds] [label]
stop_process() {
	local pid="$1" sig="$2" timeout="${3:-15}" label="${4:-process}" waited=0
	[ -n "$pid" ] && [ "$pid" != "-" ] || return 0
	kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; return 0; }
	kill -"$sig" "$pid" 2>/dev/null
	while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$timeout" ]; do sleep 1; waited=$((waited + 1)); done
	if kill -0 "$pid" 2>/dev/null; then
		echo "stop_process: $label pid $pid did not exit within ${timeout}s of SIG$sig; sending SIGKILL" >&2
		kill -KILL "$pid" 2>/dev/null
		waited=0
		while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 5 ]; do sleep 1; waited=$((waited + 1)); done
		if kill -0 "$pid" 2>/dev/null; then
			echo "stop_process: $label pid $pid STILL present after SIGKILL and a 5s wait" >&2
		fi
	fi
	wait "$pid" 2>/dev/null
}

# monotonic_now prints seconds since boot on the kernel's own monotonic (BOOTTIME) clock,
# read from /proc/uptime's first field (10ms resolution) - never CLOCK_REALTIME/date, which
# a sampling loop dividing a CPU delta by elapsed time must not use: a wall-clock step (NTP)
# would silently distort every CPU-per-core figure computed against it. 10ms resolution is
# adequate here because callers (watch-run.sh) sample on the order of 10 real seconds apart,
# not the sub-100ms operations os-ops.sh's own run_cmd times with a finer wall-clock reading.
monotonic_now() {
	awk '{print $1}' /proc/uptime 2>/dev/null
}
