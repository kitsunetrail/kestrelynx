#!/usr/bin/env bash
# What: safety monitor for one load-run.sh run. Samples every 10 seconds (KL_WATCH_INTERVAL)
# and, on a sustained problem, writes a stop request to the shared stop file that both
# load-run.sh's own controller loop and the Go `supervise` processes running the tracer and
# collector already poll - this script never signals the tracer/collector/web-probe loop
# itself (only the runner and supervise do that, through their own bounded stop sequences).
# Every sample is written to <run dir>/watch.jsonl whether or not it trips a threshold, so a
# run's own resource trace is available even when nothing stopped it.
#
# Unlike the runner's own tracer/collector supervision, THIS process's own job does not end
# when a stop is requested: it keeps sampling disk usage and (while the tracer's own cgroup
# still exists) its CPU for as long as the tracer or collector is actually still running,
# including the whole bounded SIGINT/SIGTERM/SIGKILL sequence supervise itself performs
# after a stop request - a run cannot be considered safely stopped, from a disk/CPU-limit
# point of view, on the mere fact that a stop was requested, only once the processes that
# might still be consuming disk or CPU have actually gone.
#
# Usage (from the repository root, normally started by load-run.sh itself, BEFORE the
# tracer or collector exist yet - see "targets file" below):
#   bash experiments/runtime-discovery/tools/watch-run.sh <run dir> <out root dir> <targets file> <stop file>
#
#   run dir       = the specific run's own output directory (watch.jsonl and run.log live here)
#   out root dir  = the shared output directory this run's directory sits under (for the
#                   all-runs size limit and the free-space check)
#   targets file  = a small key=value file load-run.sh writes once, before this script
#                   starts (tracer/collector pids are already known by then in the current
#                   design, but this script re-reads the file every sample regardless, so a
#                   caller that wants to update it later still can)
#   stop file     = the shared stop-request file; a non-empty existing reason (written by
#                   load-run.sh's own window-elapsed/operator-stop path) is left alone, and
#                   this script's own detected conditions are only ever written if the file
#                   is not already non-empty
#
# Targets file keys (each optional; "-" or absent means "not applicable"):
#   tracer_pid=<pid>            collector_pid=<pid>
#   tracer_cgroup=<path>        trace_err=<path>
#   web_timing=<path>
#   expect_tracer=0|1           expect_collector=0|1
#   min_until_epoch=<epoch>     residual_unconfirmed=0|1
#   termination_confirmed_file=<path>
#   watch_until_epoch=<epoch>
#
# expect_tracer/expect_collector say which processes this run is GOING to have, before they
# exist. They are what lets this script keep watching through a preparation phase in which a
# pid is still "-": without them, a caller that starts the watcher first (as it should, so
# the tracer's own compile and attach are watched too) would look, on the very first sample,
# exactly like a run whose processes have all already finished. A targets file that names
# neither key falls back to the older rule: exit once every pid it has ever named is gone.
#
# min_until_epoch is the caller's own observation window end. Watching must not stop at the
# last process this script was given a pid for: a collector takes its final sample one
# interval before the window closes and then exits, and the rest of that window - where a web
# failure or a capacity problem is just as much a reason to stop the run - would otherwise go
# unwatched.
#
# termination_confirmed_file is how the caller says that every target's termination has
# actually been established. Until that file exists and is non-empty, this script treats
# termination as UNDETERMINED and will not stop on its own, whatever the pids look like: a
# supervisor vanishing says nothing about the descendants its child may have left behind, and
# the moment those might still be consuming CPU and disk is exactly the moment a monitor is
# worth having. A caller using the expect_* keys must therefore name this file; a caller that
# names neither (the older shape) keeps the older rule. residual_unconfirmed=1 is the caller
# saying it has finished checking and the answer was no.
#
# watch_until_epoch is the single absolute bound, and it is the ONE way this script stops
# without having been told: a caller that dies without ever confirming - or before it ever
# announced the pids it expected - cannot leave this running forever. Reaching it exits 3,
# not 0, and writes WATCH_EXIT to the run log with which condition was still unmet, so
# "gave up waiting to be told" is never read as "the run finished cleanly".
#
# Stop conditions (each threshold overridable by the env var named), checked every sample:
#   tracer CPU > KL_WATCH_CPU_CORES core-equivalents (default 1), CPU/real-elapsed-time
#     computed from two monotonic readings (never a fixed assumed interval), for 3
#     consecutive successfully-measured samples
#   the "Lost N events" notification count increases for 3 consecutive samples
#   this run's own directory exceeds KL_WATCH_RUN_BYTES (default 1 GiB)
#   the shared output directory exceeds KL_WATCH_ROOT_BYTES (default 4 GiB)
#   free space on the output filesystem drops below KL_WATCH_FREE_BYTES (default 20 GiB)
#   KL_WATCH_WEB_FAILURES (default 3) consecutive web_timing.jsonl RESPONSES - not sample
#     batches - each failed, processed strictly in the order they were recorded and judged
#     at the response that reaches the threshold, so a later success in the same batch
#     cannot erase a streak that already reached it
#
# A hard wall-clock deadline for the SUPERVISED PROCESSES is enforced independently by
# supervise itself (-deadline), not by this script: duplicating it here would only risk the
# two disagreeing about when a run is "stuck". watch_until_epoch below is a different thing
# - a bound on how long THIS script waits to be told the run is over.
#
# A cgroup read failure resets that metric's own baseline (the next successful read starts a
# fresh not-yet-a-delta state) rather than letting a stale baseline understate or overstate a
# delta spanning more than one real sampling interval.
set -uo pipefail
cd "$(dirname "$0")/../../.."
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./load-lib.sh
. "$here/load-lib.sh"

USAGE="Usage: bash experiments/runtime-discovery/tools/watch-run.sh <run dir> <out root dir> <targets file> <stop file>"
[ $# -ge 4 ] || { echo "$USAGE" >&2; exit 2; }
R="$1"; OUTROOT="$2"; TARGETS="$3"; STOPFILE="$4"
[ -d "$R" ] || { echo "watch-run: run dir $R does not exist" >&2; exit 2; }

INTERVAL="${KL_WATCH_INTERVAL:-10}"
CPU_CORES_LIMIT="${KL_WATCH_CPU_CORES:-1}"
RUN_BYTES_LIMIT="${KL_WATCH_RUN_BYTES:-1073741824}"      # 1 GiB
ROOT_BYTES_LIMIT="${KL_WATCH_ROOT_BYTES:-4294967296}"    # 4 GiB
FREE_BYTES_LIMIT="${KL_WATCH_FREE_BYTES:-21474836480}"   # 20 GiB
WEB_FAILURES_LIMIT="${KL_WATCH_WEB_FAILURES:-3}"

WATCHLOG="$R/watch.jsonl"
RUNLOG="$R/run.log"

pid_alive() { [ "$1" != "-" ] && [ -n "$1" ] && [ "$1" -gt 0 ] 2>/dev/null && kill -0 "$1" 2>/dev/null; }

tracer_pid="-"; collector_pid="-"; tracer_cgroup="-"; trace_err="-"; web_timing="-"
expect_tracer=""; expect_collector=""
min_until_epoch=""; residual_unconfirmed=""
termination_confirmed_file=""; watch_until_epoch=""
seen_tracer=0; seen_collector=0
read_targets() {
	tracer_pid="-"; collector_pid="-"; tracer_cgroup="-"; trace_err="-"; web_timing="-"
	expect_tracer=""; expect_collector=""
	min_until_epoch=""; residual_unconfirmed=""
	termination_confirmed_file=""; watch_until_epoch=""
	[ -r "$TARGETS" ] || return 0
	# shellcheck disable=SC1090
	. "$TARGETS" 2>/dev/null || true
	[ "$tracer_pid" != "-" ] && seen_tracer=1
	[ "$collector_pid" != "-" ] && seen_collector=1
	return 0
}

# every_expected_process_is_gone is this script's own exit condition: every process this run
# said it would have has been seen running and has since gone. A process that is expected
# but has not appeared yet keeps this script alive, which is the whole point of starting it
# before the tracer exists.
every_expected_process_is_gone() {
	if [ -z "$expect_tracer" ] && [ -z "$expect_collector" ]; then
		# Older targets file: fall back to "every pid it has ever named is gone".
		{ [ "$tracer_pid" != "-" ] || [ "$collector_pid" != "-" ]; } \
			&& ! pid_alive "$tracer_pid" && ! pid_alive "$collector_pid"
		return $?
	fi
	local any=0
	if [ "$expect_tracer" = 1 ]; then
		any=1
		{ [ "$seen_tracer" = 1 ] && ! pid_alive "$tracer_pid"; } || return 1
	fi
	if [ "$expect_collector" = 1 ]; then
		any=1
		{ [ "$seen_collector" = 1 ] && ! pid_alive "$collector_pid"; } || return 1
	fi
	[ "$any" = 1 ]
}

# termination_is_confirmed answers "has the caller established that every target it started
# actually stopped?". The answer starts as no and stays no until the caller says otherwise:
# the pids being gone is not the answer, and neither is the absence of bad news.
termination_is_confirmed() {
	if [ -z "$expect_tracer" ] && [ -z "$expect_collector" ]; then
		return 0  # older targets file: it makes no such claim either way
	fi
	[ "$residual_unconfirmed" = 1 ] && return 1
	[ -n "$termination_confirmed_file" ] && [ -s "$termination_confirmed_file" ]
}

# watch_bound_reached is the ONE way this script stops without the caller having confirmed
# anything, and it is deliberately asked first, ahead of every other condition. The bound
# exists for exactly the situations the other conditions cannot end: a run that died before
# it ever announced the pids it expected (they stay "-" forever, so "every expected process
# has been seen and gone" can never become true), a supervisor still lingering, a
# configuration that expects no process at all. A bound evaluated after those is a bound
# that, in every case it was added for, never applies.
watch_bound_reached() {
	[ -n "$watch_until_epoch" ] || return 1
	[ "$(date -u +%s)" -ge "$watch_until_epoch" ] 2>/dev/null
}

# watch_undetermined_reason says, in the run log, which condition was still unmet when the
# bound was reached - the difference between "the run finished and nobody told us" and "a
# process this run started is still there" matters to whoever reads it afterwards.
watch_undetermined_reason() {
	local parts=""
	if [ "${expect_tracer:-0}" != 1 ] && [ "${expect_collector:-0}" != 1 ]; then
		parts="this run expects no supervised process of its own, so nothing here can ever say it has finished"
	elif ! every_expected_process_is_gone; then
		parts="not every expected process has been seen to finish (expect_tracer=${expect_tracer:-unset}"
		parts="$parts expect_collector=${expect_collector:-unset} tracer_pid=$tracer_pid collector_pid=$collector_pid"
		parts="$parts seen_tracer=$seen_tracer seen_collector=$seen_collector)"
	fi
	if ! termination_is_confirmed; then
		[ -n "$parts" ] && parts="$parts; "
		if [ "$residual_unconfirmed" = 1 ]; then
			parts="${parts}the runner reported that residual tasks could not be confirmed gone"
		elif [ -z "$termination_confirmed_file" ]; then
			parts="${parts}the runner never named a termination-confirmation file"
		else
			parts="${parts}the runner never wrote its termination confirmation ($termination_confirmed_file)"
		fi
	fi
	if [ -z "$parts" ]; then
		parts="the observation window had not ended (min_until_epoch=${min_until_epoch:-unset})"
	fi
	printf '%s' "$parts"
}

# watch_may_exit is the NORMAL end of this script, and it requires all of it: every process
# this run expected has been seen and gone, the caller's own observation window has ended,
# and the caller has confirmed that everything it started actually terminated.
watch_may_exit() {
	every_expected_process_is_gone || return 1
	local now
	now="$(date -u +%s)"
	if [ -n "$min_until_epoch" ] && [ "$now" -lt "$min_until_epoch" ] 2>/dev/null; then
		return 1
	fi
	termination_is_confirmed
}

request_stop() {
	local reason="$1"
	[ -s "$STOPFILE" ] && return 0
	printf '%s\n' "$reason" >"$STOPFILE"
	echo "$(date -u +%FT%T.%NZ) STOP_REQUESTED: $reason" >>"$RUNLOG"
}

prev_cpu_usec=""; prev_cpu_mono=""
prev_lost_notifications=""
web_lines_seen=0
web_consecutive_failures=0
web_threshold_hit=""
cpu_over_streak=0
lost_increase_streak=0

while true; do
	sleep "$INTERVAL"
	read_targets
	ts="$(date -u +%FT%T.%NZ)"

	cpu_cores="null"; cpu_state="not_measured: no tracer cgroup for this run"
	if [ "$tracer_cgroup" != "-" ]; then
		usec="$(cgroup_cpu_usage_usec "$tracer_cgroup" 2>/dev/null || true)"
		mono="$(monotonic_now)"
		if [ -n "$usec" ] && [ -n "$mono" ]; then
			if [ -n "$prev_cpu_usec" ] && [ -n "$prev_cpu_mono" ]; then
				delta_usec=$((usec - prev_cpu_usec))
				elapsed_s="$(awk -v a="$prev_cpu_mono" -v b="$mono" 'BEGIN{d=b-a; if(d<=0)d="NA"; print d}')"
				if [ "$elapsed_s" = "NA" ]; then
					cpu_state="not_measured: monotonic clock did not advance between samples"
				else
					cpu_cores="$(awk -v d="$delta_usec" -v e="$elapsed_s" 'BEGIN{printf "%.3f", (d/1000000)/e}')"
					cpu_state="measured"
				fi
			else
				cpu_state="not_measured: first sample, no prior reading to take a delta against"
			fi
			prev_cpu_usec="$usec"; prev_cpu_mono="$mono"
		else
			cpu_state="not_measured: could not read $tracer_cgroup/cpu.stat or the monotonic clock"
			prev_cpu_usec=""; prev_cpu_mono=""
		fi
	fi

	lost_notif="null"; lost_state="not_measured: no trace stderr file for this run"
	lost_increased="false"
	if [ "$trace_err" != "-" ]; then
		n="$(count_lost_notifications "$trace_err" 2>/dev/null || true)"
		if [ -n "$n" ]; then
			lost_notif="$n"; lost_state="measured"
			if [ -n "$prev_lost_notifications" ] && [ "$n" -gt "$prev_lost_notifications" ]; then
				lost_increased="true"
			fi
			prev_lost_notifications="$n"
		else
			lost_state="not_measured: could not read $trace_err"
			prev_lost_notifications=""
		fi
	fi

	run_bytes="$(dir_size_bytes "$R" 2>/dev/null || true)"; [ -n "$run_bytes" ] || run_bytes="null"
	root_bytes="$(dir_size_bytes "$OUTROOT" 2>/dev/null || true)"; [ -n "$root_bytes" ] || root_bytes="null"
	free_bytes="$(fs_free_bytes "$OUTROOT" 2>/dev/null || true)"; [ -n "$free_bytes" ] || free_bytes="null"

	# Web responses are processed one at a time, strictly in the order web_timing.jsonl's
	# own append order recorded them, and the threshold is evaluated AT the response that
	# reaches it, not after the whole batch: a batch of "fail, fail, success" that takes an
	# already-2-long streak to 3 has reached the limit at its first line, and a later
	# success in the same batch must not erase that. web_threshold_hit latches the streak
	# length at the moment it was reached, so the stop decision below is made on what
	# actually happened rather than on where the streak happened to end up.
	#
	# Only the lines already counted by this sample's own wc -l are read: the probe loop
	# appends to this file concurrently, so reading to end-of-file instead would process
	# lines this sample never counted and then skip them for good on the next one.
	if [ "$web_timing" != "-" ] && [ -r "$web_timing" ]; then
		total_lines="$(wc -l <"$web_timing" 2>/dev/null || echo 0)"
		if [ "$total_lines" -gt "$web_lines_seen" ]; then
			new_lines=$((total_lines - web_lines_seen))
			while IFS= read -r line; do
				case "$line" in
					*'"ok":true'*) web_consecutive_failures=0 ;;
					*)
						web_consecutive_failures=$((web_consecutive_failures + 1))
						if [ "$web_consecutive_failures" -ge "$WEB_FAILURES_LIMIT" ]; then
							web_threshold_hit="$web_consecutive_failures"
						fi
						;;
				esac
			done < <(tail -n "+$((web_lines_seen + 1))" "$web_timing" | head -n "$new_lines")
			web_lines_seen="$total_lines"
		fi
	fi

	printf '{"ts":"%s","tracer_cpu_cores":%s,"tracer_cpu_state":"%s","lost_notifications_total":%s,"lost_notifications_state":"%s","run_dir_bytes":%s,"out_root_bytes":%s,"free_bytes":%s,"web_consecutive_failures":%s}\n' \
		"$ts" "$cpu_cores" "$cpu_state" "$lost_notif" "$lost_state" "$run_bytes" "$root_bytes" "$free_bytes" "$web_consecutive_failures" >>"$WATCHLOG"

	# Immediate (single-sample) stop conditions: capacity, not a transient spike.
	if [ "$run_bytes" != "null" ] && [ "$run_bytes" -gt "$RUN_BYTES_LIMIT" ]; then
		request_stop "run directory $run_bytes bytes exceeds the ${RUN_BYTES_LIMIT}-byte per-run limit"
	fi
	if [ "$root_bytes" != "null" ] && [ "$root_bytes" -gt "$ROOT_BYTES_LIMIT" ]; then
		request_stop "output directory $root_bytes bytes exceeds the ${ROOT_BYTES_LIMIT}-byte shared limit"
	fi
	if [ "$free_bytes" != "null" ] && [ "$free_bytes" -lt "$FREE_BYTES_LIMIT" ]; then
		request_stop "free space $free_bytes bytes is below the ${FREE_BYTES_LIMIT}-byte minimum"
	fi

	# 3-consecutive-sample stop conditions: a single high sample is not sustained load.
	if [ "$cpu_state" = "measured" ] && awk -v c="$cpu_cores" -v l="$CPU_CORES_LIMIT" 'BEGIN{exit !(c>l)}'; then
		cpu_over_streak=$((cpu_over_streak + 1))
	else
		cpu_over_streak=0
	fi
	if [ "$cpu_over_streak" -ge 3 ]; then
		request_stop "tracer CPU exceeded ${CPU_CORES_LIMIT} core-equivalent(s) for 3 consecutive samples (last: $cpu_cores)"
	fi

	if [ "$lost_increased" = "true" ]; then
		lost_increase_streak=$((lost_increase_streak + 1))
	else
		lost_increase_streak=0
	fi
	if [ "$lost_increase_streak" -ge 3 ]; then
		request_stop "lost-event notifications increased for 3 consecutive samples (total now $lost_notif)"
	fi

	if [ -n "$web_threshold_hit" ]; then
		request_stop "$WEB_FAILURES_LIMIT consecutive web responses failed (streak reached $web_threshold_hit)"
	fi

	# This script keeps sampling through a requested stop, including the whole bounded
	# stop sequence supervise itself performs on the tracer/collector: it only exits once
	# every process this run expected to have has gone AND the run's own observation window
	# has ended AND the runner has confirmed every target's termination (config=none, which
	# expects neither process, is watched - for disk/space only - until load-run.sh kills
	# this loop itself once its own window/stop handling is done).
	# The bound first, and on its own exit path: reaching it is not this run finishing, it
	# is this script giving up on being told, and the two must not be read as the same thing.
	if watch_bound_reached; then
		echo "$(date -u +%FT%T.%NZ) WATCH_EXIT: reached the watch bound ($watch_until_epoch) with termination UNDETERMINED; $(watch_undetermined_reason)" >>"$RUNLOG"
		exit 3
	fi
	if watch_may_exit; then
		exit 0
	fi
done
