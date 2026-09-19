#!/bin/sh
# Starts the operational-processing loop and then the resident program.
#
# strace is always installed in this image so the ground-truth tool's
# dedicated run can use the exact same image ID as an ordinary measurement
# run; it is invoked only when TRACE_MODE=1, an environment variable no
# ordinary measurement run sets.
#
# In trace mode, strace's own tracee has to be a process that then forks
# BOTH the operational-processing loop and the resident program, because
# strace -f follows every descendant of the process it starts, forever —
# starting the loop outside strace's own tracee would leave every command
# it execs unobserved. Backgrounding the loop and then exec-ing the
# resident program inside that one traced shell keeps both subtrees under
# the same trace.
#
# -D keeps strace itself out of the traced process's own ancestry (it runs
# as a detached grandchild instead of the tracee's parent), so the
# resident program stays PID 1 and receives SIGTERM directly from "docker
# stop" — without it, a graceful stop only reaches strace, which does not
# relay the signal, and an exit-time dump the program writes on SIGTERM
# never runs.
set -e

if [ "${TRACE_MODE:-0}" = "1" ]; then
	mkdir -p /var/log/strace
	# clone/clone3/fork/vfork are traced too, alongside the syscalls the
	# ground-truth tool actually credits as usage evidence, so it can
	# rebuild which process was ultimately created by which - the only way
	# it has to tell a short-lived helper a resident process forked from
	# one it exec'd itself, and to attribute a helper's own file opens
	# correctly even when that helper never execs anything of its own.
	exec strace -D -f -ff -tt -e trace=execve,execveat,openat,openat2,open,clone,clone3,fork,vfork \
		-o /var/log/strace/trace -- \
		sh -c '/os-ops.sh & exec python3 -u /server.py'
fi
/os-ops.sh &
exec python3 -u /server.py
