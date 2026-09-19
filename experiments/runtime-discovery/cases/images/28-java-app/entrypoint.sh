#!/bin/sh
# Starts the operational-processing loop and then the resident program.
# See case 26's entrypoint.sh for why strace is always installed but only
# invoked under TRACE_MODE=1, and why the operational loop has to be
# forked from inside strace's own tracee rather than started outside it.
#
# -D keeps strace itself out of the traced process's own ancestry (it runs
# as a detached grandchild instead of the tracee's parent), so the
# resident program stays PID 1 and receives SIGTERM directly from "docker
# stop" — without it, a graceful stop only reaches strace, which does not
# relay the signal, and the shutdown hook's exit-time dump never runs.
set -e

JAVA_CP=/app/app.jar:/app/libs/commons-lang3-3.14.0.jar:/app/libs/commons-text-1.11.0.jar:/app/libs/gson-2.10.1.jar:/app/libs/slf4j-api-2.0.13.jar:/app/libs/slf4j-simple-2.0.13.jar
# -XX:-UsePerfData turns off the JVM's own hsperfdata bookkeeping file
# (a per-process file under /tmp/hsperfdata_<user>/<pid> for jps/jstat to
# read), which it creates by fchdir-ing into that directory and then
# opening its own pid-named file through a now-relative AT_FDCWD path -
# a syscall this design's own strace-based ground truth does not trace,
# so that file would otherwise show up as an unresolved path with
# nothing to do with any bundled package's own usage.
JAVA_ARGS="-XX:-UsePerfData -Xlog:class+load=info:file=/var/log/jvm-class-load.log:uptime,level,tags -cp $JAVA_CP App"

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
		sh -c "/os-ops.sh & exec java $JAVA_ARGS"
fi
/os-ops.sh &
exec java $JAVA_ARGS
