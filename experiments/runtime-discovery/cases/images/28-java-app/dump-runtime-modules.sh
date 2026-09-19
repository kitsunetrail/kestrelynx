#!/bin/sh
# Appends one JSON Lines record per class the JVM loaded from a jar file,
# out of the new tail of its own -Xlog:class+load=info output, to
# runtime-modules.jsonl. This is the only practical way to get this
# runtime's own view of what it loaded: the JVM offers no ordinary API a
# running program can call to list its own loaded classes and their
# source jars, but it can be told to log every class load to a file, and
# that file is this program's own record of what it read, independent of
# the harness's sampling or event collection.
#
# Argument: the phase name for this snapshot point (startup, after_lazy,
# final, ...). Only lines appended since the previous call are read, using
# a line-count marker, so calling this several times over one run reports
# each phase's own new activity rather than repeating everything before it.
set -u

CLASSLOG=/var/log/jvm-class-load.log
OUT=/var/log/runtime-modules.jsonl
MARK=/tmp/jvm-class-load.mark
PHASE="${1:-unknown}"

[ -r "$CLASSLOG" ] || exit 0
last=0
[ -r "$MARK" ] && last="$(cat "$MARK")"
total="$(wc -l <"$CLASSLOG" 2>/dev/null || echo 0)"
[ "$total" -gt "$last" ] || exit 0

ts="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
tail -n "+$((last + 1))" "$CLASSLOG" \
	| sed -n 's/^.*\]\s*\([A-Za-z0-9_$.]*\)\s*source:\s*file:\(.*\)$/\1\t\2/p' \
	| while IFS="$(printf '\t')" read -r cls jar; do
		printf '{"ts":"%s","phase":"%s","runtime":"java","class":"%s","jar":"%s"}\n' \
			"$ts" "$PHASE" "$cls" "$jar" >>"$OUT"
	done
echo "$total" >"$MARK"
