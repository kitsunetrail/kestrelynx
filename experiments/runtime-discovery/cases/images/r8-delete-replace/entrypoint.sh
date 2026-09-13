#!/bin/sh
# Sets up the three R8 processes and records each in /var/log/usage.jsonl,
# one JSON object per line: {ts, pid, starttime, event, path, ok}, plus a
# "meta" line per copied file naming its source package, version, sha256,
# and inode before/after the operation. None of the three processes ever
# logs an "exit"/"dlclose": each is meant to stay running (or loaded) for
# the rest of the observation window, so its usage interval is open-ended.
#
# Each of the three operations also logs a completion line
# ({"event":"stage","stage":"<name>","done":true}) once the operation
# itself has finished, not merely once its process started. A reader
# waiting for this case to be ready waits for all three of those, because
# the state this case exists to create (unlinked exe, unlinked library,
# replaced library) does not exist until then.
set -eu

LOG=/var/log/usage.jsonl
: >"$LOG"

now_ts() {
	# RFC3339 with nanoseconds: the operations below complete within
	# milliseconds of the process that they act on starting, and a
	# whole-second stamp would place both at the same instant.
	date -u +%Y-%m-%dT%H:%M:%S.%NZ
}

log_event() {
	printf '{"ts":"%s","pid":%s,"starttime":%s,"event":"%s","path":"%s","ok":%s}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" "$5" >>"$LOG"
}

log_meta() {
	# $1=path $2=package $3=version $4=sha256 $5=inode_before $6=inode_after
	printf '{"ts":"%s","event":"meta","path":"%s","package":"%s","version":"%s","sha256":"%s","inode_before":"%s","inode_after":"%s"}\n' \
		"$(now_ts)" "$1" "$2" "$3" "$4" "$5" "$6" >>"$LOG"
}

log_stage() {
	# $1=stage name. Emitted only after the operation has actually
	# completed.
	printf '{"ts":"%s","event":"stage","stage":"%s","done":true}\n' \
		"$(now_ts)" "$1" >>"$LOG"
}

starttime_of() {
	# Field 22 (starttime) of /proc/<pid>/stat. Field 2 (comm) is
	# parenthesized and may contain ")" itself, so the greedy match finds
	# the *last* ")" and the remaining field 20 is overall field 22.
	awk '{match($0, /.*\)/); $0 = substr($0, RLENGTH + 1); print $20}' "/proc/$1/stat" 2>/dev/null || echo 0
}

real_sqlite="$(ls /usr/lib/*/libsqlite3.so.0 2>/dev/null | head -1)"
if [ -z "$real_sqlite" ]; then
	echo "entrypoint.sh: could not find libsqlite3.so.0 under /usr/lib/*; is libsqlite3-0 installed?" >&2
	exit 1
fi
sqlite_pkg="$(dpkg -S "$real_sqlite" 2>/dev/null | cut -d: -f1 | head -1)"
sqlite_ver="$(dpkg-query -W -f='${Version}' "$sqlite_pkg" 2>/dev/null || true)"
sqlite_sha256="$(sha256sum "$real_sqlite" | cut -d' ' -f1)"

# 1. exe unlink: run a copy of server-a, then unlink the running copy.
cp /opt/bin/server-a-src /opt/bin/server-a-run
server_sha256="$(sha256sum /opt/bin/server-a-src | cut -d' ' -f1)"
log_meta "/opt/bin/server-a-run" "" "" "$server_sha256" "$(stat -c %i /opt/bin/server-a-run)" ""
/opt/bin/server-a-run &
pid1=$!
st1="$(starttime_of "$pid1")"
log_event "$pid1" "$st1" "exec" "/opt/bin/server-a-run" "true"
sleep 1
rm -f /opt/bin/server-a-run
log_stage "exe_unlinked"

# 2. lib unlink: dlopen a copy, then unlink it while still mapped.
mkdir -p /opt/lib
cp "$real_sqlite" /opt/lib/libsqlite3.so.0
inode_before2="$(stat -c %i /opt/lib/libsqlite3.so.0)"
log_meta "/opt/lib/libsqlite3.so.0" "$sqlite_pkg" "$sqlite_ver" "$sqlite_sha256" "$inode_before2" ""
/opt/bin/loader /opt/lib/libsqlite3.so.0 &
pid2=$!
st2="$(starttime_of "$pid2")"
log_event "$pid2" "$st2" "dlopen" "/opt/lib/libsqlite3.so.0" "true"
sleep 1
rm -f /opt/lib/libsqlite3.so.0
log_stage "lib_unlinked"

# 3. lib replace: dlopen a copy, then atomically replace the same path via
# a same-directory temp file and rename(2) (not truncate/overwrite, which
# would keep the same inode and never exercise the replacement condition).
mkdir -p /opt/lib2
cp "$real_sqlite" /opt/lib2/libsqlite3.so.0
inode_before3="$(stat -c %i /opt/lib2/libsqlite3.so.0)"
log_meta "/opt/lib2/libsqlite3.so.0" "$sqlite_pkg" "$sqlite_ver" "$sqlite_sha256" "$inode_before3" ""
/opt/bin/loader /opt/lib2/libsqlite3.so.0 &
pid3=$!
st3="$(starttime_of "$pid3")"
log_event "$pid3" "$st3" "dlopen" "/opt/lib2/libsqlite3.so.0" "true"
sleep 1
tmp3="$(mktemp /opt/lib2/.replace.XXXXXX)"
cp /opt/bin/server-a-src "$tmp3"
mv "$tmp3" /opt/lib2/libsqlite3.so.0
inode_after3="$(stat -c %i /opt/lib2/libsqlite3.so.0)"
log_meta "/opt/lib2/libsqlite3.so.0" "$sqlite_pkg" "$sqlite_ver" "$sqlite_sha256" "$inode_before3" "$inode_after3"
log_stage "lib_replaced"

echo "entrypoint.sh: all three operations complete; usage.jsonl has $(wc -l <"$LOG") lines"
wait
