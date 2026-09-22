#!/usr/bin/env bash
# What: exercises the four capability-sensitive operations this harness's event side needs
# (BPF program load, tracepoint attach, perf buffer creation/reading, cgroup-id map
# creation) under one named privilege condition, using the Go `supervise` subcommand to run
# each one as the target user and verify - from the kernel's own /proc, not from this
# script's own assumptions - that the condition was actually in effect (real exe, real
# non-root effective UID, real CapEff) before any operation result is trusted at all. A
# condition whose own verification fails is recorded as "condition_not_established",
# separate from and never confused with an operation's own success/failure/unreached.
#
# Usage (from the repository root, as root):
#   sudo bash experiments/runtime-discovery/tools/privilege-run.sh <root|bpf_perfmon|bpf_perfmon_dac|bpf_perfmon_dac_override|sysadmin>
#
#   root             - runs every operation as root, through this same recording path,
#                       with no capabilities applied to either private binary copy
#   bpf_perfmon      - cap_bpf,cap_perfmon=ep on both private binary copies
#   bpf_perfmon_dac  - the above plus cap_dac_read_search=ep
#   bpf_perfmon_dac_override - the above plus cap_dac_override=ep (only to get past bpftrace's own
#                      pre-check, which refuses to start without CAP_DAC_OVERRIDE; the result
#                      then shows what the kernel itself allows once the tool is willing to run)
#   sysadmin         - cap_sys_admin=ep on both private binary copies
#
# Every non-root condition runs as KL_PRIV_USER, an environment variable naming an
# already-existing unprivileged user. This script never creates one, and refuses a name
# that resolves to uid 0 (supervise itself also refuses this independently):
#   sudo useradd -M -s /usr/sbin/nologin kltest   # once, outside this script
#   sudo KL_PRIV_USER=kltest bash experiments/runtime-discovery/tools/privilege-run.sh bpf_perfmon
#
# What this script never does: modify the system-installed bpftrace binary (every
# capability is applied to a private copy under a dedicated /var/tmp working directory, not
# under this repository), modify any sysctl, or modify runtime-events' own built copy
# (out/runtime-events) - the cgroup-id-map operation also runs a private, separately-capped
# copy of it.
#
# Why /var/tmp rather than under this repository's own out/ directory for the private
# binary copies: this repository normally lives under a login-only home directory (mode
# 0750 or tighter), which KL_PRIV_USER - a different, unprivileged account - cannot
# traverse into at all regardless of what any leaf directory's own permissions say.
# /var/tmp (mode 1777, the same sticky-world-writable shape as /tmp) is reachable by any
# local user.
#
# How each operation's own result is decided: from the CHILD's own exit code and signal as
# supervise recorded them, never from supervise's own exit status (a supervisor that
# successfully supervised a failing child exits 0), and, for bpftrace, from which stage its
# free-text diagnostics show it reached. That stage heuristic, for bpftrace v0.25.0:
#   - a --dry-run that exits cleanly is a successful LOAD, whatever the log says: this
#     version returns from its dry-run branch before the point at which "Attached N probes"
#     would be printed, so requiring that text would call every clean dry-run a failure
#   - otherwise "Attached N probes" (past tense, printed once attaching has finished) means
#     the load stage completed
#   - "cannot attach probe" and the other attach-time messages are an ATTACH failure, which
#     implies the load itself had already succeeded - never reported as a load failure
#   - compile/verifier messages are a LOAD failure
#   - anything else is "unknown": never guessed at from an exit code alone
# This reads bpftrace's own human-readable diagnostics; bpftrace reports no machine-readable
# stage of its own.
#
# Each operation gets its own child-out/ directory, owned by and writable for the target
# user, for whatever the operation itself writes (bpftrace's -o file, the cgroup map's own
# JSON). supervise's own records stay outside it, in the root-owned operation directory: a
# non-root child must be able to write its output without being able to alter the record of
# what it was.
#
# Output: experiments/runtime-discovery/out/privilege-<condition>.json and .md (the
# summary), plus experiments/runtime-discovery/out/privilege-<condition>-artifacts/ holding
# every operation's own raw log, the cgroup-id map's own output JSON, and supervise's own
# process record for each operation - preserved evidence, not just the summary's own
# tail-truncated log excerpt. Only the capability-tagged binary copies and the /var/tmp
# scratch directory are deleted - and only once every operation's own supervise record
# confirms its child has stopped and every artifact has been copied file by file; when
# either is not the case the scratch directory is deliberately kept, its path reported, and
# this script exits non-zero. Nothing under out/ is ever removed by this script.
#
# Prerequisites: run as root, bpftrace and setcap installed, the runtime-discovery binary
# built into experiments/runtime-discovery/out/ (both for cgroup-id-map and for its own
# `supervise` subcommand this script now runs every operation through), and the native
# Docker Engine daemon reachable at /var/run/docker.sock (operation 3 starts one throwaway
# container).
set -uo pipefail
cd "${KL_ROOT:-$(dirname "$0")/../../..}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./load-lib.sh
. "$here/load-lib.sh"
unset DOCKER_CONTEXT; export DOCKER_HOST=unix:///var/run/docker.sock
O=experiments/runtime-discovery/out
CASES=experiments/runtime-discovery/cases
B="$O/runtime-discovery"
BT_PLAIN=experiments/runtime-events/bpftrace/runtime-events-nofilter.bt
# bpftrace reads these from its environment; supervise removes them from the CHILD's own
# environment (-unset-env) rather than this script wrapping the command in `env -u ...`, so
# the process supervise starts, verifies (exe, uid, CapEff) and supervises is bpftrace
# itself and not a wrapper that has merely promised to exec it.
BPF_UNSET_ENV=BPFTRACE_MAX_STRLEN,BPFTRACE_PERF_RB_PAGES,BPFTRACE_ON_STACK_LIMIT
RUNTIME_EVENTS_BUILT=$O/runtime-events

USAGE="Usage: sudo bash experiments/runtime-discovery/tools/privilege-run.sh <root|bpf_perfmon|bpf_perfmon_dac|bpf_perfmon_dac_override|sysadmin>"
[ $# -ge 1 ] || { echo "$USAGE" >&2; exit 2; }
CONDITION="$1"
case "$CONDITION" in root|bpf_perfmon|bpf_perfmon_dac|bpf_perfmon_dac_override|sysadmin) ;; *) echo "$USAGE" >&2; exit 2;; esac
[ "$(id -u)" = 0 ] || { echo "privilege-run: run as root (setcap, supervise's own user-switch, and reading another user's /proc entries all need it)" >&2; exit 1; }
command -v setcap >/dev/null || { echo "privilege-run: setcap not installed" >&2; exit 1; }
command -v bpftrace >/dev/null || { echo "privilege-run: bpftrace not installed" >&2; exit 1; }
[ -x "$B" ] || { echo "privilege-run: $B not built" >&2; exit 1; }
[ -x "$RUNTIME_EVENTS_BUILT" ] || { echo "privilege-run: $RUNTIME_EVENTS_BUILT not built" >&2; exit 1; }
DAEMON=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null); case "$DAEMON" in "") echo "docker daemon unreachable" >&2; exit 1;; *Desktop*) echo "docker socket belongs to Docker Desktop ($DAEMON); this needs the native daemon" >&2; exit 1;; esac

RUN_AS="root"
if [ "$CONDITION" != root ]; then
  if [ -z "${KL_PRIV_USER:-}" ]; then
    echo "privilege-run: KL_PRIV_USER must name an existing unprivileged user for condition '$CONDITION'." >&2
    echo "  This script never creates one. Create it once, then re-run:" >&2
    echo "    sudo useradd -M -s /usr/sbin/nologin kltest" >&2
    echo "    sudo KL_PRIV_USER=kltest bash $0 $CONDITION" >&2
    exit 2
  fi
  id -u "$KL_PRIV_USER" >/dev/null 2>&1 || { echo "privilege-run: KL_PRIV_USER=$KL_PRIV_USER does not exist; create it first (this script never creates a user)" >&2; exit 1; }
  RUN_AS="$KL_PRIV_USER"
fi
RUN_AS_UID="$(id -u "$RUN_AS")"; RUN_AS_GID="$(id -g "$RUN_AS")"

SYSTEM_BPFTRACE="$(command -v bpftrace)"
PRIVDIR="/var/tmp/kl-privilege-$CONDITION-$$"
ARTIFACTS="$O/privilege-$CONDITION-artifacts"
FACTS="$PRIVDIR/facts"; OPS="$PRIVDIR/ops"
rm -rf "$PRIVDIR"; mkdir -p "$PRIVDIR/bin" "$FACTS" "$OPS"
rm -rf "$ARTIFACTS"; mkdir -p "$ARTIFACTS"
PRIV_BPFTRACE="$PRIVDIR/bin/bpftrace"; PRIV_RUNTIME_EVENTS="$PRIVDIR/bin/runtime-events"
cp "$SYSTEM_BPFTRACE" "$PRIV_BPFTRACE"; cp "$RUNTIME_EVENTS_BUILT" "$PRIV_RUNTIME_EVENTS"
chmod 0755 "$PRIVDIR" "$PRIVDIR/bin" "$FACTS" "$OPS" "$PRIV_BPFTRACE" "$PRIV_RUNTIME_EVENTS"

log(){ echo "$(date -u +%FT%T.%NZ) $*"; }
log "## condition $CONDITION, run as $RUN_AS ($RUN_AS_UID), scratch $PRIVDIR, artifacts $ARTIFACTS"

# --- cleanup is registered before setcap is ever applied and before any test container or
# supervised process exists, on EXIT/INT/TERM. It requests the stop through the same file
# supervise itself polls (never a bare SIGKILL of a supervisor, which would leave its own
# child orphaned), WAITS for each supervisor to actually finish that bounded sequence,
# copies every piece of evidence to the artifacts directory under out/, and only then
# removes the capability-tagged copies and the /var/tmp scratch dir. The signal paths exit
# after that work rather than returning into the middle of an operation.
CLEANUP_WAIT_S="${KL_CLEANUP_WAIT_S:-40}"
CLEANUP_CONTAINER=""; CLEANED=0; CLEANUP_HELD=0; PRESERVE_ERRORS=""
declare -A CLEANUP_STOPFILES=(); declare -A CLEANUP_SUPERVISORS=(); declare -A CLEANUP_CGROUPS=()
# STARTED_OPS is the registry every stop confirmation is driven from: an operation is
# entered here BEFORE its supervised child is launched, so a child that was started but
# whose supervisor was killed before it could write its record is still on the list and
# still has to be accounted for. Deriving the list from the records that happen to exist
# afterwards would do the opposite - the operations whose evidence is missing are exactly
# the ones that would silently drop off it.
declare -A STARTED_OPS=(); declare -A OP_WAIT_FAILED=()

register_operation(){ STARTED_OPS[$1]="$2"; }
register_supervisor(){ CLEANUP_SUPERVISORS[$1]="$2"; }

# preserve_artifacts copies the raw evidence out of the scratch directory into out/, where
# nothing this script does ever deletes it - one file at a time, each copy checked. A
# recursive copy whose overall result is discarded cannot support the claim this function
# exists to make: that everything worth keeping is now somewhere the cleanup below will not
# remove. Any failure is counted and named in PRESERVE_ERRORS, and the caller keeps the
# originals. Safe to call more than once.
PRESERVE_FAILED=0
preserve_artifacts(){
	local src rel dst failed=0 list find_rc
	PRESERVE_ERRORS="$ARTIFACTS/preserve-errors.txt"
	if ! mkdir -p "$ARTIFACTS/ops" "$ARTIFACTS/facts" 2>/dev/null; then
		PRESERVE_FAILED=1
		echo "privilege-run: cannot create $ARTIFACTS; the raw evidence stays in $PRIVDIR" >&2
		return 1
	fi
	: > "$PRESERVE_ERRORS"
	# The file list is built into a file first, and the enumeration's own exit status is
	# checked, because that status is the only thing that says the list is COMPLETE. Piping
	# the search straight into the loop (a pipeline or a process substitution) throws it
	# away: a directory that could not be read would simply contribute nothing, every file
	# that was listed would copy cleanly, and this would report a full preservation of an
	# unknown fraction of the evidence - and the originals would then be deleted.
	list="$ARTIFACTS/.preserve-list"
	find "$PRIVDIR/ops" "$PRIVDIR/facts" -type f -print0 > "$list" 2>>"$PRESERVE_ERRORS"
	find_rc=$?
	if [ "$find_rc" != 0 ]; then
		echo "enumerating $PRIVDIR failed (find exit $find_rc); the list of evidence to preserve is incomplete" >>"$PRESERVE_ERRORS"
		PRESERVE_FAILED=1
		rm -f "$list"
		echo "privilege-run: could not enumerate the raw evidence under $PRIVDIR (see $PRESERVE_ERRORS); the originals are kept there" >&2
		return 1
	fi
	while IFS= read -r -d '' src; do
		rel="${src#"$PRIVDIR"/}"
		dst="$ARTIFACTS/$rel"
		if ! mkdir -p "$(dirname "$dst")" 2>>"$PRESERVE_ERRORS"; then
			failed=$((failed + 1)); echo "$rel: could not create its destination directory" >>"$PRESERVE_ERRORS"; continue
		fi
		if ! cp -p "$src" "$dst" 2>>"$PRESERVE_ERRORS"; then
			failed=$((failed + 1)); echo "$rel: copy failed" >>"$PRESERVE_ERRORS"
		fi
	done < "$list"
	rm -f "$list"
	PRESERVE_FAILED="$failed"
	if [ "$failed" != 0 ]; then
		echo "privilege-run: $failed file(s) could not be copied to $ARTIFACTS (see $PRESERVE_ERRORS); the originals are kept in $PRIVDIR" >&2
		return 1
	fi
	rm -f "$PRESERVE_ERRORS"
	return 0
}

# wait_for_supervisor waits for one supervise process to finish its own stop sequence,
# escalating at most to a SIGTERM of the supervisor itself (which makes it run that same
# sequence). It never SIGKILLs a supervisor: that would abandon the real child.
wait_for_supervisor(){
	local label="$1" pid="$2" waited=0
	[ -n "$pid" ] || return 0
	while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$CLEANUP_WAIT_S" ]; do sleep 1; waited=$((waited + 1)); done
	if kill -0 "$pid" 2>/dev/null; then
		echo "privilege-run cleanup: $label supervise (pid $pid) has not finished; sending TERM" >&2
		kill -TERM "$pid" 2>/dev/null
		waited=0
		while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$CLEANUP_WAIT_S" ]; do sleep 1; waited=$((waited + 1)); done
	fi
	if kill -0 "$pid" 2>/dev/null; then
		echo "privilege-run cleanup: $label supervise (pid $pid) is STILL running; not sending SIGKILL, which would orphan its child" >&2
		return 1
	fi
	wait "$pid" 2>/dev/null
	return 0
}

# termination_state prints "confirmed" or "unconfirmed: <why>" for one operation, read from
# the record supervise itself wrote. A supervisor that has exited establishes nothing about
# its child on its own: it exits after writing that record whatever became of the child, so
# a stop SIGKILL never confirmed, or a cgroup still holding a descendant, both leave a
# cleanly-exited supervisor behind a process that is still running.
termination_state(){
	python3 -c '
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except (OSError, ValueError) as e:
    print("unconfirmed: the supervision record could not be read (%s)" % e); raise SystemExit
tc = r.get("termination_confirmed") or {}
if tc.get("measured") and tc.get("value"):
    print("confirmed"); raise SystemExit
print("unconfirmed: status=%s, %s" % (r.get("status"), tc.get("reason") or "the record carries no termination_confirmed field"))
' "$1" 2>/dev/null || echo "unconfirmed: the supervision record could not be read"
}

# every_operation_terminated goes through the REGISTRY of operations that were started, not
# through whatever records exist. Three separate things make an operation unconfirmed, and
# all three are treated the same way: its supervisor could not be confirmed finished, its
# record is missing or unreadable, or the record itself says the child's termination was
# never established. This is what gates deleting the scratch directory: a capability-tagged
# binary copy must not be removed from under a process that may still be executing it, and
# the evidence of a run that did not stop must not be thrown away with it.
TERMINATION_UNCONFIRMED=""
every_operation_terminated(){
	local op rec state ok=0
	TERMINATION_UNCONFIRMED=""
	for op in "${!STARTED_OPS[@]}"; do
		rec="${STARTED_OPS[$op]}"
		if [ "${OP_WAIT_FAILED[$op]:-0}" = 1 ]; then
			ok=1
			TERMINATION_UNCONFIRMED="${TERMINATION_UNCONFIRMED}$op: unconfirmed: its supervisor never finished its own stop sequence
"
			continue
		fi
		if [ ! -s "$rec" ]; then
			ok=1
			TERMINATION_UNCONFIRMED="${TERMINATION_UNCONFIRMED}$op: unconfirmed: no supervision record at $rec, so nothing establishes that its child stopped
"
			continue
		fi
		state="$(termination_state "$rec")"
		[ "$state" = confirmed ] && continue
		ok=1
		TERMINATION_UNCONFIRMED="${TERMINATION_UNCONFIRMED}$op: $state
"
	done
	[ "$ok" = 0 ]
}

cleanup(){
	local key sf pid cg
	if [ "$CLEANED" = 0 ]; then
		CLEANED=1
		for key in "${!CLEANUP_STOPFILES[@]}"; do
			sf="${CLEANUP_STOPFILES[$key]}"
			[ -n "$sf" ] && [ ! -s "$sf" ] && echo "privilege-run cleanup" >"$sf" 2>/dev/null
		done
		for key in "${!CLEANUP_SUPERVISORS[@]}"; do
			pid="${CLEANUP_SUPERVISORS[$key]}"
			wait_for_supervisor "$key" "$pid" || OP_WAIT_FAILED[$key]=1
		done
		[ -n "$CLEANUP_CONTAINER" ] && docker rm -f "$CLEANUP_CONTAINER" >/dev/null 2>&1
		preserve_artifacts; local preserved=$?
		chown -R "${SUDO_USER:-$(id -un)}":"${SUDO_USER:-$(id -un)}" "$ARTIFACTS" 2>/dev/null
		for key in "${!CLEANUP_CGROUPS[@]}"; do
			cg="${CLEANUP_CGROUPS[$key]}"
			[ -n "$cg" ] && [ -d "$cg" ] && "$B" cgroup-remove -wait 10 "$cg" >>"$ARTIFACTS/cgroup-remove.jsonl" 2>/dev/null
		done
		if ! every_operation_terminated; then
			CLEANUP_HELD=1
			echo "privilege-run: NOT deleting $PRIVDIR - the following operations could not confirm their child had stopped:" >&2
			printf '%s' "$TERMINATION_UNCONFIRMED" >&2
			echo "privilege-run: the capability-tagged binary copies are still in $PRIVDIR/bin; remove them once those processes are gone." >&2
			printf '%s' "$TERMINATION_UNCONFIRMED" > "$ARTIFACTS/termination-unconfirmed.txt" 2>/dev/null
		elif [ "$preserved" != 0 ]; then
			CLEANUP_HELD=1
			echo "privilege-run: NOT deleting $PRIVDIR - the raw evidence could not be fully copied to $ARTIFACTS." >&2
		else
			rm -rf "$PRIVDIR"
		fi
	fi
}
trap 'cleanup; [ "$CLEANUP_HELD" = 1 ] && exit 1; true' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

CAP_SPEC=""
case "$CONDITION" in
  root) CAP_SPEC="";;
  bpf_perfmon) CAP_SPEC="cap_bpf,cap_perfmon=ep";;
  bpf_perfmon_dac) CAP_SPEC="cap_bpf,cap_perfmon,cap_dac_read_search=ep";;
  bpf_perfmon_dac_override) CAP_SPEC="cap_bpf,cap_perfmon,cap_dac_read_search,cap_dac_override=ep";;
  sysadmin) CAP_SPEC="cap_sys_admin=ep";;
esac
echo "$CAP_SPEC" > "$FACTS/capabilities_requested.txt"
if [ -n "$CAP_SPEC" ]; then
  setcap "$CAP_SPEC" "$PRIV_BPFTRACE" || { echo "privilege-run: setcap failed on $PRIV_BPFTRACE" >&2; exit 1; }
  setcap "$CAP_SPEC" "$PRIV_RUNTIME_EVENTS" || { echo "privilege-run: setcap failed on $PRIV_RUNTIME_EVENTS" >&2; exit 1; }
fi

precheck_reachable() {
	local what="$1"; shift
	if runuser -u "$RUN_AS" -- "$@" 2>/dev/null; then return 0; fi
	echo "privilege-run: reachability precheck FAILED for $what (as $RUN_AS: $*)" >&2
	return 1
}
BPFTRACE_USABLE=0
precheck_reachable "the private bpftrace copy (read+execute)" test -r "$PRIV_BPFTRACE" -a -x "$PRIV_BPFTRACE" && BPFTRACE_USABLE=1
RUNTIME_EVENTS_USABLE=0
precheck_reachable "the private runtime-events copy (read+execute)" test -r "$PRIV_RUNTIME_EVENTS" -a -x "$PRIV_RUNTIME_EVENTS" && RUNTIME_EVENTS_USABLE=1

log "## static facts: sysctls, lockdown, binary hashes"
for k in kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid kernel.yama.ptrace_scope; do
  sysctl -n "$k" 2>/dev/null > "$FACTS/sysctl.$k.txt" || echo "not_measured: sysctl $k not readable" > "$FACTS/sysctl.$k.txt"
done
if [ -r /sys/kernel/security/lockdown ]; then cat /sys/kernel/security/lockdown > "$FACTS/lockdown.txt"
else echo "not_measured: /sys/kernel/security/lockdown not present (securityfs lockdown not mounted or not enabled)" > "$FACTS/lockdown.txt"; fi
sha256sum "$SYSTEM_BPFTRACE" | awk '{print $1}' > "$FACTS/system_bpftrace_sha256.txt"
sha256sum "$PRIV_BPFTRACE" | awk '{print $1}' > "$FACTS/private_bpftrace_sha256.txt"
sha256sum "$PRIV_RUNTIME_EVENTS" | awk '{print $1}' > "$FACTS/private_runtime_events_sha256.txt"

USER_ARGS=(); [ "$CONDITION" != root ] && USER_ARGS=(-user "$RUN_AS")
EXPECT_CAPEFF=""
if [ -n "$CAP_SPEC" ]; then
  # bpftrace's own CapEff once the requested file capabilities take effect: "=ep" means
  # both the effective and permitted sets equal exactly the named capabilities, which
  # supervise's own -expect-capeff compares against verbatim, so this has to be the exact
  # hex bitmask those capabilities correspond to. Computed from the same capability NAMES
  # given to setcap above (never a separately hand-computed constant, which a bit-number
  # slip could silently make wrong) via Python's own literal table of Linux capability bit
  # numbers (include/uapi/linux/capability.h) - a name typo or an unknown capability fails
  # loudly here rather than comparing against a wrong mask that always mismatches.
  EXPECT_CAPEFF="$(python3 -c "
names = '${CAP_SPEC%%=*}'.split(',')
bits = {'cap_chown':0,'cap_dac_override':1,'cap_dac_read_search':2,'cap_fowner':3,'cap_fsetid':4,
        'cap_kill':5,'cap_setgid':6,'cap_setuid':7,'cap_setpcap':8,'cap_linux_immutable':9,
        'cap_net_bind_service':10,'cap_net_broadcast':11,'cap_net_admin':12,'cap_net_raw':13,
        'cap_ipc_lock':14,'cap_ipc_owner':15,'cap_sys_module':16,'cap_sys_rawio':17,'cap_sys_chroot':18,
        'cap_sys_ptrace':19,'cap_sys_pacct':20,'cap_sys_admin':21,'cap_sys_boot':22,'cap_sys_nice':23,
        'cap_sys_resource':24,'cap_sys_time':25,'cap_sys_tty_config':26,'cap_mknod':27,'cap_lease':28,
        'cap_audit_write':29,'cap_audit_control':30,'cap_setfcap':31,'cap_mac_override':32,'cap_mac_admin':33,
        'cap_syslog':34,'cap_wake_alarm':35,'cap_block_suspend':36,'cap_audit_read':37,'cap_perfmon':38,
        'cap_bpf':39,'cap_checkpoint_restore':40}
mask = 0
for n in names:
    mask |= 1 << bits[n.strip().lower()]
print('%016x' % mask)
")"
fi

# condition_established checks a completed supervise record against what this condition is
# supposed to have produced: the actually exec'd exe matches, and (for a non-root condition)
# the process's own real+effective UID is the target user's (never 0) and, when a capability
# set was requested, CapEff matches exactly. A condition that fails this is recorded as
# "condition_not_established" - a fact about the harness's own setup, kept separate from
# whether the operation ITSELF then succeeded or failed under that (possibly unestablished)
# condition, so the two are never conflated in the result.
condition_established() {
	local record="$1"
	python3 -c "
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print('condition_not_established: could not read the supervise record'); sys.exit()
if not r.get('exe_verified', {}).get('measured') or not r['exe_verified'].get('value'):
    print(f\"condition_not_established: exe not verified ({r.get('verification_error') or r.get('exe_verified')})\"); sys.exit()
if sys.argv[2] == 'root':
    print('established'); sys.exit()
uidv = r.get('uid_verified', {})
if not uidv.get('measured') or not uidv.get('value'):
    print(f\"condition_not_established: uid not verified as {sys.argv[3]} (real={r.get('real_uid')} effective={r.get('effective_uid')})\"); sys.exit()
if r.get('effective_uid') == 0:
    print('condition_not_established: effective uid is 0 despite -user being given'); sys.exit()
if sys.argv[4]:
    capv = r.get('capeff_verified', {})
    if not capv.get('measured') or not capv.get('value'):
        print(f\"condition_not_established: CapEff {r.get('cap_eff')} does not match expected {sys.argv[4]}\"); sys.exit()
print('established')
" "$record" "$CONDITION" "$RUN_AS_UID" "$EXPECT_CAPEFF"
}

# extract_errno never infers a number from an exit code or from wording like "Permission
# denied": it only reports a number this operation's own log literally spelled out.
extract_errno() {
	local f="$1" m
	m=$(grep -ioE 'errno[: ]+[0-9]+' "$f" 2>/dev/null | grep -oE '[0-9]+' | head -1)
	[ -n "$m" ] && echo "$m" || echo unknown
}

classify_denial() {
	local f="$1"
	if grep -qiE 'bpf\(\)|BPF_PROG_LOAD|perf_event_open|CAP_BPF|CAP_PERFMON' "$f" 2>/dev/null && grep -qi 'permission\|not permitted' "$f" 2>/dev/null; then
		echo perf_bpf_check; return
	fi
	if grep -qiE '/sys/kernel/(debug/)?tracing' "$f" 2>/dev/null && grep -qi 'permission denied' "$f" 2>/dev/null; then
		echo tracefs_dac; return
	fi
	if grep -qiE 'lockdown|apparmor|selinux|LSM' "$f" 2>/dev/null; then
		echo lsm; return
	fi
	echo unknown
}

# child_outcome prints the CHILD's own "<exit code> <exit signal> <status>" as supervise
# recorded it (exit code "unknown" when no exit was ever observed, signal "-" when the
# process exited normally). supervise's own exit status is a different fact entirely - it
# reports whether the SUPERVISION worked, and is 0 for a child that failed - so an
# operation's own result is never taken from it.
child_outcome() {
	python3 -c "
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print('unknown - no_record'); raise SystemExit
code = r.get('exit_code')
print('%s %s %s' % ('unknown' if code is None else code,
                    r.get('exit_signal') or '-',
                    r.get('status') or 'unknown'))
" "$1" 2>/dev/null || echo "unknown - no_record"
}

# bpftrace_stage classifies which of the two stages (load, attach) a run's own log reaches,
# for bpftrace v0.25.0 specifically. Three rules, in this order:
#   1. A --dry-run (dry=1) that exited cleanly loaded successfully. This version returns
#      from its dry-run branch BEFORE the point at which "Attached N probes" is printed, so
#      a clean dry-run legitimately never prints it, and requiring that text would report
#      every successful dry-run as a failure.
#   2. "Attached N probes" (past tense, printed once attaching has already finished) means
#      every program compiled and loaded, since attaching is only attempted afterwards.
#   3. Otherwise the log's own diagnostics decide: attach-time messages ("cannot attach
#      probe" among them) are an ATTACH failure - which means the load itself had already
#      succeeded, so it is never reported as a load failure - and compile/verifier messages
#      are a LOAD failure.
# Anything else is "unknown", never guessed at from the exit code alone. This reads
# bpftrace's own free-text diagnostics; bpftrace reports no machine-readable stage itself.
# Usage: bpftrace_stage <log> <dry-run 0|1> <child exit code, or "unknown">
bpftrace_stage() {
	local log="$1" dry="$2" child_exit="$3"
	if [ "$dry" = 1 ] && [ "$child_exit" = 0 ]; then
		echo load_ok; return
	fi
	if grep -qi 'Attached [0-9]* probe' "$log" 2>/dev/null; then
		echo load_ok; return
	fi
	if grep -qiE 'cannot attach probe|error attaching|failed to attach|attach.*(permission|not permitted)' "$log" 2>/dev/null; then
		echo attach_failed; return
	fi
	if grep -qiE 'verifier|failed to compile|syntax error|semantic error|invalid probe|BPF_PROG_LOAD|error loading program' "$log" 2>/dev/null; then
		echo load_failed; return
	fi
	# bpftrace's own pre-check: without CAP_DAC_OVERRIDE (or uid 0) it refuses to start at all,
	# before any kernel operation. That is the tool declining, not the kernel deciding, so it
	# gets its own stage rather than being folded into a load failure.
	if grep -qiE 'please run bpftrace as the root user|Missing CAP_[A-Z_]* capability' "$log" 2>/dev/null; then
		echo tool_refused; return
	fi
	# tracefs itself refusing to be read (available_events, the tracepoint format files) happens
	# while the program is still being prepared, so nothing was loaded: a load-stage failure
	# whose denying layer classify_denial reports as tracefs_dac.
	if grep -qiE '/sys/kernel/(debug/)?tracing' "$log" 2>/dev/null && grep -qi 'permission denied' "$log" 2>/dev/null; then
		echo load_failed; return
	fi
	echo unknown
}

# prepare_op_dir creates one operation's own directories: the operation directory itself
# (root-owned, holding supervise's own record, which the child must not be able to alter)
# and a child-out subdirectory owned by the target user, which is where the operation's own
# output - bpftrace's -o file, the cgroup map's JSON - actually goes.
prepare_op_dir() {
	local d="$1"
	mkdir -p "$d/child-out" || return 1
	chmod 0755 "$d" "$d/child-out" || return 1
	chown "$RUN_AS_UID":"$RUN_AS_GID" "$d/child-out" || return 1
}

log "## operation 1: BPF program load (dry-run of the nofilter script)"
D="$OPS/bpf_program_load"
if ! prepare_op_dir "$D"; then
	mkdir -p "$D"; echo unreached > "$D/result.txt"; echo "could not create an output directory writable by $RUN_AS" > "$D/reason.txt"
elif [ "$BPFTRACE_USABLE" != 1 ]; then
	echo unreached > "$D/result.txt"; echo "reachability precheck failed for the private bpftrace copy" > "$D/reason.txt"
else
	CG1="/sys/fs/cgroup/kl-priv-$CONDITION-load-$$"; STOP1="$D/stop_request.txt"
	CLEANUP_STOPFILES[op1]="$STOP1"; CLEANUP_CGROUPS[op1]="$CG1"
	# Registered before the child exists: from here on this operation has to account for a
	# stopped child, even if no record is ever written.
	register_operation bpf_program_load "$D/supervise.json"
	"$B" supervise -cgroup "$CG1" "${USER_ARGS[@]}" -expect-exe "$PRIV_BPFTRACE" ${EXPECT_CAPEFF:+-expect-capeff "$EXPECT_CAPEFF"} \
		-record "$D/supervise.json" -stop-request "$STOP1" -grace 5 -deadline 30 -allow-unmeasured \
		-unset-env "$BPF_UNSET_ENV" \
		-- "$PRIV_BPFTRACE" --dry-run -v "$BT_PLAIN" \
		> "$D/log.txt" 2>&1
	echo "$?" > "$D/supervisor_exit_code.txt"
	read -r child_code child_signal child_status <<<"$(child_outcome "$D/supervise.json")"
	echo "$child_code" > "$D/exit_code.txt"; echo "$child_signal" > "$D/exit_signal.txt"; echo "$child_status" > "$D/child_status.txt"
	cond="$(condition_established "$D/supervise.json")"
	echo "$cond" > "$D/condition.txt"
	if [ "$cond" != established ]; then
		echo unreached > "$D/result.txt"; echo "$cond" > "$D/reason.txt"
	else
		stage="$(bpftrace_stage "$D/log.txt" 1 "$child_code")"
		echo "$stage" > "$D/stage.txt"
		case "$stage" in
			load_ok) echo success > "$D/result.txt";;
			attach_failed)
				# An attach-time failure in a --dry-run log means the program had already
				# compiled and loaded: this operation tests the LOAD, which succeeded.
				echo success > "$D/result.txt"
				echo "the load stage completed; the failure the log reports is at attach, which this operation does not test" > "$D/note.txt";;
			load_failed) echo failure > "$D/result.txt"; extract_errno "$D/log.txt" > "$D/errno.txt"; classify_denial "$D/log.txt" > "$D/denial.txt";;
			tool_refused)
				echo failure > "$D/result.txt"; echo bpftrace_own_check > "$D/denial.txt"; extract_errno "$D/log.txt" > "$D/errno.txt"
				echo "bpftrace refused to start under this condition (its own pre-check requires CAP_DAC_OVERRIDE or uid 0), so no kernel operation was attempted; this is a limit of the measurement tool, not a kernel decision" > "$D/reason.txt";;
			*) echo unreached > "$D/result.txt"; echo "load-vs-attach stage undeterminable from bpftrace's own log (child exit=$child_code signal=$child_signal status=$child_status)" > "$D/reason.txt";;
		esac
	fi
fi

log "## operations 2+3: tracepoint attach (~15s) and buffer creation/reading"
AD="$OPS/tracepoint_attach"; BD="$OPS/buffer_create_and_read"
TRACE_OUT="$AD/child-out/trace.txt"
if ! prepare_op_dir "$AD" || ! prepare_op_dir "$BD"; then
	mkdir -p "$AD" "$BD"
	for d in "$AD" "$BD"; do echo unreached > "$d/result.txt"; echo "could not create an output directory writable by $RUN_AS" > "$d/reason.txt"; done
elif [ "$BPFTRACE_USABLE" != 1 ]; then
	for d in "$AD" "$BD"; do echo unreached > "$d/result.txt"; echo "reachability precheck failed for the private bpftrace copy" > "$d/reason.txt"; done
else
	CNAME="klpriv-$CONDITION-$$"
	docker rm -f "$CNAME" >/dev/null 2>&1
	if ! docker run -d --name "$CNAME" alpine:3.20 sleep 60 >/dev/null 2>&1; then
		for d in "$AD" "$BD"; do echo unreached > "$d/result.txt"; echo "could not start the throwaway container" > "$d/reason.txt"; done
	else
		CLEANUP_CONTAINER="$CNAME"
		MARKER="klpriv-marker-$$"
		if ! docker exec "$CNAME" cp /bin/true "/$MARKER" >"$AD/marker_copy.log" 2>&1; then
			for d in "$AD" "$BD"; do echo unreached > "$d/result.txt"; echo "could not create the in-container marker executable (docker exec cp failed)" > "$d/reason.txt"; done
		else
			CG2="/sys/fs/cgroup/kl-priv-$CONDITION-attach-$$"; STOP2="$AD/stop_request.txt"
			CLEANUP_STOPFILES[op2]="$STOP2"; CLEANUP_CGROUPS[op2]="$CG2"
			register_operation tracepoint_attach "$AD/supervise.json"
			"$B" supervise -cgroup "$CG2" "${USER_ARGS[@]}" -expect-exe "$PRIV_BPFTRACE" ${EXPECT_CAPEFF:+-expect-capeff "$EXPECT_CAPEFF"} \
				-record "$AD/supervise.json" -stop-request "$STOP2" -grace 5 -deadline 20 -allow-unmeasured \
				-unset-env "$BPF_UNSET_ENV" \
				-- "$PRIV_BPFTRACE" -o "$TRACE_OUT" "$BT_PLAIN" \
				> "$AD/log.txt" 2>&1 &
			SUP2=$!
			register_supervisor tracepoint_attach "$SUP2"
			sleep 3
			ATTACHED=0
			if bash "$CASES/run.sh" attach-check "$TRACE_OUT" 10 >>"$AD/log.txt" 2>&1; then ATTACHED=1; fi
			if [ "$ATTACHED" = 1 ]; then docker exec "$CNAME" "/$MARKER" >/dev/null 2>&1; fi
			sleep 3
			echo "attach op complete" > "$STOP2"
			wait "$SUP2"; echo "$?" > "$AD/supervisor_exit_code.txt"
			# Reaped here, so the cleanup must not wait on it again - but the operation stays
			# in the registry, and its record still has to confirm the child actually stopped.
			unset 'CLEANUP_SUPERVISORS[tracepoint_attach]'
			read -r child_code child_signal child_status <<<"$(child_outcome "$AD/supervise.json")"
			for d in "$AD" "$BD"; do
				echo "$child_code" > "$d/exit_code.txt"; echo "$child_signal" > "$d/exit_signal.txt"; echo "$child_status" > "$d/child_status.txt"
			done
			cp "$AD/supervisor_exit_code.txt" "$BD/supervisor_exit_code.txt" 2>/dev/null
			condr="$(condition_established "$AD/supervise.json")"
			echo "$condr" > "$AD/condition.txt"
			cp "$AD/supervise.json" "$BD/supervise.json" 2>/dev/null
			echo "$condr" > "$BD/condition.txt"
			if [ "$condr" != established ]; then
				echo unreached > "$AD/result.txt"; echo "$condr" > "$AD/reason.txt"
				echo unreached > "$BD/result.txt"; echo "$condr" > "$BD/reason.txt"
			else
				stage="$(bpftrace_stage "$AD/log.txt" 0 "$child_code")"
				echo "$stage" > "$AD/stage.txt"; echo "$stage" > "$BD/stage.txt"
				# A run that never got past loading did not reach the attach this
				# operation tests: that is "unreached", not an attach failure. Only a run
				# whose programs actually loaded can be said to have failed AT attach.
				if [ "$ATTACHED" = 1 ]; then
					echo success > "$AD/result.txt"
				elif [ "$stage" = load_failed ]; then
					echo unreached > "$AD/result.txt"
					echo "the BPF program never loaded (stage=load_failed), so the tracepoint attach was never attempted" > "$AD/reason.txt"
				elif [ "$stage" = tool_refused ]; then
					echo unreached > "$AD/result.txt"
					echo "bpftrace refused to start under this condition (its own pre-check requires CAP_DAC_OVERRIDE or uid 0), so the tracepoint attach was never attempted; this is a limit of the measurement tool, not a kernel decision" > "$AD/reason.txt"
				elif [ "$stage" = unknown ]; then
					echo unreached > "$AD/result.txt"
					echo "which stage this run reached could not be determined from bpftrace's own log (child exit=$child_code signal=$child_signal status=$child_status)" > "$AD/reason.txt"
				else
					echo failure > "$AD/result.txt"; extract_errno "$AD/log.txt" > "$AD/errno.txt"; classify_denial "$AD/log.txt" > "$AD/denial.txt"
				fi
				if [ "$ATTACHED" != 1 ]; then
					echo unreached > "$BD/result.txt"
					if [ "$stage" = load_failed ] || [ "$stage" = tool_refused ]; then
						echo "the BPF program never loaded, so neither the attach nor a buffer read was reached" > "$BD/reason.txt"
					else
						echo "tracepoint attach was not confirmed; a buffer read cannot be meaningfully tested" > "$BD/reason.txt"
					fi
				elif grep -q "$MARKER" "$TRACE_OUT" 2>/dev/null; then
					echo success > "$BD/result.txt"
				else
					echo failure > "$BD/result.txt"; extract_errno "$AD/log.txt" > "$BD/errno.txt"; classify_denial "$AD/log.txt" > "$BD/denial.txt"
				fi
			fi
		fi
		docker rm -f "$CNAME" >/dev/null 2>&1; CLEANUP_CONTAINER=""
	fi
fi
unset 'CLEANUP_STOPFILES[op2]'

log "## operation 4: cgroup-id map creation"
D="$OPS/cgroup_id_map"
if ! prepare_op_dir "$D"; then
	mkdir -p "$D"; echo unreached > "$D/result.txt"; echo "could not create an output directory writable by $RUN_AS" > "$D/reason.txt"
elif [ "$RUNTIME_EVENTS_USABLE" != 1 ]; then
	echo unreached > "$D/result.txt"; echo "reachability precheck failed for the private runtime-events copy" > "$D/reason.txt"
else
	CG4="/sys/fs/cgroup/kl-priv-$CONDITION-cgmap-$$"; STOP4="$D/stop_request.txt"
	CLEANUP_STOPFILES[op4]="$STOP4"; CLEANUP_CGROUPS[op4]="$CG4"
	OUTJSON="$D/child-out/cgroup-map.json"
	if ! precheck_reachable "the cgroup-id map's own output directory (write)" test -w "$D/child-out"; then
		echo unreached > "$D/result.txt"; echo "RUN_AS cannot write to its own output directory ($D/child-out)" > "$D/reason.txt"
	else
		register_operation cgroup_id_map "$D/supervise.json"
		"$B" supervise -cgroup "$CG4" "${USER_ARGS[@]}" -expect-exe "$PRIV_RUNTIME_EVENTS" ${EXPECT_CAPEFF:+-expect-capeff "$EXPECT_CAPEFF"} \
			-record "$D/supervise.json" -stop-request "$STOP4" -grace 5 -deadline 20 -allow-unmeasured \
			-- "$PRIV_RUNTIME_EVENTS" cgroup-map -root /sys/fs/cgroup -out "$OUTJSON" \
			> "$D/log.txt" 2>&1
		echo "$?" > "$D/supervisor_exit_code.txt"
		read -r child_code child_signal child_status <<<"$(child_outcome "$D/supervise.json")"
		echo "$child_code" > "$D/exit_code.txt"; echo "$child_signal" > "$D/exit_signal.txt"; echo "$child_status" > "$D/child_status.txt"
		cond="$(condition_established "$D/supervise.json")"
		echo "$cond" > "$D/condition.txt"
		if [ "$cond" != established ]; then
			echo unreached > "$D/result.txt"; echo "$cond" > "$D/reason.txt"
		else
			# Verified against the REAL schema: a top-level "errors" array (enumeration
			# failures), each entry's own "handle_error" (per-directory ID-read failures),
			# and the presence of at least one entry for a cgroup this run itself knows
			# exists (its own supervise cgroup, CG4, guaranteed to have existed at scan
			# time) - never exit-code-0 alone, which this tool can report even when its
			# own JSON records an enumeration error or finds nothing at all.
			CONTENT_OK="$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print(0); sys.exit()
entries = d.get('entries')
top_errors = d.get('errors') or []
if not isinstance(entries, list) or not entries:
    print(0); sys.exit()
if top_errors:
    print(0); sys.exit()
if any(e.get('handle_error') for e in entries):
    print(0); sys.exit()
target = sys.argv[2].rstrip('/')
if not any(e.get('path','').rstrip('/').endswith(target) for e in entries):
    print(0); sys.exit()
print(1)
" "$OUTJSON" "$CG4" 2>/dev/null || echo 0)"
			if [ "$child_code" = 0 ] && [ "$CONTENT_OK" = 1 ]; then
				echo success > "$D/result.txt"
			else
				echo failure > "$D/result.txt"; extract_errno "$D/log.txt" > "$D/errno.txt"; classify_denial "$D/log.txt" > "$D/denial.txt"
				{ [ "$child_code" = 0 ] && [ "$CONTENT_OK" != 1 ]; } && echo "the tool exited 0 but errors[]/handle_error/missing target entry failed content validation" >> "$D/log.txt"
			fi
		fi
	fi
fi
unset 'CLEANUP_STOPFILES[op4]'
unset 'CLEANUP_STOPFILES[op1]'

log "## preserving raw evidence to $ARTIFACTS before removing capability-tagged copies"
preserve_artifacts

log "## assembling privilege-$CONDITION.json / .md"
mkdir -p "$O"
KLP_CONDITION="$CONDITION" KLP_RUN_AS="$RUN_AS" KLP_RUN_AS_UID="$RUN_AS_UID" KLP_PRIVDIR="$PRIVDIR" KLP_OUT="$O" python3 "$here/privilege_run_assemble.py"
chown -R "${SUDO_USER:-$(id -un)}":"${SUDO_USER:-$(id -un)}" "$O/privilege-$CONDITION.json" "$O/privilege-$CONDITION.md" "$ARTIFACTS" 2>/dev/null
log "## done: $O/privilege-$CONDITION.json (raw evidence under $ARTIFACTS)"
