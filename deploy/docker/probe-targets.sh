#!/usr/bin/env bash
# Brings up the seven verification containers the Sensor probe
# (kestrelynx sensor --probe) reads from and, for a labeled subset, runs
# narrowly-scoped write/connect/signal/exec probes against:
#
#   sameuid    a process running as the same UID (65532) the Sensor itself
#              runs as, for the fd-based mem-write probe (the bare-pid_t
#              ptrace/process_vm/pidfd/kill probes target a disposable child
#              the probe binary spawns itself instead — see
#              cmd/kestrelynx/sensor.go's spawnSameUIDChild)
#   sockets    a writable /tmp plus a listening UNIX stream socket and a
#              bound UNIX datagram socket, for the denied-connect/
#              denied-sendto/denied-root-write probes
#   setuid     a setuid file the exec-denial probe targets
#   ext4vol    a named volume mounted at /data, for the denied-
#              ioctl(FS_IOC_SETFLAGS) probe and the backing-filesystem-type
#              check
#   execloop   execs /bin/true once a second in a loop, so the probe's eBPF
#              event sampling window has something short-lived to capture
#              and can show the resulting event's path in the container's
#              own form (e.g. "/usr/bin/true", not a host-rooted path) —
#              read only, never a --target-pid
#   unconfined run with --security-opt apparmor=unconfined, for the
#              read-only classification checks only (never a --target-pid)
#   privileged run with --privileged, likewise read-only only
#
# Every container is labeled kestrelynx.probe-target=true and
# kestrelynx.probe-run=$KL_PROBE_RUN_ID (the latter via ledger_run_container,
# see lib-ledger.sh — it is what lets cleanup confirm ownership before
# removing anything, not merely a name match); the four write/connect/
# signal/exec targets are additionally labeled
# kestrelynx.probe-kind=<name above>, which is what
# cmd/kestrelynx/sensor.go's verifyTarget and runUnsafeOpsForTarget use to
# decide which unsafe probe(s), if any, apply to a given --target-pid — see
# that command's own package doc comment for the full verification it
# performs before trusting any of this.
#
# This script never removes anything itself: every container and the volume
# it creates are recorded into $KL_PROBE_LEDGER (by ledger_run_container/
# ledger_create_volume, before the command that creates them runs) so a
# caller with an active trap on that ledger (run-probe.sh) can recover
# exactly what this script created even if this script is interrupted
# partway through. It never reuses an existing volume: see the
# existing-volume check in up(), which distinguishes "does not exist" from
# "could not check" and aborts on the latter rather than assuming it is
# safe to proceed.
#
# Required environment: KL_PROBE_RUN_ID (a unique run identifier, already
# validated by the caller), KL_PROBE_LEDGER (a path to append
# created-resource records to). Optional: KL_PROBE_TARGET_IMAGE (overrides
# the pinned verification-target image tag — set by run-probe.sh when it
# has already resolved and verified an image ID via --image-tar, so this
# script launches containers from that exact verified image rather than
# re-resolving the tag itself).
#
# Usage: deploy/docker/probe-targets.sh up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib-ledger.sh
source "$SCRIPT_DIR/lib-ledger.sh"

: "${KL_PROBE_RUN_ID:?probe-targets.sh: KL_PROBE_RUN_ID must be set by the caller}"
: "${KL_PROBE_LEDGER:?probe-targets.sh: KL_PROBE_LEDGER must be set by the caller}"
if ! run_id_is_valid "$KL_PROBE_RUN_ID"; then
	echo "probe-targets.sh: KL_PROBE_RUN_ID $KL_PROBE_RUN_ID is not a valid run ID (want: 1-64 characters, alphanumeric and hyphen only)" >&2
	exit 1
fi

# The caller (run-probe.sh) tracks this script's PID and waits for it to
# exit before running its own cleanup, so that cleanup never races a
# creation this process is still in the middle of — see ledger_wait_pending's
# own doc comment. If this process is sent SIGTERM directly (for example by
# the operator's process-group Ctrl-C), an untrapped SIGTERM would terminate this
# process immediately, potentially while ledger_run_container is still
# polling for a `docker run` it already backgrounded to finish, leaving that
# one `docker run` to keep running as an orphan after this process is gone.
trap 'ledger_wait_pending; exit 143' TERM

# Pinned by tag by default (fetched and recorded in run-probe.sh's preflight
# output as the resolved digest of whichever tag is actually pulled).
# KL_PROBE_TARGET_IMAGE, when set, must be a verified image ID (not a bare
# tag a --image-tar bundle merely claims), resolved by run-probe.sh's own
# manifest check before this script ever runs.
IMAGE="${KL_PROBE_TARGET_IMAGE:-python:3.12.7-slim-bookworm}"

LABEL="kestrelynx.probe-target=true"
VOLUME="kl-probe-ext4vol-data-$KL_PROBE_RUN_ID"

# name_for KIND -> the deterministic, run-ID-qualified container name for
# one of this script's seven verification containers.
name_for() { echo "kl-probe-$1-$KL_PROBE_RUN_ID"; }

# pull_if_absent avoids a network fetch when the exact tag is already
# present — the case after `docker load` of a bundle run-probe.sh's
# --image-tar produced, which is the point of that option: a VPS running
# this script should not need to reach the registry at all once the bundle
# has been loaded.
pull_if_absent() {
	if ! docker image inspect "$1" >/dev/null 2>&1; then
		docker pull "$1" >&2
	fi
}

up() {
	pull_if_absent "$IMAGE"

	# Distinguishes "does not exist" (safe to proceed) from "could not be
	# checked" (aborts): a communication failure here must never be
	# silently treated as "the volume is not there".
	local existing
	if existing="$(docker volume inspect "$VOLUME" 2>&1)"; then
		echo "probe-targets.sh: refusing to reuse existing volume $VOLUME" >&2
		exit 1
	elif ! grep -qiE "no such volume" <<<"$existing"; then
		echo "probe-targets.sh: could not confirm whether volume $VOLUME already exists (daemon communication problem?): $existing" >&2
		exit 1
	fi
	ledger_create_volume "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$VOLUME"

	# The check above and `docker volume create` are not atomic: if another
	# volume by this same name is created in between, `docker volume
	# create` succeeds by silently reusing whatever already exists under
	# that name (a documented Docker CLI behavior, not a bug) rather than
	# failing — so the volume ledger_create_volume just "created" is not
	# necessarily this run's own until this is checked. Verified here,
	# before anything mounts it (the first mount is ext4vol below) — a
	# mismatch or an unconfirmable check aborts without ever mounting it.
	local vol_label vol_rc
	vol_label="$(inspect_owner_label volume "$VOLUME")" && vol_rc=0 || vol_rc=$?
	case "$vol_rc" in
	10)
		echo "probe-targets.sh: volume $VOLUME is gone immediately after being created; aborting" >&2
		exit 1
		;;
	20)
		echo "probe-targets.sh: could not confirm ownership of newly created volume $VOLUME (daemon communication problem?); aborting" >&2
		exit 1
		;;
	esac
	if [ "$vol_label" != "$KL_PROBE_RUN_ID" ]; then
		echo "probe-targets.sh: volume $VOLUME already existed under another owner (label=\"$vol_label\"); docker volume create reused it instead of making a new one, so this run refuses to mount it" >&2
		exit 1
	fi

	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for sameuid)" -d \
		--label "$LABEL" --label "kestrelynx.probe-kind=sameuid" \
		--user 65532:65532 \
		"$IMAGE" sleep infinity

	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for sockets)" -d \
		--label "$LABEL" --label "kestrelynx.probe-kind=sockets" \
		-v "$SCRIPT_DIR/probe-target-scripts/sockets.py:/probe/sockets.py:ro" \
		"$IMAGE" python3 /probe/sockets.py

	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for setuid)" -d \
		--label "$LABEL" --label "kestrelynx.probe-kind=setuid" \
		"$IMAGE" sh -c 'cp /bin/true /usr/local/bin/probe-setuid-true && chmod 4755 /usr/local/bin/probe-setuid-true && sleep infinity'

	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for ext4vol)" -d \
		--label "$LABEL" --label "kestrelynx.probe-kind=ext4vol" \
		-v "$VOLUME:/data" \
		"$IMAGE" sh -c 'mkdir -p /data && : > /data/kestrelynx-probe-ioctl-test && chmod 0666 /data/kestrelynx-probe-ioctl-test && sleep infinity'

	# Sleeps 1 second between execs, short enough that even a few seconds of
	# the probe's event-sampling window sees more than one. Read-only: never
	# given a kestrelynx.probe-kind label, so verifyTarget's kind dispatch
	# never runs an unsafe probe against it even if it were mistakenly
	# passed as --target-pid.
	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for execloop)" -d \
		--label "$LABEL" \
		"$IMAGE" sh -c 'while true; do /bin/true; sleep 1; done'

	# AppArmor is not present on every host this repository is developed
	# on; if the daemon rejects the security-opt outright, this container is
	# skipped rather than aborting the whole run, and run-probe.sh's
	# preflight step already reports AppArmor's presence so the gap is
	# visible in the run's own record rather than silently assumed. The
	# ledger entry is appended before the attempt regardless, so a partial
	# failure here still leaves nothing unaccounted for.
	if ! ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for unconfined)" -d \
		--label "$LABEL" \
		--security-opt apparmor=unconfined \
		"$IMAGE" sleep infinity; then
		echo "probe-targets.sh: $(name_for unconfined) could not be started (AppArmor likely unavailable on this host); continuing without it" >&2
	fi

	ledger_run_container "$KL_PROBE_LEDGER" "$KL_PROBE_RUN_ID" "$(name_for privileged)" -d \
		--label "$LABEL" \
		--privileged \
		"$IMAGE" sleep infinity

	echo "probe-targets.sh: verification containers started (run $KL_PROBE_RUN_ID)" >&2
}

case "${1:-}" in
up) up ;;
*)
	echo "usage: $0 up" >&2
	exit 2
	;;
esac
