#!/usr/bin/env bash
# Shared ledger helpers for run-probe.sh and probe-targets.sh.
#
# Every container or volume either script creates is recorded, by its own
# deterministic (run-ID-qualified) name, into a ledger file BEFORE the
# command that creates it runs — so the ledger reflects reality even if that
# command is interrupted or fails partway through. Recording a name in the
# ledger is never, by itself, treated as proof of ownership: every resource
# this library creates also carries a `kestrelynx.probe-run=<run ID>` Docker
# label, and cleanup only ever removes a ledger-recorded name after
# `docker inspect` confirms that label's value matches the run ID doing the
# cleanup. A name that exists but carries a different (or no) label is left
# untouched and reported as a warning — this is what makes a name collision
# (this run's own generated name happening to match something already
# there) safe: the pre-existing thing is never assumed to be this run's.
#
# Ledger line formats (strictly validated on read — see ledger_cleanup):
#   container <name>
#   volume <name>
#   id <name> <resolved-container-id-or-volume-name>
#
# A malformed line anywhere in the ledger halts the entire cleanup pass
# without removing anything: a ledger that cannot be trusted to describe
# what was created is not a safe basis for deciding what to remove.

# run_id_is_valid ID reports (via exit status) whether ID is safe to use as
# a resource-name component and as a Docker label value: alphanumeric and
# hyphen only, 1-64 characters. This is deliberately restrictive — a run ID
# is never meant to carry arbitrary characters — and is checked both right
# after this library's own generator produces one (defense in depth, not
# because the generator is expected to fail) and before it is ever
# substituted into a container/volume name or label.
run_id_is_valid() {
	[[ "$1" =~ ^[A-Za-z0-9-]{1,64}$ ]]
}

# ledger_append LEDGER KIND REST... appends one line "KIND REST...".
ledger_append() {
	local ledger="$1" kind="$2"
	shift 2
	printf '%s %s\n' "$kind" "$*" >>"$ledger"
}

# ledger_line_valid LINE checks LINE against the exact formats this library
# ever writes (see the file header). Names are restricted to the character
# set Docker itself allows in a resource name (alphanumeric, '.', '_', '-');
# an id is either a 64-hex container ID or a volume's own name (same
# character set).
ledger_line_valid() {
	local line="$1"
	[[ "$line" =~ ^container\ [A-Za-z0-9._-]{1,255}$ ]] && return 0
	[[ "$line" =~ ^volume\ [A-Za-z0-9._-]{1,255}$ ]] && return 0
	[[ "$line" =~ ^id\ [A-Za-z0-9._-]{1,255}\ [A-Za-z0-9._-]{1,255}$ ]] && return 0
	return 1
}

# docker_inspect_raw KIND NAME FORMAT prints `docker inspect`'s own raw
# formatted output for a single resource and returns 0, or returns without
# printing anything:
#   10  the resource does not exist (Docker's own "no such ..." response)
#   20  the check itself could not be performed (e.g. the daemon could not
#       be reached) — NEVER treated the same as "does not exist"
docker_inspect_raw() {
	local kind="$1" name="$2" format="$3" out
	if out="$(docker inspect --type "$kind" -f "$format" "$name" 2>&1)"; then
		printf '%s\n' "$out"
		return 0
	fi
	if grep -qiE "no such (container|volume|object)" <<<"$out"; then
		return 10
	fi
	echo "docker_inspect_raw: could not inspect $kind $name: $out" >&2
	return 20
}

# inspect_owner_label KIND NAME prints the resource's own
# kestrelynx.probe-run label value (possibly empty). Same return contract as
# docker_inspect_raw.
inspect_owner_label() {
	local kind="$1" name="$2" format
	case "$kind" in
	container) format='{{index .Config.Labels "kestrelynx.probe-run"}}' ;;
	volume) format='{{index .Labels "kestrelynx.probe-run"}}' ;;
	*)
		echo "inspect_owner_label: unrecognized kind $kind" >&2
		return 20
		;;
	esac
	docker_inspect_raw "$kind" "$name" "$format"
}

# inspect_owner_label_and_id NAME (containers only) prints
# "LABEL<TAB>FULL-ID" from a single docker inspect call, so a caller can act
# on (stop, rm) the exact container it just confirmed ownership of by that
# container's own ID — never by name, which a stop/rm-by-name could apply to
# a different container that came to hold the same name after this check
# ran. Same return contract as docker_inspect_raw. Volumes have no separate
# ID (their name is their identity), so this has no volume form.
inspect_owner_label_and_id() {
	local name="$1"
	docker_inspect_raw container "$name" $'{{index .Config.Labels "kestrelynx.probe-run"}}\t{{.Id}}'
}

# KL_PENDING_RUN_PIDS tracks, in this shell process, the PID of every
# `docker run` ledger_run_container has backgrounded that has not yet been
# waited on. It is appended to before that function's own cidfile-poll loop
# runs, so a PID is recorded even if this shell exits (e.g. via a signal)
# while still inside that loop — see ledger_wait_pending.
declare -a KL_PENDING_RUN_PIDS=()

# ledger_wait_pending waits for every PID in KL_PENDING_RUN_PIDS that this
# shell has not already waited on, so a caller (typically a termination
# trap, right before it runs ledger_cleanup) can be sure no `docker run`
# this shell itself started is still in flight — cleanup's own docker
# inspect calls would otherwise race a creation that is still completing in
# the background. Waiting on a PID this shell already reaped is harmless
# (silently ignored): most of the PIDs here will already be gone by the
# time this runs during ordinary, non-interrupted execution.
ledger_wait_pending() {
	local pid
	for pid in "${KL_PENDING_RUN_PIDS[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
}

# ledger_run_container LEDGER RUN_ID NAME -- DOCKER_RUN_ARGS...
#
# Records NAME in the ledger before creating anything, then runs
# `docker run --name NAME --label kestrelynx.probe-run=RUN_ID --cidfile
# <tmp> ARGS...`, recording the resolved container ID as soon as Docker
# reports it (via the cidfile, which Docker writes at container-creation
# time — before a foreground run's own blocking start+attach phase, so this
# works the same way for `-d` and plain/`--rm` runs). The caller must not
# also pass --name or --cidfile. Returns docker run's own exit status.
ledger_run_container() {
	local ledger="$1" run_id="$2" name="$3"
	shift 3
	ledger_append "$ledger" container "$name"

	local cidfile
	cidfile="$(mktemp -u)" # -u: name only; docker refuses to write to an existing file
	docker run --name "$name" --label "kestrelynx.probe-run=$run_id" --cidfile "$cidfile" "$@" &
	local run_pid=$!
	KL_PENDING_RUN_PIDS+=("$run_pid")

	# Poll for the cidfile rather than waiting on run_pid first: for a
	# foreground (non -d) run, run_pid does not return until the container
	# exits, but the cidfile appears as soon as the container is created,
	# well before that.
	local id="" waited=0
	while [ "$waited" -lt 10000 ]; do
		if [ -s "$cidfile" ]; then
			id="$(cat "$cidfile")"
			break
		fi
		sleep 0.05
		waited=$((waited + 50))
	done
	if [ -n "$id" ]; then
		ledger_append "$ledger" id "$name" "$id"
	fi

	local status=0
	wait "$run_pid" || status=$?
	rm -f "$cidfile"
	return "$status"
}

# ledger_create_volume LEDGER RUN_ID NAME creates a Docker volume, recording
# NAME in the ledger before creation. A volume's own name is its identity —
# no separate ID to record.
ledger_create_volume() {
	local ledger="$1" run_id="$2" name="$3"
	ledger_append "$ledger" volume "$name"
	docker volume create --label "kestrelynx.probe-run=$run_id" "$name" >&2
}

# ledger_cleanup LEDGER RUN_ID removes every container/volume LEDGER
# recorded, but only after confirming, via inspect_owner_label, that the
# resource currently carries this exact RUN_ID's ownership label — a name
# that exists with a different or missing label (someone else's resource
# that happens to share the name) is left untouched and reported. Any
# malformed line halts the whole pass before removing anything.
#
# Returns:
#   0  every entry was either removed or confirmed already gone
#   1  at least one entry could not be removed (ownership mismatch, or the
#      daemon could not be reached for it) — see stderr for which
#   3  the ledger itself contains a malformed line; nothing was removed
ledger_cleanup() {
	local ledger="$1" run_id="$2"
	if [ ! -f "$ledger" ]; then
		echo "ledger_cleanup: no ledger at $ledger; nothing was ever recorded, nothing to remove" >&2
		return 0
	fi

	local -a lines
	mapfile -t lines <"$ledger"
	local line
	for line in "${lines[@]}"; do
		[ -n "$line" ] || continue
		if ! ledger_line_valid "$line"; then
			echo "ledger_cleanup: REFUSING to clean up — malformed ledger line: $line" >&2
			echo "ledger_cleanup: the following resources may still need manual removal:" >&2
			printf '  %s\n' "${lines[@]}" >&2
			return 3
		fi
	done

	# Build the set of (kind, name) targets, most-recently-created first,
	# and the name->recorded-ID cross-reference from "id" lines (containers
	# only; a volume's own name is already its identity, so
	# ledger_create_volume never writes one).
	local -a targets=()
	local -A recorded_ids=()
	local kind name rest
	for line in "${lines[@]}"; do
		[ -n "$line" ] || continue
		read -r kind name rest <<<"$line"
		if [ "$kind" = "id" ]; then
			recorded_ids["$name"]="$rest"
		fi
	done
	for ((i = ${#lines[@]} - 1; i >= 0; i--)); do
		read -r kind name rest <<<"${lines[i]}"
		[ "$kind" = "container" ] || [ "$kind" = "volume" ] || continue
		local key="$kind $name"
		local seen=0
		for t in "${targets[@]}"; do
			[ "$t" = "$key" ] && seen=1 && break
		done
		[ "$seen" = 1 ] || targets+=("$key")
	done

	local overall=0
	for t in "${targets[@]}"; do
		read -r kind name <<<"$t"
		local label id rc
		id=""
		if [ "$kind" = "container" ]; then
			# Label and ID come from the SAME inspect call: acting on $name
			# again after this (a second, separate inspect, or a stop/rm by
			# name) would leave a window in which $name could have been
			# reassigned to a different container — stop/rm below use $id,
			# never $name, so they can only ever act on the exact container
			# this check just confirmed ownership of.
			local combined
			combined="$(inspect_owner_label_and_id "$name")" && rc=0 || rc=$?
			case "$rc" in
			10) continue ;; # already gone; nothing to do
			20)
				echo "ledger_cleanup: WARNING: could not confirm ownership of $kind $name (daemon check failed); not touching it" >&2
				overall=1
				continue
				;;
			esac
			label="${combined%%$'\t'*}"
			id="${combined#*$'\t'}"
			# Cross-check against the ID recorded at creation time, when one
			# was recorded (ledger_run_container's cidfile poll can time out
			# without ever recording one — id is then simply "", and this
			# check is skipped, but the stop/rm below still uses the ID this
			# same inspect call just returned).
			if [ -n "${recorded_ids[$name]:-}" ] && [ "$id" != "${recorded_ids[$name]}" ]; then
				echo "ledger_cleanup: WARNING: $kind $name's current ID ($id) does not match the one recorded at creation (${recorded_ids[$name]}); refusing to remove it" >&2
				overall=1
				continue
			fi
		else
			label="$(inspect_owner_label "$kind" "$name")" && rc=0 || rc=$?
			case "$rc" in
			10) continue ;;
			20)
				echo "ledger_cleanup: WARNING: could not confirm ownership of $kind $name (daemon check failed); not touching it" >&2
				overall=1
				continue
				;;
			esac
		fi
		if [ "$label" != "$run_id" ]; then
			echo "ledger_cleanup: WARNING: $kind $name exists but is NOT owned by run $run_id (label=\"$label\"); refusing to remove it" >&2
			overall=1
			continue
		fi
		case "$kind" in
		container)
			docker stop -t 5 "$id" >/dev/null 2>&1 || true
			docker rm -f "$id" >/dev/null 2>&1 || true
			;;
		volume)
			# Volumes have no separate ID — a volume's name is its whole
			# identity, so there is no ID-based form of `docker volume rm`.
			docker volume rm -f "$name" >/dev/null 2>&1 || true
			;;
		esac
	done
	return "$overall"
}

# ledger_verify_removed LEDGER RUN_ID checks that every entry LEDGER
# recorded and this run owned is now gone. A resource that still exists but
# is NOT owned by RUN_ID (the pre-existing-collision case) does not count
# against verification — it was correctly left alone. Returns:
#   0  every entry owned by RUN_ID is confirmed gone
#   1  at least one entry owned by RUN_ID is confirmed still present
#   2  a check itself could not be performed — never treated as "gone"
ledger_verify_removed() {
	local ledger="$1" run_id="$2"
	[ -f "$ledger" ] || return 0
	local -a lines
	mapfile -t lines <"$ledger"
	local kind name rest remaining=0
	local -A checked=()
	for line in "${lines[@]}"; do
		[ -n "$line" ] || continue
		read -r kind name rest <<<"$line"
		[ "$kind" = "container" ] || [ "$kind" = "volume" ] || continue
		local key="$kind $name"
		[ -n "${checked[$key]:-}" ] && continue
		checked[$key]=1

		local label rc
		label="$(inspect_owner_label "$kind" "$name")" && rc=0 || rc=$?
		case "$rc" in
		10) continue ;; # gone -- good
		20)
			echo "ledger_verify_removed: could not check $kind $name: daemon check failed" >&2
			return 2
			;;
		esac
		if [ "$label" = "$run_id" ]; then
			echo "ledger_verify_removed: $kind $name (owned by this run) is still present" >&2
			remaining=1
		fi
		# label != run_id here means it exists but is someone else's
		# (or unlabeled) resource -- not a verification failure.
	done
	[ "$remaining" = 0 ]
}
