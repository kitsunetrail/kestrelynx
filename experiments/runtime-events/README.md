# Runtime events experiment

**English** | [日本語](README.ja.md)

- This experimental tool uses bpftrace to record successful executions and file opens.
- It identifies the container associated with each event and converts the records into JSONL for the runtime-discovery harness.
- It is separate from the product binary and is not included in the container image.
- The [public development log](../../docs/development/runtime-event-evidence.md) records the motivation, measurements, and evidence limits.

## What it does

- Records the relationship between the tracing clock and wall-clock time.
- Builds and refreshes a table linking cgroups to containers over time.
- Collects events and converts them into JSONL with attribution and loss records.

## Requirements

- Linux with BTF and the seven required tracepoints.
- The tracepoints are `sched:sched_process_exec` and `syscalls:sys_enter_open`, `sys_exit_open`, `sys_enter_openat`, `sys_exit_openat`, `sys_enter_openat2`, and `sys_exit_openat2`.
- Live measurements used bpftrace v0.25.0; the minimum working version remains undetermined.
- Native Docker Engine with cgroup v2 and access to the host cgroup hierarchy.
- Root access through sudo.
- Go 1.26.4, Bash, jq, and the additional [runtime-discovery requirements](../runtime-discovery/README.md#requirements) for automated measurements.

## Try it

- Run commands from the repository root.
- The simplest route uses the runtime-discovery tools.
- `check-tracing.sh` checks script loading and collection and conversion of known events.
- `case-run.sh` runs collection, independent ground-truth preparation, and matching.

```sh
mkdir -p experiments/runtime-discovery/out
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
# Case 13: repeated short-lived processes
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512
```

- Check `experiments/runtime-discovery/out/check-tracing/smoke.log` and `events.jsonl`, then the measurement's `record.md` and `csv_hc/event_drops.csv`.

### Use it on its own

- Replace `<running-container>` with a running container that provides `sh`, `/bin/true`, and `/etc/os-release`.
- This example joins that container and records a short window under `attach_running`.
- Save generated files under git-ignored `./out/` and keep traces, observations, and results out of commits.

```sh
mkdir -p ./out
go build -o ./out/runtime-events ./experiments/runtime-events
sudo bash -s -- '<running-container>' <<'SH'
set -euo pipefail
./out/runtime-events clock -out ./out/clock.json
./out/runtime-events cgroup-map -out ./out/cgroup-map.json
bpftrace experiments/runtime-events/bpftrace/runtime-events-nofilter.bt \
  > ./out/trace.txt \
  2> >(while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$line"
  done > ./out/trace.err) &
tracer_pid=$!
trap 'kill -INT "$tracer_pid" 2>/dev/null || true; wait "$tracer_pid" 2>/dev/null || true' EXIT
bash experiments/runtime-discovery/cases/run.sh attach-check ./out/trace.txt
window_start=$(date -u +%FT%T.%NZ)
window_end=$(date -u -d "$window_start + 6 seconds" +%FT%T.%NZ)
docker exec "$1" sh -c '/bin/true; cat /etc/os-release >/dev/null'
sleep 6
kill -INT "$tracer_pid"
wait "$tracer_pid" || true
stop_instant=$(date -u +%FT%T.%NZ)
trap - EXIT
./out/runtime-events cgroup-map \
  -merge ./out/cgroup-map.json -out ./out/cgroup-map.json
cat ./out/trace.txt ./out/trace.err |
  ./out/runtime-events convert -in - -out ./out/events.jsonl \
    -cgroup-map ./out/cgroup-map.json \
    -config-id bpftrace-v2-nofilter-64p -script-version 3 \
    -filter runtime-events-nofilter.bt -variant nofilter \
    -sync attach_running -buffer-pages 64 -path-buffer 256 -attached \
    -boot-epoch "$(jq -r .boot_epoch ./out/clock.json)" \
    -clock-error-ns "$(jq -r .error_ns ./out/clock.json)" \
    -window-start "$window_start" -window-end "$window_end" \
    -stopped-at "$stop_instant"
SH
```

## Scripts

| File | Purpose | Buffer |
| --- | --- | --- |
| `bpftrace/runtime-events-nofilter.bt` | Collect executions and opens without a path filter | 64 pages |
| `bpftrace/runtime-events-nofilter-256p.bt` | Collect with a larger buffer | 256 pages |
| `bpftrace/runtime-events-nofilter-512p.bt` | Collect with a larger buffer | 512 pages |
| `bpftrace/runtime-events.bt` | Trial collection with a path filter | 64 pages |
| `bpftrace/runtime-events-filtered-a.bt` | Trial using a shorter path for filtering | 64 pages |
| `bpftrace/runtime-events-filtered-b.bt` | Trial using a shorter string buffer | 64 pages |

- `runtime-events.bt`, `runtime-events-filtered-a.bt`, and `runtime-events-filtered-b.bt` remain as records of filtered attempts rejected by the verifier in the measured environment.

## Reading results

| Line in `events.jsonl` | Meaning |
| --- | --- |
| Header: `events_header` | Collection settings, clock information, and startup and attachment confirmation |
| Event: `event` | An execution or open, its outcome, path, and container attribution |
| Trailer: `events_trailer` | End metadata and recorded losses |

- Check lost-event counts separately from the number of loss notifications.
- Separate unmatched open halves inside the observation window from remnants at its boundaries.
- Check whether events have container attribution and usable paths.
- `observed` means the harness confirmed startup and attachment without reported window incompleteness.
- `degraded` means startup and attachment were confirmed, but losses, stopping before the planned end, or unmeasured loss categories limit the window.

## Limitations

- File-open collection covers `open`, `openat`, and `openat2`; `creat` and io_uring opens are outside its scope.
- Opening a file does not prove that its contents were read or its dependency code executed.
- Evidence can only raise priority; missing evidence never establishes non-use, safety, or grounds for lowering priority.
- Only amd64 has been tested.
- Nested PID namespaces can give the observer and workload different process numbers; matching needs namespace identity as well as numbers.

## Details

- [Inputs and outputs](REFERENCE.md#inputs-and-outputs) describe raw trace versions and JSONL fields.
- [Command flags](REFERENCE.md#command-flags) list all options and collection configuration checks.
- [Measurement order](REFERENCE.md#measurement-order) covers startup, readiness, helper commands, conversion, and matching.
- [Counters and losses](REFERENCE.md#counters-and-losses) explain boundary remnants, partial events, and observation states.
- [Clocks](REFERENCE.md#clocks) and [cgroup validity](REFERENCE.md#cgroup-table-and-validity) describe time conversion and attribution periods.
- [Checks and limitations](REFERENCE.md#checking-without-docker) cover saved inputs, measurement history, and detailed cautions.
