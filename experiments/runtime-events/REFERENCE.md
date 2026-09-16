# Runtime events reference

**English** | [日本語](REFERENCE.ja.md)

- The [README](README.md) covers the purpose, requirements, commands to try, scripts, and result interpretation.
- Commands here run from the repository root.
- Manual examples save generated files under git-ignored `./out/`.
- Automated measurements use `experiments/runtime-discovery/out/`.
- Traces, observations, and results must remain outside commits.
- Motivation, measurement plans, and evidence limits are recorded in the [public development log](../../docs/development/runtime-event-evidence.md).

## Inputs and outputs

### Raw trace records

- Scripts write line-oriented text to stdout.
- Fields are separated by `|`.
- Paths occupy the final field so embedded `|` characters are preserved.
- Current scripts use format version `3`.

```text
V|<format version>|<string buffer length>|<buffer pages>|<variant>
E|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<cgroup id>|<leader start ns>|<comm>|<raw path>
O|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<cgroup id>|<leader start ns>|<dirfd>|<raw path>
X|<monotonic ns>|<pid>|<tid>|<ns pid>|<ns tid>|<pid ns inum>|<return value>|<entry's monotonic ns>
```

| Record | Meaning |
| --- | --- |
| `V` | Format version, string length, buffer pages, and script variant |
| `E` | Successful execution |
| `O` | File-open entry with its path |
| `X` | File-open outcome with its return value and recorded entry time |

| Format version | Identity fields | Conversion option |
| --- | --- | --- |
| `1` | No namespace-local PID/TID or PID namespace identifier | `-script-version 1` |
| `2` | Adds namespace-local PID/TID, without the PID namespace identifier | `-script-version 2` |
| `3` | Includes namespace-local PID/TID and their PID namespace identifier | `-script-version 3` |

- Current `X` records carry the entry's monotonic nanoseconds to identify the corresponding entry.
- Older five-field exit records use process identity and an outcome time no earlier than the entry.
- Counter maps print on exit as `@<name>: <value>`.
- Preserve stderr alongside stdout.
- Messages such as `Lost 17 events` contribute to loss accounting.
- Ordinary startup banners and warnings without record separators are ignored.
- The converter also accepts these optional records.

```text
C|<monotonic ns>|<Unix wall-clock ns>
M|<counter name>|<value>
```

- Supplied scripts emit neither `C` nor `M`.
- A wrapper can prepend a paired clock reading as `C`.
- A `C` record overrides the supplied epoch for subsequent events.
- Place clock records before the events they describe.

### Event JSONL

- Conversion writes an `events_header`, event records, and an `events_trailer`.
- Every line uses `record` to identify its kind.

| Header fields | Meaning |
| --- | --- |
| `record` | `events_header` |
| `config_id`, `sync` | Collection configuration and workload ordering |
| `method`, `version`, `variant`, `filter` | Collection method, trace format, script variant, and filter metadata |
| `buffer_pages`, `path_buffer_len` | Recording-buffer pages and string-buffer length |
| `tracepoints` | Recorded attachment points |
| `started_at` | Recorded start metadata |
| `attached_at` | Attachment-completion time when available |
| `boot_epoch`, `clock_source`, `clock_error_ns`, `clock_note` | Clock conversion and its recorded uncertainty |
| `started`, `attached` | Startup and attachment confirmation |
| `container_id` | Optional intended target |

| Event fields | Meaning |
| --- | --- |
| `record`, `event` | `record` is `event`; `event` is `exec` or `open` |
| `ts`, `monotonic_ns` | Converted UTC time and original monotonic nanoseconds; opens use entry time |
| `pid`, `tid` | Initial PID namespace process and thread numbers in current scripts |
| `starttime` | Leader start time converted to a string of process-start ticks |
| `ns_pid`, `ns_tid` | Process and thread numbers in the task's own PID namespace; zero for older input without these fields |
| `pid_ns` | Identifier of the namespace containing `ns_pid` and `ns_tid`; omitted when unavailable |
| `raw_path`, `path` | Recorded path and cleaned or joined path; unresolved paths omit `path` |
| `path_resolved`, `path_truncated` | Resolution success and whether the path filled the string buffer |
| `ok` | Always true for executions; true for opens with a nonnegative return value |
| `ret` | Return value; zero is omitted |
| `cgroup_id`, `container_id`, `cgroup_depth`, `attribution` | Table-based attribution with `container` or `unattributed` status |
| `comm`, `source` | Execution command name and source label; all three open syscalls currently use `sys_enter_openat` |

| Trailer fields | Meaning |
| --- | --- |
| `record` | `events_trailer` |
| `ended_at` | End metadata |
| `drops` | Counters and completeness information described below |
| `detach_confirmed`, `detach_note` | Format fields for detachment; this converter does not confirm detachment |

- Failed opens remain in JSONL with `ok:false`.
- Unmatched open halves are counted without emitting an event.
- Absolute paths are cleaned lexically.
- Filesystem symlinks are not resolved.
- CWD-relative paths require a matching `-cwd-map` entry.
- Paths relative to another directory descriptor remain unresolved.
- Events without process-generation information cannot use a working-directory entry.
- Namespace-local numbers can repeat across namespaces.
- Compare them together with their namespace identity.
- Host-occurrence matching requires `pid_ns` on both the event and the independent occurrence.
- Namespace-local numbers also support container-log matching when the host itself is in a child PID namespace.

## Command flags

- Build the executable before live measurements.
- Create the parent directory before writing clock output.

```sh
mkdir -p ./out
go build -o ./out/runtime-events ./experiments/runtime-events
./out/runtime-events clock -h
./out/runtime-events cgroup-map -h
./out/runtime-events convert -h
```

### clock

| Flag | Default | Purpose |
| --- | --- | --- |
| `-out` | stdout | Write clock JSON to a file |

### cgroup-map

| Flag | Default | Purpose |
| --- | --- | --- |
| `-root` | `/sys/fs/cgroup` | Hierarchy root to walk |
| `-out` | `./out/cgroup-map.json` | Output table |
| `-merge` | empty | Previous table to refresh while retaining history |

### convert

| Flag | Default | Purpose |
| --- | --- | --- |
| `-in` | required | Trace input; `-` reads stdin |
| `-out` | `./out/events.jsonl` | Output event log |
| `-cgroup-map` | empty | Attribution table; omission leaves every event unattributed |
| `-config-id` | required | Identifier for the method, script, filter, and buffer configuration |
| `-sync` | required | Ordering label: `startup` or `attach_running` |
| `-method` | `bpftrace` | Collection-method metadata |
| `-script-version` | `3` | Format-version metadata checked against the second `V` field; empty adopts the trace value |
| `-variant` | empty | Variant metadata checked against the fifth `V` field; empty adopts the trace value |
| `-filter` | empty | Filter-description metadata |
| `-buffer-pages` | required | Actual positive buffer size in pages, matching the `V` record |
| `-tracepoints` | empty | Comma-separated attachment-point metadata |
| `-container-id` | empty | Intended target metadata; does not filter events or force attribution |
| `-boot-epoch` | empty | Wall time at monotonic zero in RFC3339 with optional nanoseconds |
| `-clock-error-ns` | `0` | Recorded clock-pair error bound |
| `-clock-source` | `CLOCK_MONOTONIC` | Clock shared by trace stamps and epoch conversion |
| `-clock-ticks` | `100` | Ticks per second for process-generation conversion |
| `-path-buffer` | Trace `V` value, otherwise `256` | String length for truncation detection; an explicit value must match the trace |
| `-window-start` | empty | Planned observation start in RFC3339 |
| `-window-end` | empty | Planned observation end in RFC3339 |
| `-stopped-at` | empty | Actual wrapper-observed stop in RFC3339 |
| `-stop-reason` | empty | Explanation of the stop |
| `-started` | `true` | Whether the tracer started; use `-started=false` for startup failure |
| `-attached` | `false` | Whether a known event confirmed attachment |
| `-attached-at` | empty | Attachment-completion time in RFC3339 with optional nanoseconds when timestamped stderr supplies none |
| `-cwd-map` | empty | Comma-separated `<pid>@<starttime>[@<from>-<to>]=<dir>` entries |

- `-boot-epoch` is required when the input contains no valid `C` record.

- `-cwd-map` requires the process-generation start time.
- Its RFC3339 validity period is optional.
- A process number alone is insufficient because numbers can be reused.
- Use `-script-version 2` for traces without the PID namespace identifier.
- Use `-script-version 1` for older traces without namespace-local numbers.
- Both window flags are required to classify boundary remnants.
- Attachment time is reference metadata and does not replace the observation window.
- When `-attached-at` and timestamped stderr both supply attachment times, they must identify the same instant.
- Conflicting attachment times cause conversion to fail.
- Conversion flags describe completed collection.
- They do not configure the running tracer.
- The converter rejects buffer-size or string-length disagreement with the trace's `V` record.
- Record the settings actually used, including environment overrides.
- Keep the script configuration, version line, and configuration identifier consistent.

### Script configurations

- The three unfiltered scripts collect successful executions and all observed `open`, `openat`, and `openat2` calls.
- They use a string-buffer length of `256`.
- All six scripts observe host-wide activity.
- Container attribution happens during conversion.
- Relevant paths are selected in user space after conversion.

| Collection script | Buffer pages | Variant | Configuration ID |
| --- | --- | --- | --- |
| `bpftrace/runtime-events-nofilter.bt` | `64` | `nofilter` | `bpftrace-v2-nofilter-64p` |
| `bpftrace/runtime-events-nofilter-256p.bt` | `256` | `nofilter-256p` | `bpftrace-v2-nofilter-256p` |
| `bpftrace/runtime-events-nofilter-512p.bt` | `512` | `nofilter-512p` | `bpftrace-v2-nofilter-512p` |

- The `v2` in these configuration IDs is part of the name.
- It does not select trace format version `2`.
- `runtime-events-nofilter.bt` uses format version `3` and emits `V|3|256|64|nofilter`.
- Its configuration is as follows.

```text
config = {
    max_strlen = 256;
    perf_rb_pages = 64;
}
```

- Its conversion metadata uses `-config-id bpftrace-v2-nofilter-64p`, `-filter runtime-events-nofilter.bt`, and `-variant nofilter`.
- The filtered experiment records are `runtime-events.bt`, `runtime-events-filtered-a.bt`, and `runtime-events-filtered-b.bt`.
- They test 12 path substrings: `/node_modules`, `site-packages`, `dist-packages`, `/lib`, `/app`, `.so`, `.jar`, `.py`, `.js`, `.mjs`, `.cjs`, and `package.json`.
- `filtered-b` uses a string-buffer length of `160`.
- `filtered-a` filters the prefix read with `str(args->filename, 96)` and uses the configured 256-byte string buffer for output.
- All three filtered scripts use a 64-page output buffer.
- All three failed `--dry-run` on Linux 6.6.114 WSL2 with bpftrace v0.25.0 and `Error code: -28`.
- Their 12 `strcontains` comparisons exceeded the verifier's limit of 8192 jumps in a sequence.
- The failure was not a stack overflow.
- Loading these filtered scripts on other kernels remains unverified.

## Measurement order

- Establish observation before triggering the workload under `startup`.
- Stop the procedure when a required check fails.
- Use the following nine steps for a complete measurement.

1. **Clock:** run `./out/runtime-events clock -out ./out/clock.json` on the tracing host.
2. **Cgroup map:** run `sudo ./out/runtime-events cgroup-map -out ./out/cgroup-map.json`.
3. **Start bpftrace:** retain stdout, stderr, and the tracer's process identity.
4. **Attach check:** run `bash experiments/runtime-discovery/cases/run.sh attach-check ./out/trace.txt` to execute a uniquely named copy of `/bin/true` and wait for its trace marker.
5. **Wait ready:** start runtime-discovery collection with the target registered through `-expect`, start the waiting case, refresh cgroups, and wait for the current collector run to become ready.
6. **Fire:** run `fire <case>` after registration, cgroup refresh, and readiness succeed, then let the workload and observation continue through the planned window.
7. **Stop:** stop the tracer, let counters flush, record observed termination, refresh cgroups, and copy workload logs before removing containers.
8. **Convert:** combine stdout and stderr with the clock relation, attachment result, configuration, planned window, and observed stop.
9. **Match:** pass JSONL through runtime-discovery `match -events` with the observation, scan, case definition, and independent ground truth.

- Start the collection script at step 3.

```sh
sudo bpftrace experiments/runtime-events/bpftrace/runtime-events-nofilter.bt \
  > ./out/trace.txt \
  2> >(while IFS= read -r line; do
    printf '%s %s\n' "$(date -u +%FT%T.%NZ)" "$line"
  done > ./out/trace.err) &
```

### Case-helper commands

| Command | Arguments and behavior |
| --- | --- |
| `register-cgroups` | `<table> [runtime-events binary]`; merges a readable table or creates one; binary defaults to `runtime-events` |
| `attach-check` | `<trace> [timeout seconds]`; default timeout `30`; confirms receipt of a known execution |
| `ready-run-id` | `<ready file> [timeout seconds] [collector start, RFC3339]`; default timeout `60`; waits for and prints a nonempty run identifier |
| `wait-ready` | `<ready file> <expected run id> [timeout seconds]`; required run ID and default timeout `120`; checks readiness and run identity |
| `fire` | `<case>`; writes to the waiting workload's signaling pipe |
| `dump-logs` | `<case> <directory>`; copies available `usage.jsonl` and `occurrences.jsonl` through host procfs |
| `host-run` | `<log> [iterations] [interval seconds]`; runs the host workload for attribution controls |

- Invoke helpers through `bash experiments/runtime-discovery/cases/run.sh`.
- Use root where host-file access requires it.
- Refresh the table after the container exists and before firing.

```sh
sudo bash experiments/runtime-discovery/cases/run.sh \
  register-cgroups ./out/cgroup-map.json ./out/runtime-events
```

- Use a fresh readiness-file path.
- Obtain the collector's `run_id` with `ready-run-id` after starting the collector.
- Pass that ID as the required second argument to `wait-ready`.
- Supplying the collector start instant as the third argument to `ready-run-id` rejects older reports.
- Omitting that instant returns the identifier with a warning that it cannot be tied to the current run.
- `attach-check` confirms execution delivery only.
- Validate open entry and outcome delivery separately during the first live run.
- A startup message alone does not confirm attachment.

### Conversion and matching

- In this example, the wrapper has saved the planned start and end as `$window_start` and `$window_end`.
- `$stop_instant` is when the wrapper observed tracer termination.
- Pass `-attached` only after the known-event check succeeds.

```sh
cat ./out/trace.txt ./out/trace.err |
  ./out/runtime-events convert -in - \
    -cgroup-map ./out/cgroup-map.json \
    -config-id bpftrace-v2-nofilter-64p -script-version 3 \
    -filter runtime-events-nofilter.bt -variant nofilter \
    -sync startup -buffer-pages 64 -path-buffer 256 -attached \
    -boot-epoch "$(jq -r .boot_epoch ./out/clock.json)" \
    -clock-error-ns "$(jq -r .error_ns ./out/clock.json)" \
    -stopped-at "$stop_instant" \
    -window-start "$window_start" -window-end "$window_end" \
    -out ./out/events.jsonl
```

- Add `-events ./out/events.jsonl` to the [runtime-discovery match command](../runtime-discovery/REFERENCE.md#matching-and-teardown).
- Event JSONL is observation input.
- Do not use it to construct the independent truth against which it is scored.
- Use `-sync attach_running` when joining an already running workload.
- Record that ordering condition separately from `startup`.

## Counters and losses

### Trailer counters

| `drops` field | Meaning |
| --- | --- |
| `lost_events` | Total events reported lost |
| `lost_notifications` | Number of loss messages |
| `enter_exit_unmatched` | Unmatched open halves not classified as boundary remnants |
| `enter_exit_unmatched_boundary` | Unmatched open halves classified by the boundary rules below |
| `map_overflow` | Reported map overflows, including measured insertion failures |
| `unmeasured` | Descriptions of loss categories that were not measured |
| `path_read_failures` | Sum of reported failures, falling back to empty emitted paths when zero |
| `path_truncations` | Paths that filled the string buffer |
| `convert_failures` | Malformed records |
| `identity_unavailable` | Events without usable process or thread identity |
| `unmatched_identity_unavailable` | Unmatched halves with missing process or thread identity, already included in unmatched totals |
| `events_before_filter`, `events_after_filter` | Script counters with execution counts added to both |
| `stopped_early`, `stopped_at`, `gap_seconds`, `stop_reason` | Observed stop and the gap before the planned window end |

- One loss notification can represent many lost events.
- Keep `lost_events` and `lost_notifications` separate.
- Preserve both trace streams to retain counters and loss messages.
- Missing stop time cannot be inferred from the last event.
- Preserve the wrapper's observation of termination.

### Map insertion failures

- Current scripts measure per-thread map insertion failures with a key-presence check.
- They explicitly emit `@map_insert_failed` at `END`, including zero.
- Conversion adds this count to `map_overflow`.
- This category remains unmeasured only when the input omits its counter.
- Duplicate `map_insert_failed` reports use the maximum value rather than their sum.
- When the aggregated `events_after_filter` count is zero, conversion uses the output event count.
- Supplying `-window-end` without `-stopped-at` adds an unmeasured entry because collection through the planned end cannot be established.
- A trace containing no records also adds an unmeasured entry.
- An omitted counter adds an `unmeasured` entry.
- An otherwise started and attached window then becomes `degraded`.
- An explicit zero measures this failure category alone.
- It does not establish that every loss category is zero.

### Boundary remnants

- Classification requires both `-window-start` and `-window-end`.
- The observation window includes both endpoints.
- An unmatched entry is a boundary remnant when its own timestamp is outside the window.
- An unmatched exit with a recorded entry time is a boundary remnant when that entry time is outside the window.
- An unmatched exit without a recorded entry time is a boundary remnant only when its own timestamp precedes the window start.
- All other unmatched halves count toward `enter_exit_unmatched`.
- This includes exits after the window end whose entry time is unavailable.
- Without both window flags, every unmatched half counts toward `enter_exit_unmatched`.
- Boundary remnants count toward `enter_exit_unmatched_boundary`.
- Attachment-completion time does not replace these window rules.

### Partial events and observation state

- The harness reports observation state separately from partial-event counts.

| State | Meaning |
| --- | --- |
| `not_attempted` | Event collection was not attempted |
| `failed` | Startup or attachment was not confirmed |
| `observed` | Startup and attachment were confirmed without reported window incompleteness |
| `degraded` | Confirmed collection has reported incompleteness or unmeasured loss categories |

- Positive `lost_events`, `lost_notifications`, `convert_failures`, `map_overflow`, or `enter_exit_unmatched` degrades confirmed collection.
- `stopped_early:true` or nonempty `unmeasured` also degrades confirmed collection.
- `partial_events` separately sums `path_read_failures`, `path_truncations`, `enter_exit_unmatched_boundary`, and `identity_unavailable`.
- These partial-event counts do not change observation state.
- `path_read_failures` sums script-reported failures and uses the count of empty emitted paths only when that sum is zero.
- `observed` does not mean that every event has a usable path or identity.
- An empty event log can still be `observed`.
- Event counts alone do not establish startup, attachment, or completeness.
- Read JSON loss details and event notes alongside the harness's CSV totals.
- An unmeasured category is not a measured zero.

## Clocks

- `clock` records the relationship between monotonic time and wall-clock time.

| Clock JSON field | Meaning |
| --- | --- |
| `boot_epoch` | Wall-clock instant corresponding to monotonic zero |
| `error_ns` | Bound on the paired-reading interval |
| `clock_source` | `CLOCK_MONOTONIC` |
| `note` | Explanation of the clock reading |

- Event timestamps use `CLOCK_MONOTONIC`.
- Conversion must use the same clock.
- `CLOCK_BOOTTIME` includes suspended time and cannot be substituted into this conversion.[^clock]
- `error_ns` bounds the paired-reading interval.
- It does not bound later wall-clock changes.
- Matching tolerance must exceed the conversion error.
- A trace's `C` record overrides the supplied epoch for subsequent events.

## Cgroup table and validity

| Table field | Meaning |
| --- | --- |
| `generated_at`, `root` | Table-generation time and hierarchy root |
| `snapshots`, `updated_at` | Snapshot count and refresh times |
| `calibration` | Identifier calibration result |
| `entries` | Recorded cgroup associations |
| `errors` | Optional collection errors |

| Entry fields | Meaning |
| --- | --- |
| `cgroup_id`, `path` | Cgroup identifier and hierarchy path |
| `container_id`, `depth` | Optional container identity and depth below its group |
| `generation` | Group generation |
| `first_seen`, `last_seen`, `expired_at` | Discovery, last observation, and expiration times |
| `inode`, `handle_id`, `handle_error`, `id_agreement` | Identifier calibration evidence |

- A readable file-handle identifier takes precedence when it differs from the inode.
- Docker scope names and bare 64-character container IDs are recognized under custom parents.
- Child groups inherit the nearest container identity.
- `-merge` retains historical entries.
- Disappeared or replaced groups close when a refresh discovers the change.
- Validity begins at discovery and closes at refresh.
- Those bounds are not independently observed lifecycle transitions.
- Refresh after creating a container and before triggering its measured work.
- Refresh again after collection while preserving earlier associations.
- Unknown cgroups remain unattributed.
- Lack of attribution does not establish that an event belongs to the host.

## Checking without Docker

- Saved input exercises conversion without live bpftrace or Docker.

```sh
mkdir -p ./out
go test ./experiments/runtime-events -run '^TestConvert' -v
go run ./experiments/runtime-events convert \
  -in experiments/runtime-events/testdata/trace-sample.txt \
  -config-id recorded-sample -script-version 1 -sync startup -buffer-pages 64 \
  -boot-epoch 2026-09-13T00:00:00Z \
  -out ./out/sample-events.jsonl
```

- The fixed epoch is the fixture's reference time.
- It is not a measurement from the current host.
- Tests cover successful and failed opens, out-of-order delivery, process identity, relative paths, truncation, loss accounting, clocks, and cgroup attribution.
- The sample reports 17 lost events in one notification.
- Its totals are 4,823 events before filtering and 9 after filtering.
- This conversion supplies no cgroup table or attachment confirmation.
- Events therefore remain unattributed and `attached` remains false.

## Detailed limitations and cautions

### Environment and compatibility

- This is a standalone experiment with no third-party Go dependencies.
- It is separate from the product binary and container image.
- Linux BTF must expose `curtask->group_leader->start_boottime`.
- All seven tracepoints listed in the README are required.
- On x86_64, a C library's `open()` can issue legacy `open` instead of `openat(AT_FDCWD, ...)`.
- Watching only the `openat` family misses those legacy calls.
- The scripts require bpftrace support for their `config` block, `nsecs(monotonic)`, and configured string lengths.
- The filtered scripts additionally use `strcontains`.
- Record the installed bpftrace version.
- Live measurements used v0.25.0.
- The minimum working version remains undetermined.
- For a version without config-block support, adapt a copy and set `BPFTRACE_MAX_STRLEN=256` and `BPFTRACE_PERF_RB_PAGES=64` in the tracer environment.[^bpftrace]
- Those changes alone do not establish compatibility.
- Root or suitable tracing and file-reading capabilities are required.
- Minimum capabilities remain under evaluation.
- Record permission failures and host security restrictions.
- Root does not guarantee that tracing will succeed.
- Container attribution requires native Docker Engine with cgroup v2 and access to the host hierarchy.[^docker]
- Builds use the repository's Go 1.26.4.
- Examples use Bash and jq.
- Observation collection and scan matching also require the [runtime-discovery environment](../runtime-discovery/README.md#requirements).

### Recorded measurements

- The initial six-second check used one container before the plain `open` probes were added.
- It recorded 7 attached probes, 42 execution events, 2672 open events, and 0 lost events.
- Current scripts define 7 tracepoints plus `BEGIN` and `END`, for 9 probes.
- The final measurement set contains 43 runs of 300 seconds on the development environment's Linux 6.6 kernel as root.
- It covers `startup`, `attach_running`, and buffers of 64, 256, and 512 pages.
- Production-host measurements on kernel 7.0 remain unperformed.
- Collection with only `CAP_BPF` and `CAP_PERFMON` remains unperformed.
- Overhead measurements remain unperformed.
- Replicate numbers of 2 or greater are available only for case 13, which runs short-lived processes.
- Saved-input checks do not establish live collection reliability or product support.
- Only amd64 has been tested.
- Syscall-number entries for other architectures do not establish support.

### Paths and evidence

- A path of at least 255 bytes fills the configured 256-byte string buffer.
- Such paths are marked truncated and unresolved.
- Collection uses no kernel-side path filter.
- Paths truncated before a relevant marker can still be excluded by later user-space filtering.
- Collection covers successful executions and the `open`, `openat`, and `openat2` family.
- `creat` and opens through io_uring are outside its scope.
- Opening a file does not establish reading its contents or executing a dependency's code.
- Evidence can only raise priority.
- Missing evidence never establishes non-use, safety, or grounds for lowering priority.

[^bpftrace]: [bpftrace configuration variables and config blocks](https://bpftrace.org/docs/release_023/language)
[^docker]: [Docker Engine runtime metrics and cgroup v2](https://docs.docker.com/engine/containers/runmetrics/)
[^clock]: [Linux manual: clock_gettime(2), CLOCK_MONOTONIC, and CLOCK_BOOTTIME](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
