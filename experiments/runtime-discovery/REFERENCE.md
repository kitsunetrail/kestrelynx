# Runtime discovery reference

**English** | [日本語](REFERENCE.ja.md)

- The [README](README.md) covers the purpose, requirements, automated commands, and case selection.
- Commands here run from the repository root.
- Manual examples save generated data under git-ignored `./out/`.
- Automated runs use `experiments/runtime-discovery/out/`.
- Observations, logs, scans, and results must remain outside commits.

## Inputs and outputs

### Collection inputs

- `collect` saves runtime observations and auxiliary file-to-package mapping inputs.
- Procfs inputs include `/proc/<pid>/exe`, `maps`, `fd`, `status`, `net/tcp`, and `net/tcp6`.
- Collection also reads process identity, namespace identity, and cgroup metadata.
- Container files are read through `/proc/<pid>/root`.
- Package metadata includes dpkg, distroless `status.d`, and apk.
- Docker API requests are GET requests for container enumeration, inspection, and `top`.
- Access to the Docker socket can permit container control even though `collect` only uses GET.
- The case helper separately builds, starts, inspects, and removes containers.
- Fixture and preflight checks use Docker-reported PIDs to read host procfs.
- Those checks work on distroless without `docker exec`.
- Case 4 readiness separately invokes `pg_isready` through `docker exec`.

### Auxiliary inputs and descriptors

- `-aux-inputs=true` saves mapping inputs in each observation's `auxiliary_inputs`.
- Inputs include Python search directories, `.dist-info/RECORD` lists, and distributions using `.egg-info`.
- Inputs also include Python and `node_modules` layouts, symlink targets, the OS package path index, merged-`/usr` links, and raw per-process `mountinfo`.
- Directory layouts contain paths rather than module contents.
- Python search directories come from filesystem inspection without invoking the container's interpreter.
- Each reading records its mount view, auxiliary generation, package database generation, collection time, first and last seen times, sample IDs, and reading PID.
- Language layouts are read again at sampling time because they can change independently of the OS package database.
- Unchanged auxiliary generations share a saved reading.
- Changed layouts remain separate.
- The OS path index is cached by package database generation.
- Auxiliary collection also runs without an OS package database.
- Bounded reads record truncations and errors.
- A missing path in incomplete input does not establish that no package owns it.
- Process `file_descriptors` records include ordinary filesystem descriptors.
- Each descriptor records its number, path, deleted marker, resolved path, and any resolution error.
- Path-resolution records identify descriptor evidence as `fd`, alongside `exe` and `maps`.
- Socket descriptors supply socket inodes.
- Pipes and anonymous-inode targets are excluded from file-to-package matching.
- An archive descriptor supports an `opened` observation without proving that a particular class executed.

### Saved files and run keys

- The scan, match, and CSV names below are those written by `case-run.sh`; the manual example writes `trivy.json`, `match.json`, and `csv/`.

| File | Contents |
| --- | --- |
| `collect/<container>__<run-key>.json` | One observation per container |
| `collect/manifest.json` | Container observation filenames and collection-level errors |
| `collect/ready.json` | Default registration readiness report |
| `case.json` | Saved case definition and declared ground-truth scope |
| `trivy_hc.json` / `trivy_all.json` | Scans of the exact running image ID, HIGH/CRITICAL and all severities |
| `gtb.json` | Independent ground truth as a JSON object |
| `events.jsonl` | Converted event header, events, and trailer |
| `intel.json` | Saved vulnerability intelligence used for classification |
| `match_hc.json` (HIGH/CRITICAL) and `match_all.json` (all severities) | Match results and detailed evidence |
| `csv_hc/` / `csv_all/` | Fourteen result tables for each scan |
| `record.md` | Individual run record produced by `tools/record.py` |
| `experiments/runtime-discovery/out/AGGREGATE-events.md` | Cross-run table produced by `tools/aggregate.py` |

| `<case>-truth-r<replicate>/image_id.txt`, `container_id.txt` | Truth-run image and container identities |
| `<case>-truth-r<replicate>/ready_at.txt`, `fired_at.txt`, `stopped_at.txt` | Truth-run readiness, firing, and stop-signal times |
| `<case>-truth-r<replicate>/varlog/` | Logs copied after graceful stop, including usage, occurrences, operations, runtime introspection, and per-process strace files |
| `<case>-truth-r<replicate>/truth.json` | Independent inventory and usage truth produced by `truth.py` |
| `<measurement-run>/coverage.json`, `coverage.md` | Package coverage scores or a hold decision with reasons |

- An observation filename is `case9__9_root_i30_w300_p0_r1_attach_running_none.json`.
- The run key contains `case_variant`, `permission`, `interval`, `window`, `phase`, `replicate`, `sync`, and `config_id`.
- `sync` distinguishes workload ordering.
- `config_id` distinguishes event collection configurations.
- Observations contain identities, timing, host architecture, process evidence, ownership, listeners, privileges, load measurements, failures, target registration, auxiliary inputs, and descriptors.
- A successful command exit does not replace inspection of the observation.
- Match JSON contains image identity verification, usage verdicts, evidence, confirmation rates, exposure, ranking comparisons, and GT-B accuracy metrics.
- Rerunning into the same paths overwrites files.
- Each run needs its own directory.
- Aggregation is separate from `match`.

### Event input

- `match -events` reads event JSONL separately from GT-B usage and occurrence logs.
- Usage logs without event-record discriminators are rejected as event input.
- Each event JSONL line has a `record` discriminator.
- `events_header` describes configuration, ordering, method, filter, buffer, clock conversion, and confirmed startup and attachment.
- `event` records retain timestamps, process and thread identity, raw and resolved paths, success, cgroup information, and container attribution.
- `events_trailer` describes collection end and losses.
- Tracer stderr must be retained so conversion includes reported losses.
- The [runtime-events reference](../runtime-events/REFERENCE.md) describes tracing, clock conversion, and the cgroup correspondence table.
- Differing nonempty `sync` or `config_id` values between observations and event headers are rejected.
- A missing event configuration ID is rejected when the observation specifies a configuration other than `none`.
- Older inputs can omit dimensions without an omitted value generally counting as disagreement.

## Command flags

### collect

| Flag | Meaning |
| --- | --- |
| `-socket` | Docker Engine UNIX socket, normally `/var/run/docker.sock` |
| `-containers` | Comma-separated container names or IDs already available for observation |
| `-case-variant` | Case variant in the run key, such as `9` or `7a` |
| `-permission` | Permission-condition label |
| `-interval` | Seconds between sample starts |
| `-window` | Observation-window duration in seconds |
| `-phase` | Sampling offset in seconds from `-phase-base` |
| `-phase-base` | RFC3339 reference instant for the offset |
| `-replicate` | Replicate number in the run key |
| `-ps-args` | Docker `top` arguments, default `-eo pid,ppid,user` |
| `-out-dir` | Directory for observations and the manifest |
| `-cgroup-path` | Collector cgroup v2 directory, overriding the path derived from `/proc/self/cgroup` |
| `-docker-cgroup-path` | Daemon cgroup directory, default `/sys/fs/cgroup/system.slice/docker.service` |
| `-expect` | Comma-separated names or IDs to register before their workloads start |
| `-expect-poll-ms` | Registration polling interval, default `200` milliseconds and required to be positive |
| `-expect-timeout` | Time for all expected targets to reach acceptance, default `120` seconds and required to be positive |
| `-ready-file` | Readiness report rewritten on registration changes, default `<out-dir>/ready.json` |
| `-sync` | `startup` or `attach_running`, defaulting to `startup` with `-expect` and `attach_running` otherwise |
| `-config-id` | Event method, script/build, filter, and buffer configuration identifier, default `none` |
| `-aux-inputs` | Save auxiliary mapping inputs, default `true` |
| `-aux-max-dir-entries` | Module-layout path limit per directory tree, default `200000` |
| `-aux-max-record-lines` | Installed-file manifest line limit per Python distribution, default `100000` |
| `-aux-max-owned-paths` | Package database path-index entry limit, default `400000` |
| `-aux-scan-depth` | Search depth below conventional installation roots, default `8` |

- The standard sampling condition is root, a 300-second window, a 30-second interval, zero offset, and replicate 1.
- That condition schedules ten samples.
- Permission and replicate conditions must be recorded explicitly.
- `-permission` labels a run without granting privileges.
- Labels are `root`, `ptrace`, `ptrace_dac`, and `none`.
- `ptrace` denotes non-root with `CAP_SYS_PTRACE`.
- `ptrace_dac` additionally includes `CAP_DAC_READ_SEARCH`.
- `none` denotes non-root without capabilities.
- Capabilities apply to the built executable rather than `go run`.
- Socket access, directory permissions, and host security controls also affect success.
- Omitting both `-containers` and `-expect` selects containers running at the initial enumeration.
- `-expect` alone waits only for its named targets.
- Adding `-containers` also selects already-running targets.
- Overridden `-ps-args` must retain the `pid,ppid,user` column order.
- Without `-phase-base`, ordinary attach-running collection uses its start time.
- Registration waits reset the default reference after the wait.
- The reference time and its source are recorded.
- Workload-relative comparisons use the workload cycle's reference instant as `-phase-base`.
- Auxiliary reads also have a fixed limit of 100,000 symlink targets per reading.
- That symlink limit has no flag.
- Registration, search, and truncation settings belong with the saved run conditions.

### match

| Flag | Meaning |
| --- | --- |
| `-observation` | Required container observation JSON |
| `-trivy` | Required scan JSON for the measured image |
| `-case` | Required case definition containing expectations and any GT-B scope |
| `-gtb` | Optional independent ground-truth JSON |
| `-events` | Optional converted event JSONL |

| `-all-packages` | Add zero-Finding package verdicts from Trivy `Packages` entries, requiring `--list-all-pkgs` scan output and defaulting to `false` |
| `-occurrence-tolerance-ms` | Pairing tolerance, default `500` milliseconds |
| `-intel-cache` | KEV/EPSS cache directory |
| `-intel-snapshot` | Saved intelligence JSON used without KEV/EPSS lookup |
| `-out-intel-snapshot` | Output path for the intelligence used by this match |
| `-act-now-epss` | EPSS threshold for `act_now`, `0.10` in the standard example |
| `-watch-epss` | EPSS threshold for `watch`, `0.01` in the standard example |
| `-out-json` | Match-result JSON path |
| `-out-csv-dir` | Directory for the fourteen CSV tables |

- `match` needs no live container or root filesystem.
- Omitting independent GT-B leaves FP/FN undetermined.
- Without `-intel-snapshot`, matching uses the intelligence cache and may fetch updated KEV/EPSS feeds.
- `-out-intel-snapshot` saves the intelligence actually used.
- An earlier result's `intel` object can also supply the snapshot.
- Reproduction requires the same saved inputs, thresholds, and intelligence snapshot.
- Snapshot runs perform no KEV/EPSS lookup.
- Only snapshot runs pin intelligence sufficiently for reproducible classification.
- Automated tools accept the snapshot path through `KL_INTEL_SNAPSHOT`.
- Pairing tolerance must be fixed before measurement and retained across comparisons.

### Coverage runners and scoring tools

| Command | Arguments and defaults |
| --- | --- |
| `tools/case-run.sh` | `<case> [replicate] [startup\|attach_running] [64\|256\|512\|none] [interval] [window]`, defaulting to replicate `1`, `startup`, `64`, `30`, and `300` |
| `tools/case-batch.sh` | `<plan file>`, with each line containing `<case> <replicate> <sync> <pages> [interval] [window]` |
| `tools/truth-run.sh` | `<case> [replicate] [window seconds]`, accepting case 26 through case 28 and defaulting to replicate `1` and window `900` |
| `tools/truth.py` | `<truth run dir> <case json> [measurement run dir]`, writing `<truth run dir>/truth.json` |
| `tools/coverage.py` | `<measurement run dir> <truth.json>`, writing `coverage.json` and `coverage.md` in the measurement directory |
| `cases/run.sh build` | `<case>`, building the separate image-build step without starting a container where that step exists |
| `cases/run.sh fire-when-ready` | `<case> [timeout seconds]`, retrying the actual firing signal with a default timeout of `900` seconds |
| `cases/run.sh wait-after-lazy-phase` | `<case> [timeout seconds]`, waiting for an `after_lazy` introspection record with a default timeout of `60` seconds |

- The fifth and sixth `case-run.sh` arguments are positive whole seconds for sample-start interval and observation-window duration.
- The fifth and sixth plan fields have the same meanings and default to `30` and `300` when omitted.
- Plan entries for case 23, case 24, `23+24`, and `23+host` route to the attribution runner rather than applying the coverage interval and window.
- `coverage-main.txt` schedules case 26 through case 28 at a 30-second interval and a 900-second window under both startup conditions with two replicates, totaling 12 runs.
- `coverage-rest.txt` schedules the remaining interval/window combinations `(10, 900)`, `(30, 300)`, and `(10, 300)` under both startup conditions with one replicate, totaling 18 runs.
- Both coverage plans use `512` event-buffer pages.
- `case-run.sh` builds the image before starting the tracer and collector so an uncached build does not consume the observation window.
- For case 26 through case 28 under `startup`, `-phase-base` uses the collector's start instant so the window includes container startup before registration completes.
- For these cases under `attach_running`, the runner uses `fire-when-ready` with a 900-second timeout and `wait-after-lazy-phase` with a 120-second timeout before starting observation.
- These cases use Trivy `--list-all-pkgs` for both severity scans and `match -all-packages` for both matches.
- `truth-run.sh` creates a fresh container, runs the workload under strace, waits for readiness and fires, waits the requested window, then stops gracefully and copies `/var/log`.
- The optional measurement directory makes `truth.py` check equivalence during truth construction, while `coverage.py` repeats that check for every measurement it scores.
- `truth.py` needs Docker access to inspect the saved image ID, while `coverage.py` needs the saved truth-run directory and logs referenced by `truth.json`.
- Run `coverage.py` from the same checkout as `truth.py` so its imported parsing and operation helpers agree.

## Manual measurement

### Measurement order

1. Prepare the host.
2. Start the case.
3. Check readiness and fixture validity.
4. Scan the exact running image ID.
5. Collect observations.
6. Collect independent ground truth.
7. Match observations, scan, case definition, and ground truth.
8. Tear down the case.

- Ordinary `attach_running` measurements follow this order.
- Cases 13–24 under `startup` require the registration sequence below.
- A failed readiness, fixture, or preflight check stops the run.

### Host preparation and build

- A dedicated host reduces interference from competing workloads.
- Leftover networking from other runtimes can affect measurements.
- The CLI, image scan, and collector must use the same native Docker endpoint.
- Docker Desktop through a separate VM does not expose the required host PIDs.
- Docker Desktop WSL integration is unsupported because it takes over the socket.
- Standard collection and host-procfs checks require root.
- Equivalent non-root reading uses `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
- Event measurements also require the environment in the [runtime-events README](../runtime-events/README.md).
- Live measurements used bpftrace v0.25.0; the minimum working version remains undetermined.
- Go 1.26 is required, with Go 1.26.4 specified by the repository.
- Trivy scans images; Bash and curl support the helper; jq supports these examples.
- The case helper uses python3 to parse usage logs when available.
- Its fallback regular expression tolerates whitespace differences.
- The automation's Python commands require python3.
- Case ports must be available.
- Network access supports image builds, Trivy data, requests in cases 9/13/23/24, and KEV/EPSS retrieval without a snapshot.

```sh
mkdir -p ./out
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
docker context show
docker info --format '{{.ServerVersion}} {{.Driver}} {{.DockerRootDir}} {{.CgroupVersion}}'
uname -r
cat /proc/sys/kernel/yama/ptrace_scope
findmnt -no OPTIONS /proc

go build -o ./out/runtime-discovery ./experiments/runtime-discovery
go run ./experiments/runtime-discovery collect -h
go run ./experiments/runtime-discovery match -h
```

- Host-preparation outputs and errors belong in the run record.
- Published HTTP ports require a curl check.
- Absence of a host listening socket does not establish failure of Docker NAT publication.
- A built executable provides a stable binary for permission comparisons.

### Sampling example: case 9

```sh
run_dir=./out/9-root-30-300-offset0-rep1
mkdir -p "$run_dir"
sudo bash experiments/runtime-discovery/cases/run.sh up 9
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 9
cp experiments/runtime-discovery/cases/9.json "$run_dir/case.json"
image_id=$(docker inspect --format '{{.Image}}' case9)
trivy image --format json --output "$run_dir/trivy.json" "$image_id"

sudo systemd-run --scope --unit=runtime-discovery-collect \
  -p CPUAccounting=yes -p MemoryAccounting=yes \
  "$(pwd)/out/runtime-discovery" collect \
  -socket /var/run/docker.sock -containers case9 \
  -case-variant 9 -permission root \
  -interval 30 -window 300 -phase 0 -replicate 1 \
  -out-dir "$run_dir/collect"
```

- The scope isolates the collector in its own cgroup v2.
- A possible explicit `-cgroup-path` is `/sys/fs/cgroup/system.slice/runtime-discovery-collect.scope`.
- Hosts without systemd require a manually created and entered cgroup v2, passed through `-cgroup-path`.
- Collection records initial package database read cost, collector cgroup usage, and daemon cgroup usage.
- Daemon cgroup measurements include the `ps` processes started by `docker top`.
- `memory.peak` covers the cgroup's lifetime rather than only the observation window.
- Unavailable measurements are recorded as failures.
- Permission comparisons on cases 1/2/6 remain separate from standard results.
- Sampling comparisons use cases 9/10.
- Sampling intervals are 10/30/60 seconds with a fixed 300-second window or ten samples.
- Offset comparisons use 0/3/7 seconds.
- Each comparison preserves its own conditions and output directory.

### Case definitions and helper behavior

- Sampling cases 1–12 contain 13 variants because case 7 has `7a` and `7b`.
- `run.sh` takes the bare number or number-and-letter variant.
- Docker container names are `case<number>`, such as `case1` and `case7a`.
- Collection flags take those container names or IDs.
- `cases/*.json` separates `expected_usage` from `expected_verdict`.
- GT-A usage declarations are `used` or `not_used`.
- `expected_factor` is optional.
- `gap_class_hint` and `gap_class_rationale` describe declared gaps.
- `gt_b_scope` declares the package scope of independent truth.
- Case 5 declares cryptography used while expecting `unobserved` under the previous language-package rules.
- Language-package expectations in cases 13–24 likewise describe the previous rules.
- Added evaluation series can confirm a package whose declared expected verdict remains `unobserved`.
- Case 16's definition matches case 15 except for `case_id` and `image`.
- Cases 23/24 have matching definitions apart from `case_id`.

| Case | Image or base | Detailed condition |
| --- | --- | --- |
| 1 | `nginx:1.27` | Debian ownership, master/workers, all-interface publication |
| 2 | `redis:7-alpine` | apk ownership, non-root service, loopback publication |
| 3 | `nginx:1.27` | Host networking and listener attribution |
| 4 | `postgres:16` | Multiple database processes without published ports |
| 5 | `kl-case5`, based on `python:3.12-slim` | Mapped cryptography extension and language-package gap |
| 6 | `kl-case6`, based on distroless `cc-debian12` | Dynamic C server and `status.d` ownership |
| 7a / 7b | `kl-case7a` on `debian:12-slim`; `kl-case7b` on distroless `static-debian12` | Same static Go server with different metadata availability |
| 8 | `kl-case8`, based on `debian:12-slim` | Deleted executable, deleted library, atomic replacement of a loaded library |
| 9 | `kl-case9`, based on `debian:12-slim` | Short-lived curl/git with five-second sleeps between iterations |
| 10 | `kl-case10`, based on `debian:12-slim` | SQLite loaded for seven seconds and unloaded for seven seconds |
| 11 | `nginxinc/nginx-unprivileged:1.27-alpine` | Non-root service and effective privileges |
| 12 | `nginx:1.27` | Added `NET_ADMIN` and dropped `NET_RAW` |
| 13 | `kl-case13` | Individually identified curl/git executions and loader-resolved libraries |
| 14 | `kl-case14` | SQLite `dlopen`/`dlclose`, seven-second loaded/unloaded periods, load intervals, maps-based unload checks |
| 15 | `kl-case15` | Cryptography import, mapped extension, installed-file manifests, compiled cache paths |
| 16 | `kl-case16` | Same import with build-time cache removal and runtime cache writes disabled |
| 17 | `kl-case17` | Lodash `require` in a standard `node_modules` layout |
| 18 | `kl-case18` | Same dependency in pnpm's linked layout |
| 19 | `kl-case19` | Separate Log4j class-path archives, retained descriptors, `startup_open` |
| 20 | `kl-case20` | Log4j classes and nested archives in `/app/fat.jar`, outer-file evidence, `startup_open` |
| 21 | `kl-case21` | Log4j outside the class path, loader created on fire, `load_open` |
| 22 | `kl-case22` | Static `/server` containing `golang.org/x/text`, matched through its binary path |
| 23 / 24 | `kl-case13` | Identical programs and paths in separate containers, with a host control |

- The helper builds cases 5–10, including both case 7 variants.
- Other sampling cases use upstream images.
- The helper builds all event-case images, with 23/24 reusing `kl-case13`.
- `up-all` starts only cases 1–12.
- `down-all` removes case containers 1–24.
- Sampling-case startup waits for HTTP 200, service readiness logs, or `pg_isready`.
- Cases 5/6 also wait for an `open` record.
- Case 8 waits for three `stage` records.
- Case 9 waits for an `exit`.
- Case 10 waits for a `dlclose` with a maps-confirmed unload.
- JSON parsing treats differently spaced versions of the same record equally.
- `fixture-check` remains a separate command.
- Cases 8/10 also require their preflight before sampling.
- `preflight-10` polls for an unloaded period instead of assuming a fixed time.

```sh
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 8
sudo bash experiments/runtime-discovery/cases/run.sh preflight-8
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check 10
sudo bash experiments/runtime-discovery/cases/run.sh preflight-10
```

### Event workload signaling and checks

- Cases 13–24 wait on `/run/fire/fire`.
- The helper creates `$FIRE_ROOT/case<number>/fire` and bind-mounts its directory at `/run/fire`.
- `FIRE_ROOT` defaults to `experiments/runtime-discovery/out/fire`.
- An absolute directory under `./out/` can organize a manual measurement.
- The shared `container-id` file receives the full container ID before firing.
- `fire <case>` writes `go` to the FIFO from the host.
- Blocking FIFO waits avoid polling and do not launch an extra command in the container.
- `fire` does not validate collector readiness.
- Event-case `up` returns while the workload is waiting.
- Post-fire fixture checks follow completion of the required occurrences.
- Cases 13/23/24 require at least one execution record.
- Cases 14–21 require at least two load records.
- Cases 15–21 deliberately repeat loading to record an in-memory cache hit.
- Case 14 repeats load/unload cycles and determines `cache_hit` from verification of the preceding unload.
- Case 14 needs inspection of `maps_unloaded` as well as the helper's load count.
- Case 22 requires an execution record and no mapped shared library.
- `dump-logs <case> <directory>` copies available logs through the container root filesystem.
- The copied names are `<case>.usage.jsonl` and `<case>.occurrences.jsonl`.
- `host-run <log> [iterations] [interval seconds]` runs the host attribution control.
- Its defaults are ten iterations, five-second intervals, and `/usr/bin/curl`.
- `HOST_PROGRAM` selects another executable.
- Host occurrences use `container_id:"host"`.
- Cases 23/24 use distinct occurrence-ID prefixes.

### Registration before workload startup

1. Prepare clock conversion and the initial cgroup table using the [runtime-events procedure](../runtime-events/REFERENCE.md#measurement-order).
2. Start the tracer before container startup when measuring startup opens.
3. Start `collect` in the background with `-expect case13`, `-sync startup`, the intended `-config-id`, and a fresh readiness path.
4. Start the waiting container with `run.sh up 13`.
5. Obtain the current collector's run ID with `ready-run-id`.
6. Wait for that run's readiness with `wait-ready`.
7. Refresh the cgroup correspondence table with `register-cgroups`.
8. Confirm delivery of a known tracer event with `attach-check`.
9. Fire the workload and record the firing time.
10. Preserve the exact image ID, scan it, and run the post-fire fixture check.
11. Keep the workload and tracer running through the scheduled window end.
12. Refresh the cgroup table and copy independent logs before teardown.
13. Preserve both tracer streams, convert them, and pass the event JSONL to `match`.

| Helper command | Arguments and behavior |
| --- | --- |
| `ready-run-id` | `<ready file> [timeout seconds] [collector start, RFC3339]`, default timeout `60` |
| `wait-ready` | `<ready file> <expected run id> [timeout seconds]`, required run ID and default timeout `120` |
| `register-cgroups` | `<table path> [runtime-events binary]`, merging earlier associations |
| `attach-check` | `<trace file> [timeout seconds]`, confirming a known execution |
| `fire` | `<case>`, signaling the waiting workload |
| `dump-logs` | `<case> <directory>`, preserving available independent logs |
| `host-run` | `<log> [iterations] [interval seconds]`, recording host executions |

- These commands run through `sudo bash experiments/runtime-discovery/cases/run.sh`.
- `-expect` takes the container name, such as `case13`, rather than the case number.
- `-expect-timeout` must allow enough time for image building and target preparation.
- The readiness report records a unique `run_id`, conditions, transition times, target states, and errors.
- Target states progress through `registered_not_started`, `start_detected_preparing`, and `accepted`.
- Acceptance follows inspection and preparation of mount views and enabled auxiliary inputs.
- Preparation failures are retried.
- A target that misses the acceptance timeout becomes `not_started`.
- Accepted targets can still have saved errors or truncations.
- `wait-ready` succeeds only for the expected run ID with every expected target accepted.
- Passing the collector start instant to `ready-run-id` rejects older reports.
- Omitting that instant returns the identifier with a warning that it cannot be tied to the current run.
- The cgroup table must be refreshed after the container exists and before firing.
- Existing associations remain available through table merging.
- `attach-check` runs a uniquely named host probe and waits for its trace marker.
- A tracer startup message alone does not establish attachment.
- Measured work must fall within the scheduled observation window.
- Cases 19/20 require tracing before container startup to include `startup_open`.
- Cases 13/14 compare firing after readiness with joining an existing execution or load cycle.
- Cases 15–18 and 21 compare firing before observation ends with attaching after their import, require, or load.
- Case 22 compares observing `/server` execution with attaching to the resident server.
- Cases 23/24 compare either container alone, both together, and separately logged host activity.
- An `attach_running` run starts and fires work before collection with `-containers case13 -sync attach_running`.
- The event header must use the same ordering label.
- A one-time load completed before attachment remains outside that observation's window.

### Matching and teardown

- The following command follows preparation of `gtb.json` in the next section.
- Event runs add `-events "$run_dir/events.jsonl"` and use their corresponding observation filename.

```sh
go run ./experiments/runtime-discovery match \
  -observation "$run_dir/collect/case9__9_root_i30_w300_p0_r1_attach_running_none.json" \
  -trivy "$run_dir/trivy.json" -case "$run_dir/case.json" \
  -gtb "$run_dir/gtb.json" -intel-cache ./out/intel-cache \
  -out-intel-snapshot "$run_dir/intel.json" \
  -act-now-epss 0.10 -watch-epss 0.01 \
  -out-json "$run_dir/match.json" -out-csv-dir "$run_dir/csv"
sudo bash experiments/runtime-discovery/cases/run.sh down 9
```

## Ground truth (GT-B)

### Format and independence

- GT-B combines usage logs or resident-process checks with independently verified package information.
- `-gtb` accepts one JSON object rather than raw JSONL.
- GT-A expectations and collector output are not independent ground truth.
- Each run needs fresh logs.
- The declared scope must be justified before measurement.
- Only packages in `gt_b_scope` receive GT-B labels.

| Field | Meaning |
| --- | --- |
| `case_id` | Case identifier |
| `kind` | `usage_log` or `limited` |
| `usage_log` | Parsed workload usage records |
| `path_packages` | Independently verified file-to-package mappings |
| `resident_packages` | Positive resident-process checks for limited truth |
| `occurrences` | Independent records of individual executions and loads |
| `pid_map` | Independently established container/host process and thread correspondence |
| `clock_base` | Description of the occurrence clock and its relationship to event time |
| `real_opens` | Independent actual file-open syscall records, when available |

### Usage-log truth

- The collector can return after its last sample before the scheduled window ends.
- The workload must remain running through that end before GT-B is copied.
- The standard sampling example needs another 30 seconds.

```sh
sleep 30
docker cp case9:/var/log/usage.jsonl "$run_dir/usage.jsonl"
jq -sr '[.[] | .path? | select(. != null and . != "")] | unique[]' \
  "$run_dir/usage.jsonl" > "$run_dir/usage-paths.txt"
docker exec case9 dpkg-query -S /usr/bin/curl /usr/bin/git
```

- Cases 5/6/8/9/10 emit `/var/log/usage.jsonl`.
- Only 7a/7b among the self-built sampling cases omit usage logs.
- Cases 5/6 record startup and periodic maps snapshots.
- Case 9 records dynamic-loader-resolved libraries alongside execution.
- Usage logs contain one JSON object per line.

```json
{"ts":"2026-09-11T00:00:00Z","pid":42,"starttime":12345,"event":"exec","path":"/usr/bin/git","ok":true}
```

- `ts` is RFC3339 with optional fractional seconds.
- `pid` and process-start ticks identify a process generation.
- Usage event names are `exec`, `open`, `dlopen`, `dlclose`, and `exit`.
- An exit's `ok:true` confirms observation of the exit.
- Its separate `status` records the command exit code.
- Case 8 also records `meta` and `stage`.
- Case 10 adds `maps_unloaded` to `dlclose`.
- Those additional fields must remain in the saved logs.
- Pre-window records must remain when they begin an interval overlapping the window.

1. Independently verify every usage path's ownership, including library paths.
2. Account for symlink aliases and the running image's package metadata.
3. Save the verified mappings in `$run_dir/path-packages.json`.
4. Wrap the parsed log and mappings in a GT-B object.

```json
[
  {"path":"/usr/bin/curl","package":"curl"},
  {"path":"/usr/bin/git","package":"git"}
]
```

- The array illustrates the format and does not replace verification of all paths.
- On merged-`/usr` images, ownership queries must use the spelling recorded in package `.list` files.
- A recorded `/lib/...` path can return “no path found” when queried as `/usr/lib/...`.
- Direct inspection of `.list` files can resolve those aliases.
- Mappings must cover library paths outside `gt_b_scope` as well as paths inside it.
- A path verified to have no package owner uses `unowned:true`.
- An unresolved path must not be marked `unowned`.
- A mapping can use `packages` for several independently established package owners.
- The single `package` and optional `version` form remains available.
- An unmapped path prevents certification of non-use for packages without positive evidence.
- Independently established positive use remains valid.
- Missing events establish non-use only within independently justified logging coverage.

```sh
jq -s --slurpfile mappings "$run_dir/path-packages.json" '{
  case_id: "9", kind: "usage_log", usage_log: .,
  path_packages: $mappings[0]
}' "$run_dir/usage.jsonl" > "$run_dir/gtb.json"
```

### Limited resident-process truth

- Official-image checks can use a limited resident-process inspection after the window.
- The check saves `docker top`, inspects resident executables and libraries, and independently verifies ownership and versions.
- Positive observations use the following form.

```json
{"case_id":"1","kind":"limited","resident_packages":[{"package":"nginx","used":true}]}
```

- The saved case definition must declare the justified scope before measurement.
- Definitions without `gt_b_scope` leave coverage at zero.
- Limited checks cannot establish non-use.
- `used:false` entries are ignored.

### Occurrence records

- Cases 13–24 write both `/var/log/usage.jsonl` and `/var/log/occurrences.jsonl`.
- Usage logs establish package use.
- Occurrence logs identify individual executions and loads.
- Logs must be copied while the container still runs.

```sh
sudo bash experiments/runtime-discovery/cases/run.sh dump-logs 13 "$run_dir"
```

- Parsed occurrence records become the GT-B `occurrences` array.
- Independently collected process correspondence belongs in `pid_map`.
- `clock_base` describes the time basis.
- `real_opens` is valid only when actual calls were recorded independently of the event collector being evaluated.
- Supplied event-case fixtures do not produce independent `real_opens`.
- An execution occurrence is a timestamped point.
- A load occurrence has a start/end interval.

```json
{"id":"13-exec-000001","kind":"exec","pid":42,"tid":42,"starttime":12345,"pid_ns":4026531836,"ts":"2026-09-11T00:00:00.100000000Z","ok":true,"path":"/usr/bin/curl","container_id":"<full-container-id>"}
{"id":"17-load-000001","kind":"load","pid":1,"tid":1,"starttime":12346,"start":"2026-09-11T00:00:01.100000000Z","end":"2026-09-11T00:00:01.120000000Z","ok":true,"cache_hit":false,"files":["/app/node_modules/lodash/lodash.js"],"container_id":"<full-container-id>"}
```

- `id` identifies an occurrence within a case.
- Combined container and host logs require distinct occurrence IDs.
- `pid` and optional `tid` are the workload's process and thread numbers.
- `starttime` records process-generation ticks.
- `pid_ns` identifies the PID namespace containing those numbers.
- Host occurrences require `pid_ns` on both the occurrence and event.
- `path` identifies an executed file.
- `files` lists files resolved during a load.
- `cache_hit:true` identifies an in-memory repeat excluded from the load denominator.
- Failed operations and out-of-window occurrences are counted separately.
- Cases 19–21 preserve `open_condition`.
- The bundled-archive condition also preserves its qualification in `note`.
- Cases 19–21 omit thread IDs because they do not establish OS thread identity.
- Host controls declare `container_id:"host"`.
- Attribution uses the combined independent logs of all participating containers and the host.
- Usage-log `open` entries can come from maps snapshots or runtime module bookkeeping.
- Such entries are not independent syscall-level truth.

### Usage truth for case 26 through case 28 (truth.py)

#### Bundled inventory I

- `truth.py` creates a container from the saved image ID and enumerates the rootfs exported by `docker export`, independently of usage logs.
- Discovery covers the whole exported rootfs except `/proc`, `/sys`, and `/dev`, whose exclusions are recorded.
- OS packages and versions come from the copied OS package database, with file ownership resolved through its metadata.
- Python distributions are discovered across the exported filesystem, with installation metadata and `RECORD` used for versions and file ownership.
- Node packages come from readable `package.json` files containing names and versions anywhere in the image, including packages outside `node_modules` and bundled tooling.
- Java packages come from jars anywhere in the image, using their package coordinates and readable version metadata.
- This inventory targets the same bundled-package population as Trivy `--list-all-pkgs`, including packages without Findings.
- Inventory and truth keys are `(ecosystem, name, version)`, preserving different installed versions of the same package.
- `coverage_plan` declares intended groups and supplies a declaration check rather than defining the measured inventory or usage labels.

#### Used U, unused N, and unknown X

- Successful `execve`/`execveat` and `open`/`openat`/`openat2` calls from strace `-f -ff -tt` provide independent usage evidence.
- `clone`, `clone3`, `fork`, and `vfork` records reconstruct parent-child relationships and propagate the acting subject to children that do not execute another program.
- The operational curl, git, and openssl processes and their inherited helpers are short-lived subjects, while the resident program and operational scheduler are resident subjects.
- Runtime introspection adds resolved files from Python `sys.modules`, Node.js `require.cache`, and Java class-load logs.
- Only the first introspection sighting of a path contributes a new usage-evidence record, while later sightings become `held_evidence`.
- Absolute and relative symlink targets, including intermediate directory links, are resolved within the exported rootfs.
- Directory opens are excluded using both `O_DIRECTORY` and directory checks against the exported rootfs.
- Failed calls do not establish use, and unresolved relative paths remain explicit gaps.
- `U` contains versioned usage keys also present in `I`, while versioned usage absent from `I` becomes `ledger_gaps`.
- Usage or inventory entries whose versions cannot be established are reported in `version_unknown` rather than assigned a guessed version.
- Packages in `I` without positive usage evidence enter `N` only when the completeness check passes, otherwise entering `X`.
- Completeness requires nonempty trace coverage, no empty trace files, no corrupted or unparseable syscall records, no unreconstructed interrupted calls, and no missing traces for cloned processes.
- Completeness also requires resolved strace and introspection evidence, no unresolved broken ownership symlink chains, and a successful operation-equivalence check.
- An omitted measurement directory leaves operation consistency `unchecked`, so the remaining inventory is initially `X`.
- Positive usage remains in `U` when completeness fails, and the versioned inventory satisfies `I = U ∪ N ∪ X` with disjoint sets.
- `inventory_scan` records export, discovery, and metadata-read diagnostics separately from the usage completeness decision.

#### Evidence attribution and run equivalence

- Evidence is assigned to startup before firing, a named operation instance, activity after the stop signal, or an unattributed period.
- Short-lived evidence follows the traced PID and reconstructed ancestry to the operation instance identified by the occurrence log.
- Resident evidence uses timestamps against reconstructed operation intervals, with nearby assignments retained separately in `operations_nearest`.
- Short-lived evidence without a matching operation instance remains unattributed rather than falling back to a nearby timestamp.
- Operation offsets record the first usage instant relative to the corresponding operation or instance start.
- Evidence after the stop signal and evidence without usable temporal attribution do not independently establish startup or operation-scoped use.
- Equivalence compares image IDs, fixed-operation names and order, success, available `detail`, and the resolved-file sets from runtime introspection.
- Periodic `osops_` operations must cover the same kinds and agree in interleaved order, success, and available `detail` across the range both runs reached.
- Different periodic cycle counts are allowed, while trailing instances beyond the shared range remain explicitly unpaired.
- Missing or unusable measurement introspection prevents equivalence when the truth run has usable introspection.

#### truth.json fields

| Field | Meaning |
| --- | --- |
| `image_id`, `truth_run_dir`, `fired_at`, `stopped_at` | Image identity, retained source directory, and truth-run timing |
| `used`, `unused`, `unknown` | Versioned U, N, and X entries, with reasons on unknown entries |
| `inventory_size`, `inventory_scan` | Inventory count, scan scope, exclusions, export status, discovered metadata, and read failures |
| `ledger_gaps`, `identification_gaps` | Versioned positive evidence absent from the inventory and its identity-only summary |
| `version_unknown` | Inventory-side or usage-side entries lacking an established version |
| `completeness` | Trace checks, operation-consistency state, overall decision, and reasons |
| `unresolved` | Unresolved trace paths, introspection modules, unmapped paths, and ownership symlink failures |
| `declaration_gaps` | Declared packages missing from the inventory and inventoried packages absent from the declared groups |
| `operation_consistency` | Compared measurement directory, agreement details, image and introspection checks, and periodic instance pairing |
| `used[].evidence`, `evidence_types`, `subjects`, `paths` | Evidence sources, usage types, acting-subject categories, and resolved package paths |
| `used[].first_seen_s`, `last_seen_s`, `hold_seconds`, `exec_hold_seconds_min` | Truth-run evidence timing and recorded short-lived execution duration |
| `used[].used_at_startup`, `used_during_operations` | Startup-use flag and operation names associated with usage |
| `used[].operation_instances` | Specific operation IDs associated with usage evidence |
| `used[].operation_offsets_s`, `operation_instance_offsets_s` | First-use offsets keyed by operation name and specific instance ID |
| `used[].evidence_periods` | Startup, operation, nearest-operation, post-stop, and unattributed evidence counts |
| `used[].held_evidence` | Later introspection sightings retained as continued-presence evidence |

## Matching rules

### Finding confirmation

- All three series use the same scan and saved observation.
- `S0` reproduces the previous sampling rules.
- `S1` adds scanned Go binaries, open archive descriptors, module-tree files, mapped Python extensions, installed-file manifests, and the saved OS path index.
- `S2` adds successful executions and opens attributed to the measured container within the observation window.
- Event paths are resolved through saved mapping inputs.
- `S0` → `S1` and `S1` → `S2` gains are reported separately.
- Each source retains its input state and positive count.
- Missing input for one source does not erase valid evidence from another.
- Evidence retains its source and granularity.
- A Go-binary positive covers the binary and associated scan findings.
- It does not prove execution of an individual embedded module.
- Observing an outer archive does not prove independent loading of a particular nested archive.

### Identity and attribution

| Available truth | Rule and interpretation |
| --- | --- |
| Independent usable `pid_map` | `container_generation_and_thread` uses container, process generation, and host process/thread correspondence independently of the event's claimed container |
| No usable correspondence table | `container_namespace_pid_and_thread` requires matching cgroup-derived container identity, namespace-local PID/TID, and process generation |
| Host occurrence | Matching requires the same `pid_ns`, namespace-local PID/TID, and `starttime`, independently of container attribution |
| Missing required identity | Pairing is undecidable |

- Namespace-local process numbers can repeat in different containers.
- Event `ns_pid` and `ns_tid` are compared with workload-local process and thread numbers.
- Process start ticks alone do not establish identity across containers.
- Cross-container misattribution requires independent correspondence usable by `container_generation_and_thread`.
- Without it, `cross_container_evaluable=false`.
- `misattribution_rate` is then N/A even with a positive denominator.
- Host matching, `host_correct_rate`, and `correct_attribution_rate` remain separate evaluations.
- Host non-attribution does not establish correctness between containers.
- Attribution output includes correct and incorrect attribution, host outcomes, unattributed events, and undecidable counts.

### Occurrence pairing and denominators

- Pairing uses file paths, timing, container identity, and process generation.
- Independent host PID/thread correspondence is used where available.
- The default tolerance is 500 milliseconds.
- A tolerance no wider than the event clock-conversion error produces a note.
- That note does not automatically widen the tolerance.
- Execution capture requires one occurrence paired with exactly one event.
- One-to-many and many-to-one ambiguities are reported separately.
- Load capture counts eligible intervals with at least one event matching a listed file.
- An event claimed by multiple loads is excluded from all those loads.
- Actual-open capture requires independent `real_opens`.
- Cache hits, failures, and out-of-window occurrences are excluded with separate counts.
- In-window misses, undecidable identity, and unknown reasons remain distinguishable.
- Capture rates use their corresponding decidable counts as denominators.
- A zero denominator produces N/A.
- An unavailable actual-open record also produces N/A.
- Finding confirmation and occurrence capture answer different questions.

### All-package matching

- `-all-packages` registers packages from Trivy `Packages` entries even when they have no Finding.
- Added groups produce `PackageVerdict` entries with `finding_count: 0` through the same S0/S1/S2 evaluation path.
- OS versions reconstruct `epoch:version-release` from Trivy's separate fields, omitting zero epochs and empty releases.
- Zero-Finding groups use a separate `widened` index containing the additional package names, files, and placements.
- Finding-bearing groups keep the original index and verdicts, preserving Finding counts, rankings, and priority buckets.
- Added verdicts appear in `packages` after the existing aggregates have been computed.
- A report with no `Packages` entries is rejected when `-all-packages` is requested.
- `gobinary` entries are excluded from the added package population and from coverage scoring.
- The match group key remains `(class, package, installed_version)` and cannot separate identical language-package names and versions across ecosystems.

## Coverage scoring (coverage.py)

### Scope and sets

- Each available `match_hc.json` and `match_all.json` is scored separately for S0, S1, and S2 using confirmed `(ecosystem, name, installed_version)` keys.
- Categories are `resident_os`, `short_lived_os`, and the applicable language categories `python`, `node`, and `java`.
- A used OS package can belong to both subject categories, while an unused or unknown OS package is included in both OS categories.
- `U_main` includes startup use and use established through operations completed by the measurement window's end.
- Startup use remains in the main denominator under `attach_running`, including use before attachment.
- Periodic usage must correspond to a verified operation instance rather than merely another instance with the same name.
- For an operation crossing the window's end, main membership requires persistence evidence and a first-use offset that maps to or before the cutoff on the corresponding measurement instance.
- Unpaired, unrecorded, later-only, post-stop-only, or insufficiently attributed truth usage enters `X_main` rather than `N`.
- `N` retains established non-use, including entries restored from `X` after a fresh equivalence check when operation comparison was their only blocker.
- `U_window` is supplementary and includes usage associated with operations completed inside the window or startup usage with executable/shared-library evidence that could persist into it.
- Window scoring leaves boundary-crossing or unrecorded operation usage in `X_window`, while usage tied only to operations recorded entirely outside the window can enter `N_window`.
- Main scoping requires measurement operation intervals and the window end, while window scoring also requires the window start.
- When main scoping is unavailable, its availability flag is false and scoring falls back to the truth run's used set.

| Quantity | Set expression |
| --- | --- |
| Inventory | `I = U ∪ N ∪ X` |
| Confirmed set for series s | `C_s` |
| Main true positives | `TP_s = C_s ∩ U_main` |
| Main false negatives | `FN_s = U_main \ C_s` |
| Main false positives | `FP_s = C_s ∩ N` |
| Main true negatives | `TN_s = N \ C_s` |
| Main recall | `\|TP_s\| / \|U_main\|` |
| Main FPR | `\|FP_s\| / \|N\|` |
| Window figures | The same expressions using `U_window` and `N_window` |
| Identification misconfirmations | `C_s \ I` |
| Confirmations in truth-unknown inventory | `C_s ∩ X` |

- All category counts apply the corresponding category restriction to these sets.
- Zero denominators produce JSON `null` and Markdown N/A.
- `identification_misconfirmations` reports confirmed keys outside the inventory separately from ordinary TP/FP/FN.
- A confirmed wrong version is FP when that exact version is in `N`, TP when it is in `U_main`, and an identification misconfirmation when it is outside `I`.
- The correct version independently remains FN if it belongs to `U_main` and was not confirmed.
- `confirmed_in_x` reports confirmations in the remaining truth-unknown inventory, while `x_main_confirmed` and `confirmed_in_x_window` include the respective scope's unknown entries.

### Primary miss causes

- Each FN receives one primary cause in the following priority order, with cause totals equal to FN.
- Candidate tags preserve possible explanations when the evidence cannot establish a primary cause.

| Cause | Evidence used |
| --- | --- |
| `used_before_window` | All timed truth evidence precedes the firing-relative window start and lacks executable/shared-library evidence that could persist into the window |
| `short_lived_use` | For S0, every confirmed retention interval from the measurement fits between consecutive actual sample times, with no usage whose retention end remains unconfirmed |
| `mapping_not_supported` | For S2, a package path was captured in the measurement's in-window events without confirmation, or for any series the package verdict is absent or its factor identifies a mapping gap |
| `insufficient_permission` | A failure naming a package path has step `proc_denied`, `rootfs_denied`, or `prepare_proc_denied` |
| `other` | A failure naming a package path has an identifiable cause other than permission denial or `proc_gone` |
| `lost_events` | For S2, reported event loss accompanies an identifiable event gap overlapping the package's operation interval in the measurement |
| `unknown` | No preceding condition establishes the cause |

- Mapping-gap factors are `lang_pkg_unmappable`, `no_file_list`, `db_absent`, `db_error`, `mapping_input_missing`, and `event_path_unresolved`.
- `proc_gone` alone does not establish permission denial or the `other` cause.
- An `unknown` miss can carry `lost_events_candidate` for reported event loss and `short_lived_use_candidate` when S0 retention evidence is insufficient.
- Truth-run retention durations are not substituted for measurement-run retention intervals.

### Short-lived direct confirmations and output

- `short_lived_direct_confirmations` counts TP packages independently confirmed through a short-lived acting process in the measurement.
- S0 identifies that process through the confirmation's sample ID and path, while added mapping and event evidence use confirmation and process information.
- The count accumulates as S0 = P, S1 = P ∪ A, and S2 = P ∪ A ∪ E.
- An unknown acting subject contributes nothing to this auxiliary count, which does not replace the category's TP count.
- `coverage.json` retains category-by-series TP/FN/FP/TN, recall, FPR, window figures, unknown confirmations, identification misconfirmations, miss details, and direct-confirmation counts.
- `coverage.md` shows both scan variants, category-by-series metrics, identification misconfirmations, and the S2 miss table.

### Hold conditions

- Every scoring invocation checks the measurement image ID against `truth.json` and freshly compares the retained truth logs with that measurement's logs.
- Missing or different image IDs, unavailable truth source logs, or failed operation/introspection equivalence produce `hold: true` with `hold_reason`.
- A hold writes both output files without recall or false-positive figures, even though the command exits successfully.
- Trace incompleteness keeps affected negative candidates in `X` and does not by itself trigger the equivalence hold.

## Observation states

| Event state | Meaning |
| --- | --- |
| `not_attempted` | Event collection was not attempted |
| `failed` | Tracer startup or attachment was not confirmed |
| `observed` | Startup and attachment were confirmed without window-incompleteness indicators |
| `degraded` | Confirmed collection has reported incompleteness or unmeasured loss categories |

- An empty event log can be `observed`.
- Event count alone does not establish startup, attachment, or completeness.
- After startup and attachment are confirmed, positive `lost_events`, `lost_notifications`, `convert_failures`, `map_overflow`, or in-window `enter_exit_unmatched` makes the window `degraded`.
- `stopped_early:true` or nonempty `unmeasured` also makes that window `degraded`.
- `partial_events` separately sums `path_read_failures`, `path_truncations`, `enter_exit_unmatched_boundary`, and `identity_unavailable`.
- Those partial-event counts do not change the collection state.
- `observed` therefore does not mean that every event has a usable path or identity.
- Event notes and JSON loss details remain necessary alongside CSV totals.
- An unmeasured category is not a measured zero.

### Boundary remnants

- Conversion needs both `-window-start` and `-window-end` to classify boundary remnants.
- The observation window includes its endpoints.
- An unmatched entry outside that window is a boundary remnant.
- An unmatched exit with a recorded entry time is a boundary remnant when that entry time is outside the window.
- An unmatched exit without an entry time is a boundary remnant only when the exit precedes the window start.
- Other unmatched halves count as in-window `enter_exit_unmatched`.
- This includes exits after the window end when their entry time is unavailable.
- Without both window flags, all unmatched halves count toward `enter_exit_unmatched`.
- Boundary remnants are reported as `enter_exit_unmatched_boundary`.

## CSV files

- Every table includes `case_id` and the eight run-key columns.
- Those columns are `case_variant`, `permission`, `interval`, `window`, `phase`, `replicate`, `sync`, and `config_id`.

| CSV | Columns and interpretation |
| --- | --- |
| `case_summary.csv` | Previous-rule finding/package confirmation counts and rates, FPR/FNR, GT coverage, `guess_dependency_rate`, `guess_dependency_lower`, `guess_dependency_upper`, `intel_condition`, `intel_source`, image identity verification, exposure verdict |
| `classification.csv` | Previous-rule finding counts and confirmation rates overall, by priority, by package class, and under degraded intelligence |
| `factors.csv` | Verdict/factor breakdown, package counts, total findings, act-now findings, watch findings, low-priority findings |
| `gap_classes.csv` | E1–E4/unclassified confirmation gaps, recoverability, package/finding counts, act-now/watch findings |
| `path_resolution.csv` | `ownership`, `trivy_match`, and distinct `paths` tallies |
| `permissions.csv` | `operation`, `result`, `occurrences`, `message`, plus `target_finding`, `confirmed`, `unconditional_rate`, `conditional_rate`, `state_observation_failed` |
| `gt_b.csv` | Previous-rule population, undetermined count, coverage, TP/FP/TN/FN, FPR/FNR, upper/lower bounds |
| `g4.csv` | Previous-rule and event-series ranking comparisons, priority, N/A status, total findings, top-20 rank changes, labeled count, `exposure_stages_in_top20`, labeled/unlabeled examples |
| `series.csv` | Three-series confirmation metrics overall and by priority, package class, ecosystem, and evidence granularity, observed binary/file counts, collection completeness, overall GT-B accuracy, separate series increments |
| `source_inputs.csv` | Each evidence source's input state, positive package count, missing-input or failed-input reasons |
| `mapping.csv` | Per-ecosystem scan files, matched files/packages, observed binary/file counts, unmappable reasons, candidate conflicts, separate unresolved, unmappable, and outside-scan path/event counts |
| `occurrence_capture.csv` | Pairing rule, tolerance, clock basis, execution/load/actual-open counts and rates, `exec_decidable`, `load_decidable`, `real_open_decidable`, ambiguities, `exec_undecidable`, `load_undecidable`, exclusions, uncaptured reasons |
| `event_drops.csv` | Event state, collection settings, total/attributed/in-window events, before/after-filter counts, lost events, loss notifications, map overflow, conversion failures, early-stop gaps, partial-event details |
| `attribution.csv` | `match_rule`, `cross_container_evaluable`, misattribution and correct-attribution counts/rates, other-container and host errors, host non-attribution and unobserved counts, `host_correct_rate`, unattributed events, `undecidable` |

- `permissions.csv` includes a row even when no operation failed.
- Occurrence rates use `exec_decidable`, `load_decidable`, or `real_open_decidable` as appropriate.
- Those rates are N/A when their denominator is zero.
- Actual-open capture is also N/A without independent actual-open input.
- `event_drops.csv` separates `enter_exit_unmatched` from `enter_exit_unmatched_boundary`.
- It also records `identity_unavailable` and `unmatched_identity_unavailable`.
- Its `partial_events` total does not change event state.
- Detailed `unmeasured` explanations remain in JSON and notes.
- Attribution rates are N/A when their respective denominators are zero.
- `misattribution_rate` is also N/A whenever `cross_container_evaluable=false`.
- Host metrics and correct-attribution metrics remain separate.
- `tools/record.py` produces an individual run record.
- `tools/aggregate.py` aggregates saved runs into `out/AGGREGATE-events.md` under the experiment.
- `tools/case-post.sh` reprocesses saved runs.
- `RECONVERT=1` includes trace conversion in reprocessing.

## Checking without Docker

- Hand-written inputs in `testdata/` exercise `match` without Docker, root, or an installed Trivy executable.

```sh
go run ./experiments/runtime-discovery match \
  -observation experiments/runtime-discovery/testdata/synthetic_observation.json \
  -trivy experiments/runtime-discovery/testdata/synthetic_trivy.json \
  -case experiments/runtime-discovery/testdata/synthetic_case.json \
  -gtb experiments/runtime-discovery/testdata/synthetic_gtb.json \
  -intel-cache ./out/intel-cache \
  -out-intel-snapshot ./out/dry-run/intel.json \
  -out-json ./out/dry-run/match.json -out-csv-dir ./out/dry-run/csv
```

- The result contains match JSON and fourteen CSV files.
- `testdata/` has no intelligence snapshot.
- The first run can therefore require network access.
- Reported intelligence conditions and errors need inspection.
- Subsequent reproducible runs add `-intel-snapshot ./out/dry-run/intel.json`.
- Synthetic limited GT-B confirms positive use only.
- Event capture rates require event logs and independent occurrence records.

## Detailed limitations and cautions

- The coverage fixtures do not pin apt package versions, so an image rebuilt later is not assumed equivalent to the image used for truth.
- Scoring requires the same image ID for truth and measurement, with fresh containers preventing reuse of a previous run's writable layer.
- Truth and coverage use ecosystem-aware triples, but match's `(class, package, installed_version)` grouping can already merge same-name, same-version language packages from different ecosystems.
- strace changes timing and scheduling, so truth and measurement correspond through operation sequences and verified instances rather than equal elapsed time.
- A shared operation name does not establish correspondence for an unpaired periodic instance.
- Static Go binaries and embedded-module usage are outside this coverage population.
- `coverage_plan` groups express intended behavior and can differ from measured usage because of transitive loading.
- `completeness.ok` is the implemented usage-completeness decision rather than a guarantee that every inventory source was read successfully, so `inventory_scan`, `ledger_gaps`, and `version_unknown` remain necessary diagnostics.

- The harness is independent of the product binary and container image.
- There is no daemon mode or support for Kubernetes/containerd observation.
- `collect` does not collect eBPF events itself.
- Event measurements use the separate [runtime-events tool](../runtime-events/README.md).
- Address decoding uses the host's native byte order.
- Observations record the host architecture.
- Cases 10/14 hard-code `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`.
- Parser checks use hand-written fixtures.
- The recorded live measurement set contains 43 runs of 300 seconds on a development environment's Linux 6.6 kernel as root.
- Those measurements cover `startup`, `attach_running`, and buffers of 64/256/512 pages.
- The initial six-second check used seven probes before plain `open` probes were added.
- Current scripts define seven tracepoints plus `BEGIN` and `END`, totaling nine probes.
- Production-host `attach_running` measurements on kernel 7.0 remain unperformed.
- Collection using only `CAP_BPF` and `CAP_PERFMON` remains unperformed.
- Event-observation overhead measurements and a minimal CO-RE implementation remain unperformed.
- Replicate numbers of two or greater are available only for case 13.
- Sampling can miss short-lived activity.
- Mapped language extensions need not match Trivy package paths.
- Added mappings depend on scan file information and saved auxiliary inputs.
- Bounded searches cover conventional installation roots.
- Missing or truncated layouts limit later resolution.
- Target acceptance establishes registration preparation rather than full mapping coverage or tracer attachment.
- Event observation cannot recover work completed before attachment.
- `startup` and `attach_running` results must remain separate.
- Python module lists can name source files even when the interpreter read compiled cache files.
- Cases 15/16 do not independently establish which path spelling was actually opened.
- Cases 17/18 have effectively millisecond timestamp precision despite additional fractional digits.
- Java loads in cases 19–21 can read an already-open archive without opening it again.
- `startup_open` and `load_open` must remain distinct.
- Missing load-time opens do not establish non-use.
- Those Java cases lack independent OS thread identity and are excluded from reported occurrence capture.
- An outer jar observation does not establish independent loading or execution of its bundled dependencies.
- A static Go binary observation does not establish execution of each embedded module.
- Actual file-open syscall capture remains unavailable without independent `real_opens`.
- Supplied cases 13–24 provide usage and occurrence logs rather than that syscall record.
- Their reported actual-open capture rate is N/A.
- Recorded attribution controls cover case 23 alone, case 24 alone, both together, and case 23 with host activity.
- The measured host control ran `/usr/bin/curl` every five seconds for 50 iterations alongside the container workload.
- Eligible host executions remained unattributed in 41/41 and 48/48 cases.
- Those host checks used PID namespace, namespace-local PID/TID, and generation matching.
- Correct-attribution rates were 1.0 under the recorded rule across the four conditions.
- Those runs used `container_namespace_pid_and_thread` without `pid_map`.
- Cross-container misattribution remained N/A.
- The host result does not establish cross-container correctness.
- Evidence can only raise priority.
- Missing evidence establishes neither safety nor grounds for lowering priority.
- A listener does not prove internet reachability.
