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

- `symlinks` records links found in module trees, `/etc/localtime`, direct entries of `/etc/alternatives` and conventional bin/sbin directories, and paths listed by the OS package database.
- The conventional directories are `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, and `/usr/local/sbin`, with their direct entries inspected without recursive descent.
- Each link retains its path and raw `readlink` target, preserving whether the target is relative or absolute.
- `owned_paths[].is_dir` records whether the path itself was a directory at observation time, using `lstat` without following a symlink in the final component.
- Directory flags and package-database symlink targets are read again on every auxiliary reading even when the path-to-owner index is cached.
- Directory flags participate in the auxiliary-generation fingerprint so a directory-to-file change can produce a new generation without a package database change.
- The extra-symlink budget is shared by `/etc/localtime`, `/etc/alternatives`, conventional bin/sbin entries, and package-database links, with those sources inspected in that order.
- Exhausting that budget records an `extra_symlinks` truncation without stopping directory-flag inspection.
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

| `-aux-max-extra-symlinks` | Shared link-entry limit per reading for `/etc/localtime`, `/etc/alternatives`, conventional bin/sbin directories, and the OS package file list, default `20000` |
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
- Links collected while listing module trees have a separate fixed limit of 100,000 symlink targets per reading.
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

#### Extraction failures and temporary space

- `truth.py` exports the image's rootfs into a temporary directory and stops with a non-zero exit, writing no `truth.json`, when the export, the archive extraction, or any file write fails.
- Before exporting, it requires free space of at least twice the image size reported by `docker image inspect` and stops with a non-zero exit when the space is short.
- `KL_TRUTH_TMPDIR` selects the directory for the extraction, and `KL_TRUTH_KEEP_TMP=1` keeps the extracted tree after the run instead of deleting it.

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

### Symlinks, directories, and application manifests

- Saved symlink chains are resolved component by component, with absolute targets starting at the container root and relative targets starting at the link's parent directory.
- Resolution follows at most 40 links and discards partial substitutions if the chain exceeds that limit, including through a cycle.
- OS matching queries the original path after merged-`/usr` normalization and the symlink-resolved path separately.
- If each path has a single owner and the owners differ, both packages receive use confirmation, following the ground truth.
- A match through a changed target path records `Via` as `symlink:<resolved-path>`.
- Multiple ownership claims for either individual path produce `Conflict`, even if the other path has a single owner.
- Before any package-matching rule, an open event is rejected as package-use evidence if saved `is_dir` information identifies either the original or resolved path as a directory.
- These exclusions use `missDirectoryOpen` (`directory_open`) and are counted in `directory_open_events` separately from `outside_scan_events`.
- The directory-open exclusion applies to open events rather than executions or sampled paths.
- `node_project_manifest` searches for the nearest ancestor `package.json` named by the scan only when neither the resolved path nor the original path has a `node_modules` package boundary.
- This rule covers the application's own manifest without attributing a dependency to the application merely because a symlink leads outside `node_modules`.
- If no saved reading covers an event's instant, including before the first layout reading, matching falls back to the observed path and scan index alone.
- That fallback uses neither saved OS ownership nor the symlink table because later readings cannot establish that the earlier layout was unchanged.

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

- `read_event_state` treats only positive `lost_events`, `lost_notifications`, or `map_overflow` counters as event loss, while `event_state=degraded` also enables the run-wide loss-candidate signal.
- Captured-event attribute failures such as `path_read_failures` and ordinary counts such as `events_before_filter` and `events_after_filter` do not independently establish event loss.
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

### Ranking changes (coverage_rank.py)

- `tools/coverage_rank.py [out-dir]` aggregates saved `g4` rankings against scored coverage results and defaults to `experiments/runtime-discovery/out`.
- Outputs are `AGGREGATE-rank.md` and `AGGREGATE-rank.csv` under the selected directory.
- The baseline is the order without runtime information, determined by priority, severity, package, and vulnerability ID.
- A `series=none` reference row represents that baseline once per run, scan variant, and priority.
- Ranking comparisons use only the S0 and S2 series produced by matching and only the `act_now` and `watch` priority buckets.
- S0 uses sampling evidence, while S2 combines sampling, added mapping, and event evidence.
- The detail table has one row per run × scan variant × series or baseline × priority.
- The Markdown summary groups otherwise identical conditions across replicates and reports agreement across the numeric columns with `consistent=yes` or `no`, marking differing values with `DIFFERS:`.
- Missed-package columns use the corresponding scan variant's S2 misses from `coverage.json`, matched by package name and installed version for every ranking series.

| Column | Meaning |
| --- | --- |
| `total_findings` | Number of Findings in the priority bucket |
| `rank_changed_count` | Number of Findings in the adjusted top 20 whose adjusted rank differs from their baseline rank |
| `vs_no_runtime_rank_changed` | The same count as `rank_changed_count`, explicitly naming the comparison with no runtime information |
| `top20_promoted` | Number of Findings in the adjusted top 20 with `adjusted_rank < baseline_rank` |
| `labeled_count` | Number of Findings across the entire priority bucket meeting the combined label of confirmed use, publication to the world, and privileged execution |
| `missed_pkg_findings` | Total Findings in this priority bucket belonging to packages listed as S2 misses |
| `missed_pkg_in_top20` | Findings belonging to those missed packages that appear in this series' adjusted top 20 |
| `missed_pkg_rank_unchanged` | Subset of `missed_pkg_in_top20` with `adjusted_rank == baseline_rank` |
| `missed_pkg_not_promoted` | Subset of `missed_pkg_in_top20` with `adjusted_rank >= baseline_rank`, including unchanged and displaced-to-later ranks |
| `missed_pkg_outside_top20` | `missed_pkg_findings - missed_pkg_in_top20`, whose adjusted ranks are unavailable |
| `false_promotions` | Promoted Findings in the adjusted top 20 whose package and version are FP in this series, after restricting FP packages to those with Findings in this priority bucket |

- `false_promotions` is zero when no FP package has a Finding in the relevant priority bucket.
- If any relevant FP package is absent from that bucket's stored top 20, `false_promotions` is N/A because its promotion cannot be determined.
- Findings outside the stored top 20 are not included in `missed_pkg_not_promoted` because their rank changes are unavailable.
- Baseline rows report zero rank changes and promotions, with label, missed-rank, and false-promotion fields shown as N/A.

### Checks with the updated collector

- The verification runs for cases 26, 27, and 28 used `startup` with a 300-second window and the updated collector.
- Case 27 reached 100% Node recall (72/72, including the application's own `package.json`) and 100% resident-OS recall (8/8).
- Case 26 reached 94% resident-OS recall (17/18), and case 28 reached 91% (10/11).
- The one remaining resident-OS miss in each of cases 26 and 28 was `tzdata`, whose `/etc/localtime` open occurred immediately after container startup and before the first layout reading.
- The saved symlink tables contained 438 entries in case 26 and 917 in case 28, while case 28 recorded 2,822 entries with `IsDir` set.
- These verification runs had no truncation and zero false positives.

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

- Events before the first layout reading use only the scan index, without OS ownership or the symlink table, because the earlier layout's immutability cannot be established.
- Opening a directory alone does not establish package use, and its exclusion depends on directory information retained in the saved input.
- A link and target with different single owners confirm both packages, following the ground truth, while multiple owners of either individual path remain a conflict.
- Ranking comparisons exist only for S0 and S2 in the matching implementation, and stored top-20 results do not establish rank changes for Findings outside that window.

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

## Load and privilege measurement

### supervise

`supervise` starts the specified command directly as a child and handles placement in a dedicated cgroup v2, verification of the actual executable and privileges, stop requests, and final measurements.

```sh
sudo experiments/runtime-discovery/out/runtime-discovery supervise \
  -cgroup /sys/fs/cgroup/runtime-discovery-example \
  -record experiments/runtime-discovery/out/supervise.json \
  -stop-request experiments/runtime-discovery/out/supervise-stop.txt \
  -grace 10 -deadline 30 -- /usr/bin/sleep 20
```

| Flag | Meaning |
| --- | --- |
| `-cgroup` | New cgroup v2 directory to create, which must not already exist |
| `-record` | Required output path for the JSON supervision record |
| `-user` | Existing user whose UID/GID is selected before exec, rejecting UID 0 |
| `-expect-exe` | Path to compare exactly against `/proc/<pid>/exe` after startup |
| `-expect-capeff` | Hexadecimal value to compare against the actual process's `CapEff`, ignoring letter case |
| `-unset-env` | Comma-separated environment variable names to remove from the child's environment |
| `-stop-request` | File checked once per second, with nonempty contents used as the stop reason |
| `-grace` | Seconds to wait after SIGINT and again after SIGTERM, default `10` |
| `-deadline` | Maximum seconds after startup before requesting a stop, with the default `0` disabling the deadline |
| `-allow-unmeasured` | Continue without confirmed memory-controller availability and record memory as unmeasured with a reason |
| `-keep-cgroup` | Retain the cgroup and counters after exit for the caller's final readings and removal |
| `-no-cgroup` | Supervise without a dedicated cgroup and mark cgroup-derived fields unmeasured, mutually exclusive with `-cgroup` |
| `-- cmd [args...]` | Command and arguments to start directly |

- With a cgroup, supervision creates a new directory under `/sys/fs/cgroup` and attempts to enable available cpu and memory controllers through the ancestor hierarchy.
- When `clone3` with `CLONE_INTO_CGROUP` works, the child runs inside the cgroup from its first instruction, recorded as `cgroup_method=clone3_cgroup_fd` and `placement_atomic.value=true`.
- The fallback writes the actual PID to `cgroup.procs` immediately after startup, recorded as `cgroup_method=post_start_write_fallback` and `placement_atomic.value=false`.
- Fallback counters omit some startup CPU and initial memory, making the load measurement incomplete for comparison.
- A stop file, SIGINT/SIGTERM delivered to the supervisor, or the execution deadline initiates the same SIGINT, SIGTERM, and SIGKILL sequence.
- The final wait after SIGKILL is five seconds, and an unconfirmed child exit produces `status=stop_unconfirmed` without an invented exit time or code.
- A reaped child whose cgroup still contains descendant tasks produces `status=exited_residual_tasks`.
- Under `-no-cgroup`, descendant absence cannot be established, so `termination_confirmed` remains unmeasured even when the child was reaped.
- The supervisor's own exit code describes supervision and can be zero after successfully supervising a child that failed.

#### Main supervise.json fields

The record is written after startup verification and rewritten with the final state after stop handling. Independently measured fields use objects containing `measured`, `value`, and an optional `reason`; a `value` with `measured=false` is not a measurement.

| Field | Meaning |
| --- | --- |
| `command`, `pid`, `actual_exe` | Started command, actual child PID, and executable read from procfs |
| `real_uid`, `effective_uid`, `saved_uid`, `filesystem_uid` | Four UID values read from the actual process |
| `cap_eff`, `attr_current`, `limits` | Actual effective capabilities, LSM attribute, and resource limits |
| `exe_verified`, `uid_verified`, `capeff_verified`, `verification_error` | Executable, UID, and CapEff verification results and any inability to verify |
| `cgroup`, `cgroup_method`, `placement_atomic` | Placement directory, method, and whether placement covered the first instruction |
| `controllers_enabled`, `controller_warnings` | Controller enablement records and warnings |
| `started_at_wall`, `started_at_monotonic_s` | Startup time and the monotonic reference whose zero is startup |
| `exited_at_wall`, `exited_at_monotonic_s` | Time the child's exit was confirmed and elapsed seconds since startup |
| `exit_code`, `exit_signal`, `wait_error` | Child exit code, terminating signal, and wait error |
| `status` | `setup_failed`, `running`, `exited`, `exited_residual_tasks`, or `stop_unconfirmed` |
| `stop_requested`, `stop_reason`, `deadline_exceeded` | Stop request, reason, and deadline status |
| `termination_confirmed`, `residual_tasks` | Confirmation of child reaping and no remaining tasks, plus cgroup residual-task status |
| `baseline_cpu_usage_usec`, `final_cpu_usage_usec` | Cumulative CPU usage before startup and after stop handling |
| `baseline_memory_peak_bytes`, `final_memory_peak_bytes` | Cgroup memory peaks before startup and after stop handling |
| `cgroup_removed` | Removal result or reason for retention or failed removal |

`exit_code` is `null` when no exit was observed; a signal-terminated child records `-1` alongside `exit_signal`. `termination_confirmed` is measured true only when the child was reaped and the cgroup reported `populated=0`.

### cgroup-stat and cgroup-remove

`cgroup-stat` writes a cgroup's CPU, memory peak, and residual-task status to standard output as JSON.

```sh
experiments/runtime-discovery/out/runtime-discovery cgroup-stat "<cgroup v2 directory>"
```

- The single required positional argument is the cgroup v2 directory to read.
- Output contains `path`, `cpu_usage_usec`, `memory_peak_bytes`, and `populated`.
- CPU comes from `cpu.stat`'s `usage_usec`, memory from `memory.peak`, and residual-task status from `cgroup.events`'s `populated`.
- Each reading succeeds or fails independently, so successful command completion does not establish that every field was measured.

`cgroup-remove` waits for a cgroup to have no tasks, removes its directory, and writes the result to standard output as JSON.

```sh
sudo experiments/runtime-discovery/out/runtime-discovery cgroup-remove \
  -wait 30 "<cgroup v2 directory>"
```

- The single required positional argument is the cgroup v2 directory to remove, and `-wait` defaults to `30` seconds.
- Output contains `path`, `populated`, `removed`, and `waited_s`.
- Emptiness is established from `cgroup.events` reporting `populated=0`, never inferred from the size of `cgroup.procs`.
- An already-absent directory is reported as removed with a reason.
- Unreadable state, remaining tasks after the wait, or failed removal records a reason and returns non-zero.
- After final readings, remove a hierarchy retained with `-keep-cgroup` in child-first order, followed by the parent.

### optime and operational command timing

`optime -- cmd [args...]` starts a command as a child, measures elapsed time from startup handling through reaping with `CLOCK_MONOTONIC`, and writes one JSON line to standard output. The child command's stdout and stderr are discarded.

- `stage_optime` in `cases/run.sh` builds a static binary with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.
- The binary is staged at each case's `cases/images/*/optime`, and the Dockerfiles for cases 26 through 28 copy it to `/usr/local/bin/optime`.
- Rebuilding is skipped when the staged executable is newer than `cmd/optime/main.go`.
- Each image's `os-ops.sh` runs curl, git, and openssl through this helper.
- The helper's `pid` and `starttime` identify the actual wrapped child command, with `starttime` recorded as zero when it cannot be read.
- Duration uses a monotonic-clock difference truncated to microseconds, separately from wall-clock start and end times.

| Output | Fields and meaning |
| --- | --- |
| `optime` stdout | `pid`, `starttime`, `start_wall`, `end_wall`, `duration_us`, `exit_code`, and `clock_source` |
| Existing `operations.jsonl` fields | Preserved `id`, `ts`, `op`, and `ok`, with `op` set to `osops_curl`, `osops_git`, or `osops_openssl` |
| Added `operations.jsonl` fields | `end_ts`, `duration_ms`, `exit_code`, `clock_source`, and `clock_resolution_ms` |
| `duration_ms` | The helper's `duration_us` divided by 1000 and recorded in milliseconds with three decimal places |
| `clock_source`, `clock_resolution_ms` | `CLOCK_MONOTONIC` and `0.001` |
| `exit_code` | Child command exit code, with `ok` indicating whether it is zero |

`duration_us` belongs to the helper's output and is not directly stored in the current `operations.jsonl`. The added fields preserve the original fields, allowing existing operation-sequence readers to continue working. Durations from older `operations.jsonl` files without timing fields are unmeasured with reasons.

### load-run.sh and load.json

Run `tools/load-run.sh <case> [replicate] [config] [interval] [window]` as root to measure cases 26 through 28 with `attach_running`. Defaults are replicate `1`, configuration `procfs`, interval `30` seconds, and window `300` seconds.

| Configuration | Observation performed |
| --- | --- |
| `none` | No collector or tracer and no observation record |
| `procfs` | Collector |
| `events` | Collector and a 512-page nofilter tracer |

Every configuration runs the same workload and host-side web requests. The runner waits for workload firing and the lazy phase to finish, starts monitoring, and completes attachment checks and cgroup registration for event runs before deciding the window start. That instant becomes the collector's `-phase-base`.

The output directory is `experiments/runtime-discovery/out/<case>-load-<config>-<interval>-<window>-r<replicate>-attach_running/`.

| File | Contents |
| --- | --- |
| `run.log`, `case.json`, `clock.json` | Run log, case definition, and clock conversion |
| `container_id.txt`, `image_id.txt`, `fired_at.txt` | Container and image identities and the timestamp recorded after firing |
| `collector_supervise.json`, `tracer_supervise.json` | Supervision records for the processes started |
| `cgroup-<target>-wstart.json`, `cgroup-<target>-wend.json` | Window-start and window-end readings for applicable `collector`, `tracer`, and `docker` targets |
| `cgroup-remove-<target>.json` | Removal records for `collector`, `tracer`, and `parent` |
| `collect/` | Observation and manifest for configurations running a collector |
| `trace.txt`, `trace.err`, `events.jsonl`, `cgroup-map.json` | Event configuration's trace, timestamped stderr, converted events, and cgroup table |
| `trace-stdout-wstart-bytes.txt`, `trace-stdout-wend-bytes.txt`, `trace-stderr-wstart-bytes.txt`, `trace-stderr-wend-bytes.txt` | Trace output byte counts at window start and end |
| `gtb-raw/` | `usage.jsonl`, `occurrences.jsonl`, `operations.jsonl`, `runtime-modules.jsonl`, and `docker-top.txt` |
| `web_timing.jsonl`, `web_timing.err` | Host-side web response records and errors |
| `watch_targets.txt`, `watch.jsonl`, `watch.log` | Monitoring targets, samples, and monitor process log |
| `stop_request.txt`, `termination_confirmed.txt`, `stop_failures.txt` | Stop request, termination confirmation, and failed confirmation reasons when applicable |
| `load.json` | Per-run load summary assembled from raw records by `load_run_assemble.py` |

`stop_request.txt` is used for early stops and also for normal window-end shutdown when supervised targets exist. Use `stopped_early` and `stop_reason` in `load.json` to identify an early stop.

#### Four checkpoints

| Checkpoint | Source and meaning |
| --- | --- |
| `before_start` | The supervisor's `baseline_*` readings before child startup |
| `window_start` | The runner's `cgroup-stat` readings when the common observation window opens |
| `window_end` | The runner's `cgroup-stat` readings when the window closes, before requesting shutdown |
| `process_exit` | The supervisor's `final_*` readings after child exit waiting or stop handling |

- Collector and tracer CPU measurements are divided into `prep`, `window`, `drain`, and `total`.
- `prep` spans before startup to window start, `window` spans window start to end, `drain` spans window end to the final reading, and `total` spans before startup to the final reading.
- JSON field names are `collector_cpu_usage_delta_<segment>_us` and `tracer_cpu_usage_delta_<segment>_us`.
- A collector that takes all scheduled samples and exits before window end retains its counters through `-keep-cgroup` for the window-end reading.
- `collector_memory_peak_bytes` and `tracer_memory_peak_bytes` cover the cgroup's lifetime rather than only the window.
- `docker_daemon_cpu_usage_delta_window_us` comes from direct window-start and window-end readings of the same daemon cgroup in every configuration.
- Unreadable values and deltas from decreasing counters become unmeasured with reasons.

#### Window establishment and measurement completion

| Field | Meaning |
| --- | --- |
| `run_id`, `case`, `config`, `interval`, `window`, `replicate`, `sync` | Run conditions |
| `container_id`, `image_id`, `fired_at` | Workload identities and the timestamp recorded after firing |
| `window_start_wall`, `window_end_wall`, `window_end_planned_wall` | Window start, actual close, and planned end |
| `tracer_exited_at_wall` | Exit time from the tracer supervision record or an unmeasured reason |
| `window_established`, `window_start_drift_s` | Whether the planned window start was established and the runner's start drift |
| `collector_first_sample_delay_s` | First collector sample's delay from its scheduled time |
| `stopped_early`, `stop_reason` | Early-stop status and reason |
| `measurement_complete`, `measurement_incomplete_reasons` | Supervision and observation completion decision and reasons |
| `collector_valid_samples`, `collector_invalid_samples` | Valid and invalid counts from collector collection results |
| `cgroup_cleanup`, `stop_failures`, `notes` | Cgroup removal results, failed stop confirmations, and interpretation notes |
| `dump_logs_ok`, `watch_samples`, `watch_stop_reason` | Workload-log retrieval status, monitor sample count, and stop reason |

The lead time before window start defaults to five seconds through `KL_WINDOW_LEAD_S`, and start tolerance defaults to two seconds through `KL_WINDOW_START_TOLERANCE_S`. Runner start drift or a first collector sample delay beyond the tolerance sets `window_established=false`.

Reasons for `measurement_complete=false` include the following.

- Missing supervision records, non-atomic or unverified cgroup placement, or unconfirmed termination.
- Recorded cgroup removal failures or runner stop-confirmation failures.
- A missing collector exit code or non-zero collector exit.
- Missing observation or sample timing, fewer attempted samples than planned, or target inspection failure.
- Missing collection results or no valid observation among them.
- Unconfirmed tracer attachment or event collection in state `failed`.
- A missing tracer exit time or exit before the planned window end.

The planned sample count is `max(1, window // interval)`. A collector that attempts all scheduled samples and exits before window end is not incomplete merely because it exited then. `measurement_complete`, `window_established`, and `stopped_early` are independent fields, and individual unmeasured values and event degradation also require inspection.

`comparison_blocker` is the comparison function in `load.py`, not a `load.json` field. It finds the `none` control with the same case, interval, window, and replicate number and blocks comparison for the following reasons.

- No matching `none` control exists.
- Either run stopped early.
- Either run does not explicitly record `window_established=true`.
- Either run does not explicitly record `measurement_complete=true`.
- Planned window lengths differ.
- Image IDs are missing or different.

The aggregate table records the decision in `comparable_to_none` and `not_comparable_because`. Available absolute measurements remain visible when comparison is blocked, while median differences become unmeasured with reasons. A `none` row uses itself as the control without applying this comparison check, so measured medians have a self-difference of zero.

#### Events, output growth, and workload

- `events_total` and `events_attributed` count all events and target-container events whose `ts` falls inside the actual observation window.
- `events_total_per_second` and `events_attributed_per_second` divide those counts by the actual window duration.
- `events_outside_window` counts events not included in the window.
- `drops` retains conversion-trailer loss information rather than applying the same timestamp filtering used for window event counts.
- `drops` preserves `lost_events`, `lost_notifications`, `map_overflow`, `convert_failures`, `enter_exit_unmatched`, `enter_exit_unmatched_boundary`, `path_read_failures`, `path_truncations`, `identity_unavailable`, `unmatched_identity_unavailable`, `events_before_filter`, and `events_after_filter`.
- `partial_events` follows the existing rule by summing path-read failures, path truncations, unmatched boundary halves, and unavailable identity.
- `malformed_lines` counts unparseable lines in converted JSONL and is also added to the trailer's `convert_failures` when a trailer exists.
- A missing trailer leaves loss fields unmeasured instead of zero, except that actually counted malformed lines can supply `convert_failures`.
- `event_state` uses `not_attempted`, `failed`, `observed`, and `degraded`, with missing trailers, malformed lines, early stops, losses, and unmeasured categories contributing to degradation.
- `trace_stdout_bytes` and `trace_stderr_bytes` are whole-trace sizes, while their `*_bytes_per_second` fields divide window-start/end byte increments by the actual window duration.
- Separate `*_bytes_per_second_whole_lifetime` fields use the tracer's full lifetime as the denominator.
- `run_dir_growth_bytes` is the sum of file sizes in the run directory, which started empty.

`workload.curl`, `workload.git`, and `workload.openssl` summarize operational commands whose start and end in `operations.jsonl` both fall within the window. Commands crossing a boundary or having unknown timing count toward `boundary_crossing`, while wholly excluded commands count toward `outside_window`.

- Each summary contains `n`, successful-command `median_ms`, `p95_ms`, and `max_ms`, and the failure count `failures`.
- Median and p95 use nearest-rank percentiles without interpolation.
- No matching operations produces a reason in `state`, and all-failed operations leave duration statistics unmeasured.
- `workload.web` summarizes host-side requests issued on a planned five-second schedule.
- Web requests use a two-second connection timeout and a four-second total limit, with successful curl completion and HTTP 2xx/3xx required for success.
- `web_timing.jsonl` records `planned_ts`, `ts`, `seq`, `status`, `latency_ms`, `ok`, `curl_exit`, and `timeout_type`.
- Web summaries add `success_count`, `timeout_count`, and `failure_count`, classifying only `operation_timeout` as a timeout.
- Connection failures, resolution failures, empty replies, unsuccessful HTTP responses, and other errors count as non-timeout failures.

### watch-run.sh stop conditions and bounds

`tools/watch-run.sh <run dir> <out root dir> <targets file> <stop file>` is normally started by `load-run.sh`. Its required arguments are the run directory, shared output directory, monitoring targets file, and shared stop-request file.

| Environment variable | Default and stop condition |
| --- | --- |
| `KL_WATCH_INTERVAL` | Sampling interval of `10` seconds |
| `KL_WATCH_CPU_CORES` | Tracer CPU exceeds `1` core-equivalent for three consecutive samples |
| `KL_WATCH_RUN_BYTES` | Run exceeds `1073741824` bytes |
| `KL_WATCH_ROOT_BYTES` | Shared output exceeds `4294967296` bytes |
| `KL_WATCH_FREE_BYTES` | Free space falls below `21474836480` bytes |
| `KL_WATCH_WEB_FAILURES` | `3` consecutive web responses fail in recorded order |

- An increasing loss-notification count for three consecutive samples also requests a stop, and that streak length has no environment override.
- CPU core-equivalents divide the cgroup CPU delta by monotonic elapsed time from `/proc/uptime`, rather than the configured sampling interval.
- A failed CPU reading discards the previous baseline, and the next successful reading establishes a new one.
- Web failure streaks are evaluated response by response, so a later success in the same monitor sample does not undo a threshold already reached.
- The monitor writes a stop reason to the shared file without directly signaling targets.
- An existing nonempty stop reason is preserved.
- Monitoring continues after a stop request, with samples in `watch.jsonl` and stop requests and monitoring-bound exits in `run.log`.

#### Targets file

| Key | Meaning |
| --- | --- |
| `tracer_pid`, `collector_pid` | Monitoring PIDs published by the runner, currently the respective `supervise` PIDs |
| `tracer_cgroup`, `trace_err`, `web_timing` | Sources for CPU, loss notifications, and web responses |
| `expect_tracer`, `expect_collector` | `0` or `1` indicating whether the run expects each supervised target, including before startup |
| `min_until_epoch` | Planned observation-window end in epoch seconds |
| `termination_confirmed_file` | File the runner writes only after confirming termination of every supervised target |
| `residual_unconfirmed` | `1` when the runner has determined that termination cannot be confirmed |
| `watch_until_epoch` | Absolute bound for the monitor itself in epoch seconds |

The targets file is reread on every sample. Normal exit requires the expected monitoring PIDs to have been announced and exited, the planned window end to have passed, and a nonempty `termination_confirmed_file`. `residual_unconfirmed=1` prevents treating termination as confirmed. The older format without `expect_*` uses whether all announced PIDs have exited.

Reaching `watch_until_epoch` records `WATCH_EXIT` with termination undetermined and exits with code 3. `load-run.sh` sets this bound from the planned window end plus `KL_RESIDUAL_WATCH_S`, which defaults to 1800 seconds, and also publishes a finite bound during preparation and after failed termination confirmation. Once every supervised target is confirmed stopped, the runner writes the confirmation file, stops monitoring, and removes cgroups. Otherwise, it leaves monitoring and cgroups in place and exits non-zero. The `none` configuration also monitors capacity and web responses, with the runner stopping the monitor after window-end or stop handling.

Supervised process deadlines are managed separately by `supervise -deadline`. `load-run.sh` gives the tracer the sum of the preparation budget, window lead time, window length, and deadline allowance; the collector receives the same sum without the preparation budget. Defaults are `KL_PREP_BUDGET_S=180` and `KL_WATCH_HARD_DEADLINE_GRACE_S=120`.

### privilege-run.sh operations and decisions

Run `tools/privilege-run.sh <condition>` as root. Non-root conditions use the existing user named by `KL_PRIV_USER`; the script does not create an account.

| Condition | Execution user and capabilities applied to copies |
| --- | --- |
| `root` | Run as root without applying capabilities to the copies |
| `bpf_perfmon` | Non-root with `cap_bpf,cap_perfmon=ep` |
| `bpf_perfmon_dac` | Non-root with `cap_bpf,cap_perfmon,cap_dac_read_search=ep` |
| `sysadmin` | Non-root with `cap_sys_admin=ep` |

Capabilities are applied to both private copies of bpftrace and `runtime-events` in a dedicated directory under `/var/tmp`. System executables and sysctls are unchanged. Results are saved as `out/privilege-<condition>.json` and `.md`, with raw evidence under `out/privilege-<condition>-artifacts/`. Here, `out/` means `experiments/runtime-discovery/out/`.

| Operation key | Check and decision |
| --- | --- |
| `bpf_program_load` | Test the nofilter script with `--dry-run -v`, reporting completed loading as success, a load-stage error as failure, and an unknown stage as unreached |
| `tracepoint_attach` | Use `attach-check` to confirm a known event from a normally started tracer, reporting success when confirmed, unreached when loading did not complete or the stage is unknown, and failure for other unconfirmed attachment |
| `buffer_create_and_read` | After attachment confirmation, execute a unique marker in a temporary container, reporting success when it reaches the trace, failure when it does not, and unreached without confirmed attachment |
| `cgroup_id_map` | Require child exit code zero from `runtime-events cgroup-map`, nonempty `entries`, empty `errors`, no entry `handle_error`, and an entry for this operation's own cgroup |

- `result=success` means the operation's confirmation conditions were met.
- `result=failure` means the privilege condition was established but the operation's check failed.
- `result=unreached` means preparation failure, an unestablished privilege condition, an incomplete preceding stage, or an unknown reached stage prevented evaluation.
- Unperformed conditions or runs without records receive no invented success or failure, and the current tool does not generate a fourth `result` value specifically for unperformed work.
- A missing operation result file during summary assembly also defaults to `unreached` with a reason.
- Operation `exit_code` and `exit_signal` describe the child, while `supervisor_exit_code` describes supervision.

#### Stage heuristics and condition_established

The bpftrace stage classifier uses heuristics over v0.25.0's free-text diagnostics. These are not machine-readable stage reports, and the rules apply in the following order.

1. A `--dry-run` child exiting zero establishes successful loading.
2. `Attached N probes` establishes completed loading.
3. Attachment diagnostics such as `cannot attach probe` produce `attach_failed`, implying that loading itself completed.
4. Compilation, verifier, or program-loading errors produce `load_failed`.
5. Anything else remains `unknown`, without inferring the stage from the exit code alone.

Each operation records `condition_established` separately from its result. It verifies the actual executable and, for non-root conditions, requires real and effective UIDs matching the requested user, a non-zero effective UID, and CapEff matching the requested capability set. The `root` condition inherits execution from the root runner and checks executable identity in its condition decision.

- Successful verification records `condition_established=true`, while failed verification records `false` with an explanation in `condition_detail`.
- Operations that never reached condition verification have `condition_established=null`.
- An unestablished condition produces an unreached result with a `condition_not_established` reason, separately from operation failure under that condition.
- `errno` uses only a number explicitly present in the log and otherwise remains `unknown`.
- `denying_layer` heuristically classifies diagnostic wording as `perf_bpf_check`, `tracefs_dac`, `lsm`, or `unknown`.
- The summary retains requested capabilities, binary SHA-256 hashes, three sysctl values, lockdown, and available per-operation procfs information.
- `log_excerpt` contains at most the last 4000 characters, while artifacts retain complete logs and supervision records.
- Unreached summaries primarily retain reasons and condition status, with details of started operations also available in artifact supervision records.

The working directory is removed only after supervision records confirm termination of every started operation and evidence preservation succeeds. Missing supervision records, residual tasks, failed supervisor waits, or failed evidence preservation retain the original working directory, report reasons and its path, and produce a non-zero exit.

### AGGREGATE-load columns

`tools/load.py [out dir]` reads `load.json` from load run directories directly under the selected directory and creates `AGGREGATE-load.md` and `AGGREGATE-load.csv` with one row per run. The default directory is `experiments/runtime-discovery/out`.

| Column | Meaning |
| --- | --- |
| `run`, `case`, `config`, `interval`, `window`, `replicate` | Run name and measurement conditions |
| `stopped_early`, `stop_reason` | Early-stop status and reason |
| `window_established`, `measurement_complete` | Window establishment and measurement completion |
| `comparable_to_none`, `not_comparable_because` | Comparability with the matching control and blocking reason |
| `collector_cpu_prep_s`, `collector_cpu_window_s`, `collector_cpu_drain_s`, `collector_cpu_total_s` | Collector CPU seconds by segment and in total |
| `collector_memory_peak_bytes` | Collector cgroup memory peak |
| `tracer_cpu_prep_s`, `tracer_cpu_window_s`, `tracer_cpu_drain_s`, `tracer_cpu_total_s` | Tracer CPU seconds by segment and in total |
| `tracer_memory_peak_bytes` | Tracer cgroup memory peak |
| `dockerd_cpu_window_s` | Docker daemon CPU seconds during the window |
| `events_total`, `events_total_per_second`, `events_attributed`, `events_attributed_per_second` | Window event and attributed-event counts and rates |
| `event_state`, `partial_events`, `malformed_lines` | Event state, partial-event count, and unparseable-line count |
| `lost_events`, `lost_notifications`, `map_overflow`, `convert_failures`, `enter_exit_unmatched` | Loss, conversion failure, and unmatched in-window halves exposed in the aggregate |
| `trace_stdout_bytes`, `trace_stdout_bytes_per_second`, `trace_stderr_bytes`, `trace_stderr_bytes_per_second` | Whole-trace sizes and window output growth rates |
| `run_dir_growth_bytes` | Sum of file sizes in the run directory |
| `<kind>_n`, `<kind>_median_ms`, `<kind>_p95_ms`, `<kind>_max_ms`, `<kind>_failures` | Statistics for each `<kind>` of `curl`, `git`, `openssl`, and `web` |
| `<kind>_median_delta_ms` | Each median minus the matching `none` control's median |
| `web_success_count`, `web_timeout_count`, `web_failure_count` | Successful web requests, timeouts, and other failures |

CPU values are converted from microseconds in `load.json` to seconds rounded to three decimal places. Difference columns cover only operational command and web medians. Unmeasured values appear as `n/a (<reason>)`; detailed loss fields, boundary handling, and supervision records remain available alongside the aggregate.

## Observing running containers

Use `prod-precheck.sh` to check the observation environment and `prod-observe.sh` to observe existing containers with `attach_running`. Match observations separately for each generation, then use `prod_summary.py` to classify HIGH/CRITICAL Finding evidence into three states.

### Restart tracking in collect

| Flag | Meaning |
| --- | --- |
| `-track-restarts` | Detect restarts and re-creation and split records by generation, default `false` |
| `-restarts-file` | JSONL path for appended generation events, default `<out-dir>/restarts.jsonl`, unused without `-track-restarts` |
| `-load-unmeasured` | Nonempty reason string that disables cgroup load readings and records them as unmeasured |

Restart tracking checks the Docker API during each sample.

- A changed, nonempty `StartedAt` under the same container ID produces a `restart` event.
- When `docker top` fails for the old ID, the collector lists running containers again and records `recreate` if another ID has the same name.
- Missing `StartedAt` alone does not establish a restart, and failed listing or an absent replacement is checked again on the next sample.
- Failures from the sample that detected the change remain with the old generation, while the new generation rereads layout information without inheriting package-index caches, evidence deduplication state, or auxiliary-input indexes.

Each line in `restarts.jsonl` contains the following fields.

| Field | Meaning |
| --- | --- |
| `kind` | `restart` or `recreate` |
| `container_name` | Tracked name |
| `old_container_id`, `new_container_id` | Container IDs before and after the change |
| `image_id_before`, `image_id_after` | Image IDs before and after the change |
| `started_at_before`, `started_at_after` | Start times before and after the change |
| `detected_at` | Time the change or correction was detected |
| `sample_id` | Sample that detected the change, omitted for correction events |

#### Generation windows, pending changes, and corrections

The old generation's `window.scheduled_end` closes when the change is detected, before the replacement is committed. The boundary prefers a parseable `StartedAt` for the new generation, falls back to `detected_at`, and is clamped to the planned window for the whole run. Once narrowed, the old generation's end is not extended by retries or further changes while replacement remains pending.

If listing or inspecting the new ID fails, replacement remains pending and is retried on the next sample. The old generation's window stays closed. The new generation's start is calculated from the identity confirmed at commit time, using its `StartedAt` or the detection time clamped to the run window as `window.scheduled_start`. Its end is the run's planned end. Further changes during a pending replacement can leave a gap between the old generation's end and the committed generation's start.

When the confirming inspect differs from the detected information, the original event is retained and a correction event is appended.

- If detection had an empty `started_at_after` and confirmation supplies it, the correction fills the start time while retaining the original `kind` and old/new IDs.
- If detection already had a start time and confirmation finds a different one, a further generation change is recorded from the detected new ID to the confirmed ID.
- The further change's `kind` follows its own old/new IDs: `restart` for the same ID and `recreate` for different IDs.

The committed generation attempts a fresh layout reading and records `generation_prepare_failed` if it fails. Evidence is not fabricated for intermediate generations that could not be observed.

#### Per-generation record files

A target with one generation uses `<name>__<run-key>.json`. Multiple generations use `<name>__<run-key>__gen1.json`, `__gen2.json`, and so on, numbered in observation order. `<name>` is the sanitized container name, falling back to its ID when empty. `<run-key>` includes case variant, permission, interval, window, phase, replicate, synchronization condition, and collection configuration. The manifest records each generation's container ID, name, and filename.

Samples and evidence from older generations are not merged into later generations. Initial package-database reading cost is retained per generation. Steady-state collector and Docker daemon load measure the collector's whole sampling loop and are copied into every generation, so those values must not be summed across generations.

### Unmeasured load and partial saves

`-load-unmeasured "<reason>"` skips cgroup readings for the collector and Docker daemon and saves their steady-state and daemon load as `measured=false` with the reason. Memory peaks are also unmeasured. This prevents a process without a dedicated cgroup from attributing an inherited shared cgroup's load to itself. Initial package-database reading measurements are retained separately.

When the sampling loop receives SIGTERM or SIGINT, it stops starting new samples and saves collected observations, load, per-generation files, and the manifest. This handles stop requests received during the sampling loop; it does not guarantee saving during preparation or after SIGKILL.

- Manifest `errors` records the received signal and completed/planned sample counts.
- Each target's final generation receives a `collector_stopped_early` failure.
- Every unattempted planned sample receives a collection result with `proc_observe=top_failed`, `pkgdb_read=error`, and `valid=false`.
- Older generations that already ended do not receive placeholders for samples missed after the signal.

These invalid collection results let `match` distinguish an interrupted record from a smaller window that completed normally. Remaining valid observations produce `observation_state=partially_observed`; no valid observations produce `observation_failed`. Collection containing unattempted samples is treated as `collection_complete=false`.

### prod-precheck.sh

```sh
sudo bash experiments/runtime-discovery/tools/prod-precheck.sh \
  /var/tmp/runtime-discovery-prod/precheck 512
```

The script takes a required `<out dir>` and optional `[64|256|512|none]`, defaulting to `512`. It writes `precheck.json`, `precheck.md`, and raw check data under `raw/`.

| precheck.json field | Contents |
| --- | --- |
| `generated_at`, `selected_pages` | Generation time and selected page count |
| `kernel`, `btf` | Kernel information and BTF presence/details |
| `tracepoints` | `present` and `required` for each tracepoint |
| `bpftrace_version`, `bpftool_version` | Tool versions or missing-installation records |
| `cgroup2`, `procfs_mount_options` | Cgroup v2 check and procfs mount options |
| `sysctls` | `kernel/unprivileged_bpf_disabled`, `kernel/perf_event_paranoid`, and `kernel/yama/ptrace_scope` |
| `lockdown`, `apparmor` | Lockdown, AppArmor enablement, the executing shell's profile, and related readings |
| `docker` | Server version, OS, cgroup driver, and cgroup version |
| `running_containers` | Running containers' `name`, `id`, `image_id`, and `started_at` |
| `free_bytes_on_output_filesystem` | Free output-filesystem bytes, or `null` when unavailable |
| `dry_run` | Dry-run results for the 64-, 256-, and 512-page scripts |
| `hard_failures`, `ok` | Hard-requirement failures and overall result |

Hard requirements include BTF, cgroup v2, a reachable native Docker Engine, enter/exit tracepoints for `open`, `openat`, and `openat2`, and `sched_process_exec`. The presence of `sys_enter_execve` is recorded but not required.

When bpftrace is available, all three scripts are checked, but only the selected script's dry-run affects the hard-requirement result. `none` removes the bpftrace and selected-script success requirements; it does not disable the other checks, including BTF and required tracepoints. bpftool, free space, sysctls, and AppArmor readings have no additional threshold-based failure rules. A nonempty `hard_failures` produces exit code 1; errors such as invalid arguments or execution user produce exit code 2.

The script does not operate on containers or change sysctls.

### prod-observe.sh runs

```sh
sudo KL_PROD_PAGES=512 bash experiments/runtime-discovery/tools/prod-observe.sh \
  /var/tmp/runtime-discovery-prod/run-001 300 api worker
```

Arguments are `<out dir> <window seconds> [container names...]`. Root and a reachable native Docker Engine are required. Omitted container names are resolved from the running-container list at startup; this does not continuously add newly appearing containers under other names.

| Environment variable | Default and purpose |
| --- | --- |
| `KL_RD_BIN`, `KL_RE_BIN` | `experiments/runtime-discovery/out/runtime-discovery` and `experiments/runtime-discovery/out/runtime-events` |
| `KL_PROD_PAGES` | `512`, selected from `64`, `256`, `512`, or `none` |
| `KL_PROD_INTERVAL`, `KL_PROD_MAX_SECONDS` | Sample-start interval `30` seconds and window ceiling `1800` seconds |
| `KL_PROD_ALLOW_UNMEASURED_LOAD` | `0`; setting `1` disables dedicated cgroups for both observation processes |
| `KL_TRIVY_CMD` | `trivy`; split on spaces into command arguments, with scan results captured from stdout |
| `KL_INTEL_SNAPSHOT` | Reuse the specified saved KEV/EPSS snapshot |
| `KL_PROD_CGROUP_REFRESH_SECONDS` | Periodic cgroup-table refresh interval, `60` seconds |
| `KL_PROD_RESTART_POLL_SECONDS` | Generation-event append polling interval, `5` seconds |
| `KL_WINDOW_LEAD_S`, `KL_WINDOW_START_TOLERANCE_S` | Window-start lead time `5` seconds and allowed start delay `2` seconds |
| `KL_STOP_TIMEOUT_S`, `KL_SUPERVISE_WAIT_S` | Per-signal-stage grace `15` seconds and supervisor wait `90` seconds |
| `KL_PREP_BUDGET_S`, `KL_WATCH_HARD_DEADLINE_GRACE_S` | Preparation budget `180` seconds and execution-deadline allowance `120` seconds |
| `KL_CGROUP_REMOVE_WAIT_S` | Wait for each cgroup removal, `30` seconds |
| `KL_PROD_LOG_BYTES` | Limit used to retain the tail of `run.log`, `52428800` bytes |
| `KL_ROOT` | Repository root for a relocated installation, defaulting to three directories above the script |

After applying the ceiling, the observation window must still be at least the sample-start interval. The runner decides the whole-run window after tracer attachment checking and initial cgroup registration, then passes the same start to the collector as `-phase-base`. `scheduled_start` and `scheduled_end` in `run_window.json` remain independent of generation splitting and are also used for event conversion.

With event collection enabled, the cgroup table is refreshed periodically and when polling detects additional lines in `restarts.jsonl`. Each generation is scanned by its own image ID, reusing scans for identical IDs. `match` covers HIGH/CRITICAL Findings without declaring ground truth.

#### Directory layout

| File or directory | Contents |
| --- | --- |
| `run.log`, `collect.log` | Runner and collector logs |
| `targets_initial.json` | Initial target names, container IDs, image IDs/references, and start times |
| `clock.json`, `cgroup-map.json` | Clock conversion information and cgroup table |
| `run_window.json` | Planned whole-run observation window |
| `timeline.jsonl`, `restarts.jsonl` | Processing milestones and generation events appended when detected |
| `collect/` | Per-generation observations, manifest, and registration state in `ready.json` |
| `collector_supervise.json`, `tracer_supervise.json` | Supervision records for observation processes that were started |
| `cgroup-<target>-wstart.json`, `cgroup-<target>-wend.json` | Window-start/end readings for dedicated `collector` and `tracer` cgroups |
| `cgroup-remove-<target>.json` | Removal records for `collector`, `tracer`, and `parent` |
| `watch_targets.txt`, `watch.jsonl`, `watch.log` | Monitoring targets, samples, and log |
| `stop_request.txt`, `termination_confirmed.txt` | Stop request and termination confirmation after its conditions are met |
| `trace.txt`, `trace.err`, `convert.log`, `events.jsonl` | Event trace, timestamped stderr, conversion log, and converted events |
| `scans/<image-key>.json`, `scans/<image-key>.err` | Trivy results and stderr keyed by image ID with `:` removed |
| `case/<base>.json` | Per-generation case definition for matching |
| `match/<base>.match_hc.json`, `match/<base>.log` | Per-generation match result and log |
| `csv_hc/<base>/` | Per-generation match CSV files |
| `intel.json` | Enrichment snapshot when a saved snapshot was not supplied |

Files are absent when their stage was not reached or their feature was disabled. `restarts.jsonl` is also absent when no generation event occurred. `prod_summary.md` and `prod_summary.csv` are created by running `prod_summary.py` separately.

#### timeline.jsonl fields

Each line is JSON with `ts`, `event`, and event-specific fields. Additional values written by the runner are normally strings; copied generation events and other records can use different types.

| `event` | Main additional fields |
| --- | --- |
| `run_start`, `window_clamped` | Requested/effective window, pages, interval, and ceiling |
| `target_snapshot` | `container`, `container_id`, `image_id`, `started_at` |
| `monitor_started` | `pid` |
| `attach_check` | `attached` and attachment-confirmation time in `at` |
| `collector_start` | Supervisor `pid` and collector startup time in `at` |
| `effective_observation_start` | `mode` and the `at` used for classification |
| `target_registration_result` | `attached` and `at` from `ready.json` |
| `run_window_decided`, `window_established` | Planned `start`/`end`, establishment `value`, and `drift_s` |
| `cgroup_refresh` | `reason` and `result` |
| `stop_reason`, `tracer_stop`, `run_actual_end` | Stop reason, `stopped_early`, exit time, supervision-record path, and related fields |
| `convert_done`, `scan_done`, `match_done` | Result and relevant file, image, container, or generation identity |
| `first_evidence_summary` | `container`, `record`, `first_layout_reading`, `first_language_package_evidence` |
| `generation_change` | Generation-event fields copied from `restarts.jsonl` |
| `run_end` | Observation-record count and failure/warning counts, or `population=empty` |

`first_evidence_summary` reports the earliest valid auxiliary-input reading and the earliest evidence timestamp among language-package confirmations. Missing values are `null`. Its `ts` is the generation's scheduled end. Generation events are copied after matching, so timeline line order is not necessarily chronological.

#### Stop conditions and termination confirmation

Monitoring starts before the tracer and samples every 10 seconds by default through `KL_WATCH_INTERVAL`.

| Condition | Setting and default |
| --- | --- |
| Tracer CPU exceeds the threshold for three consecutive samples | `KL_WATCH_CPU_CORES=1` |
| `Lost N events` notification count increases for three consecutive samples | Fixed streak of three |
| Run directory exceeds its size limit | `KL_WATCH_RUN_BYTES=1073741824` |
| Run parent directory exceeds its total size limit | `KL_WATCH_ROOT_BYTES=4294967296` |
| Output filesystem falls below minimum free space | `KL_WATCH_FREE_BYTES=21474836480` |

Observation also refuses to start when initial free space is below the minimum. There is no web measurement, so `KL_WATCH_WEB_FAILURES` does not apply. Tracer CPU and loss-notification conditions do not apply without a tracer, and the CPU condition cannot be evaluated without a dedicated cgroup.

Planned window completion, SIGINT/SIGTERM, monitor requests, and loss of the monitor while observation processes remain active use the common stop path. `supervise -deadline` independently enforces process deadlines: preparation budget plus lead time, window, and deadline allowance for the tracer, and the same sum without preparation for the collector.

The reason is saved in `stop_request.txt`, and the runner waits for the supervisor's SIGINT, SIGTERM, and SIGKILL sequence. If waiting for a supervisor times out, the runner sends TERM to that supervisor and waits again. It does not send SIGKILL to the supervisor itself.

| Mode | Termination confirmation |
| --- | --- |
| Dedicated cgroup | Require `status=exited`, `termination_confirmed.measured=true`, and `value=true` in the supervision record |
| `-no-cgroup` | Confirm only direct-child reaping through `status=exited`, retaining a reason that descendant absence was not measured |

The supervisor's own exit is not sufficient evidence that its child terminated. Separately from physical termination, the tracer is expected to exit cleanly after a stop request; spontaneous exit, signal termination, and non-zero exit are recorded as failures. A collector that normally finishes all scheduled samples before window end is not failed merely for that early completion.

After confirming every target's termination and successfully writing `termination_confirmed.txt`, the runner stops monitoring and removes dedicated cgroups whose final readings have been taken. If termination cannot be confirmed, monitoring and cgroups remain and the runner exits non-zero. Conversion and matching are skipped if termination confirmation or cleanup did not complete. The monitor has its own finite waiting bound, whose expiry is not treated as termination confirmation.

Failures in required steps, including collector or tracer execution, cgroup registration/refresh, event conversion, image scanning, and generation matching, produce a non-zero exit while retaining completed results. An initially empty target population with no observation records is recorded as empty and exits successfully.

### prod_summary.py classification and output

```sh
sudo python3 experiments/runtime-discovery/tools/prod_summary.py \
  /var/tmp/runtime-discovery-prod/run-001 \
  --container api
```

Arguments are `<run dir> [--before <RFC3339 ts>] [--after <RFC3339 ts>] [--container <name>]`. The script pairs `match/*.match_hc.json` with `collect/*.json` sharing the same base filename, then groups generations using container names and start times from the JSON content. Generations are ordered by start time, without inferring identity from filenames or `restarts.jsonl`.

#### Verdict series and effective observation start

Classification prefers the verdict including event evidence, falling back to the verdict including read-only additions and then the original rules only when the later verdict field is empty. `unobserved`, `unresolved`, and `not_determined` are nonempty verdicts and do not trigger fallback. Sub-reasons use the selected series' own factor.

The effective observation start is the `at` value of the first `effective_observation_start` event in the timeline.

- Runs with confirmed tracer attachment record that confirmation time with `mode=events`.
- Runs without confirmed attachment or without event collection record the collector supervision record's `started_at_wall` with `mode=procfs`.
- If the runner cannot obtain collector startup time, it records the planned window start as a substitute.
- If the summary finds no such event or timestamp, the start remains unknown rather than being inferred from another time.

| Priority | State | Condition |
| --- | --- | --- |
| 1 | Confirmed, `confirmed` | The selected series reports `confirmed` |
| 2 | Undeterminable (started before observation), `undeterminable_started_before_observation` | An unconfirmed `class=lang` package with known generation and effective observation starts, where the former is strictly earlier |
| 3 | No evidence, `no_evidence` | Everything else |

An unknown start does not establish that the generation started before observation. A confirmed language package remains confirmed even when its generation started earlier.

#### No-evidence sub-reasons

The first applicable reason in this order is used.

| Sub-reason | Condition |
| --- | --- |
| `permission_failure` | Factor is `proc_denied` or `rootfs_denied` |
| `no_observation` | Factor is `no_observation`, `top_failed`, `proc_gone`, or `event_no_observation`, or `observation_state=observation_failed` |
| `mapping_unsupported` | Factor is `no_file_list`, `lang_pkg_unmappable`, `db_absent`, `db_error`, `mapping_input_missing`, or `event_path_unresolved` |
| `mapping_unsupported` | `confirmation_gap_class=E2`, only when the original rules were selected |
| `drops` | An otherwise unexplained language package whose generation has `event_state=degraded` or `failed` and a positive designated loss counter |
| `drops_candidate` | The same language-package condition without a positive designated loss counter |
| `unclassified` | None of the above |

The designated `event_drops` fields are `lost_events`, `lost_notifications`, `map_overflow`, `path_read_failures`, `path_truncations`, `convert_failures`, `enter_exit_unmatched`, `identity_unavailable`, and `unmatched_identity_unavailable`. Unmatched boundary halves, before/after-filter counts, and free-text `event_notes` are not used as loss evidence. Event degradation alone remains `drops_candidate`, rather than measured loss. An established mapping shortfall takes precedence over loss.

#### Summary tables and CSV columns

`prod_summary.md` contains per-generation counts, no-evidence sub-reason counts, and a before/after comparison when multiple generations exist. Finding counts sum each package's `finding_count`, with the three states adding to the HIGH/CRITICAL Finding total. Package counts are separate and are not added to Finding counts.

| Output | Columns |
| --- | --- |
| Per-generation count table | Container, generation, image ID, start time, total HIGH/CRITICAL Findings, Finding counts for the three states, and package counts for the three states |
| Sub-reason table | Sub-reason and HIGH/CRITICAL Finding count |
| Before/after table | Container, class, package, versions before/after, common/added/removed membership, generations and states before/after, earliest later-generation evidence time/type, and remaining reason |
| `prod_summary.csv` identity columns | `container`, `generation`, `image_id`, `container_started_at`, `package`, `version`, `class` |
| `prod_summary.csv` verdict columns | `finding_count`, the verdicts from the original rules, including read-only additions, and including event evidence, plus `verdict_tier_used` |
| `prod_summary.csv` state columns | `event_state`, `observation_state`, `state`, `subreason` |

CSV has one row per package carrying Findings and preserves the original verdicts separately from classification. The before/after table is written to Markdown; CSV retains per-generation rows.

The comparison defaults to the first and last generations. `--before` and `--after` each select the latest generation that had started by the specified timestamp, retaining the default selection if no candidate exists. No comparison rows are produced when both selections identify the same generation or only one generation exists.

The comparison key is class, name, and installed version. A key present on both sides is `common`, only afterward is `added`, and only beforehand is `removed`. Membership refers to the population carrying HIGH/CRITICAL Findings, so losing those Findings can count as removal from the comparison. An absent side is displayed as `not_present`. The earliest evidence is selected from confirmations for that exact key in the later generation, displaying its `observed_at` and `source`.
