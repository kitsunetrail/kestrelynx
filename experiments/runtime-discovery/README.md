# Runtime discovery experiment

**English** | [日本語](README.ja.md)

## Purpose

This is a stand-alone measurement harness for testing whether runtime evidence from procfs and the Docker Engine API can be tied to Trivy findings with explainable accuracy.

- It is an experiment, not a product feature.
- It is separate from the `kestrelynx` binary and is not built into the container image.
- See the [public development log](../../docs/development/runtime-prioritization.md) for the motivation and investigation status.

## Overview

- `collect` saves runtime observations.
- `match` compares those observations with an image scan, expected usage and verdicts, and optional independent ground truth.
- Run the commands below from the repository root.
- Save generated files under `./out/`, which is git-ignored.
- Do not commit observations, logs, scans, or results.

## Requirements

Measurements require the following host environment, tools, and permissions.

- A Linux host with a native Docker Engine and access to its UNIX socket.
  - Docker Desktop through a separate VM does not expose the required host PIDs.
- Go 1.26; the repository currently specifies Go 1.26.4.
- Trivy for image scans, Bash and curl for the case helper, and jq for the examples.
  - The helper reads usage logs with python3 when present and falls back to a whitespace-tolerant regular expression otherwise.
- Root access for standard collection and host-procfs helper checks.
  - The non-root condition with equivalent read access uses `CAP_SYS_PTRACE` plus `CAP_DAC_READ_SEARCH`.
- Available ports for each case.
- Network access for image builds, Trivy data, R9's curl requests, and KEV/EPSS retrieval without a saved snapshot.

## Inputs and outputs

`collect` reads host and container information and saves observations.

- From procfs, it reads `/proc/<pid>/exe`, `maps`, `fd`, `status`, `net/tcp`, and `net/tcp6`.
- It also reads process identity, namespace, and cgroup metadata.
- It reads the container root filesystem through `/proc/<pid>/root`.
- Package metadata includes dpkg, distroless `status.d`, and apk.
- It only issues GET requests to the Docker API: container enumeration, inspection, and `top`.
- The Docker socket itself can permit container control even though `collect` only uses GET.
- The case helper separately builds, starts, inspects, and removes containers.
- Fixture and preflight checks read the host's `/proc/<pid>/...` through Docker-reported PIDs.
  - They work on distroless because they do not use `docker exec`.
- R4 readiness separately uses `docker exec` to run `pg_isready`.

## Build and run

Prepare a dedicated measurement host and use the same Docker endpoint for builds and measurements.

- Stop competing workloads.
- Check for leftover networking from other runtimes.
- Ensure Docker is running and use the same native endpoint for the CLI, image scans, and collector.

```sh
mkdir -p ./out
unset DOCKER_CONTEXT
export DOCKER_HOST=unix:///var/run/docker.sock
docker context show
docker info --format '{{.ServerVersion}} {{.Driver}} {{.DockerRootDir}} {{.CgroupVersion}}'
uname -r
cat /proc/sys/kernel/yama/ptrace_scope
findmnt -no OPTIONS /proc
```

- Record these outputs and any errors.
- Verify published HTTP ports with curl.
- Absence of a host listening socket alone does not mean Docker NAT publication failed.
- For isolated load measurements, run the built collector in its own cgroup v2.
- It records initial package database read cost, its own cgroup usage, and Docker daemon cgroup usage.
- Unavailable measurements are recorded as failures.
- Build the executable when you need a stable binary for privilege comparisons.

```sh
go build -o ./out/runtime-discovery ./experiments/runtime-discovery
go run ./experiments/runtime-discovery collect -h
go run ./experiments/runtime-discovery match -h
```

## Cases

There are 12 cases, numbered 1 to 12, covering 13 variants including two variants of case 7. In commands and file names the number is prefixed with `r` (for example, 1 is `r1` and 7a is `r7a`).

- The case definitions in `cases/*.json` separate `expected_usage` (GT-A: `used` or `not_used`) from `expected_verdict`.
- `expected_factor` is optional.
- R5 declares cryptography used but expects `unobserved` because its language-package finding cannot be matched by the current path logic.
- Case-level `gap_class_hint` and `gap_class_rationale` describe declared gaps.
- `gt_b_scope`, where present, declares the package scope for independent truth.

| No. | Image | What it exercises |
| --- | --- | --- |
| 1 | `nginx:1.27` | Debian package ownership, master/workers, all-interface port publication. |
| 2 | `redis:7-alpine` | apk ownership, non-root service, loopback publication. |
| 3 | `nginx:1.27` | Host networking and listener attribution. |
| 4 | `postgres:16` | Multiple PostgreSQL processes without published ports. |
| 5 | `kl-r5`, from `python:3.12-slim` | Loaded cryptography extension and language-package matching gaps. |
| 6 | `kl-r6`, from `gcr.io/distroless/cc-debian12` | Dynamic C server and `status.d` ownership metadata. |
| 7 | `kl-r7a` on `debian:12-slim`; `kl-r7b` on `gcr.io/distroless/static-debian12` | Same static Go server across different package metadata availability. |
| 8 | `kl-r8`, from `debian:12-slim` | Deleted executable, deleted library, and atomic replacement of a loaded library. |
| 9 | `kl-r9`, from `debian:12-slim` | Short-lived curl/git invocations with a five-second sleep between iterations. |
| 10 | `kl-r10`, from `debian:12-slim` | SQLite library loaded for seven seconds, then unloaded for seven seconds. |
| 11 | `nginxinc/nginx-unprivileged:1.27-alpine` | Non-root nginx and effective privileges. |
| 12 | `nginx:1.27` | Added `NET_ADMIN`, dropped `NET_RAW`, and effective capability checks. |

- Use `sudo bash experiments/runtime-discovery/cases/run.sh up r9` to build and start R9, and `down r9` to remove it.
- The helper builds R5–R10, including both R7 variants; other cases use upstream images.
- It also accepts `up-all` and `down-all`.
- Startup waits for HTTP 200, Redis readiness logs, or `pg_isready`, depending on the case.
- R5/R6 additionally wait for an `open` event, R8 for three `stage` events, and R9 for an `exit`.
- R10 waits for a `dlclose` whose own maps read confirmed the unload.
- The helper parses those logs as JSON, so either spacing of the same record is read the same way.
- Run `fixture-check <case>` separately.
- For R8 and R10, also run `preflight-r8` or `preflight-r10` before sampling to check deleted mappings or disappearance after unloading.
- `preflight-r10` polls for an unloaded phase rather than assuming one at a fixed time.
- Every readiness, fixture, and preflight check exits non-zero on failure.
- Stop the run if a check fails.

## Measurement procedure

Follow this order for each run.

1. Prepare the host.
2. Start the case.
3. Check readiness and fixture validity.
4. Scan the exact running image ID rather than resolving its tag again.
5. Collect observations.
6. Collect ground truth.
7. Match the observations, scan, case definition, and ground truth.
8. Tear down the case.

- Use the following commands to start R9 and collect observations.

```sh
run_dir=./out/R9-root-30-300-offset0-rep1
mkdir -p "$run_dir"
sudo bash experiments/runtime-discovery/cases/run.sh up r9
sudo bash experiments/runtime-discovery/cases/run.sh fixture-check r9
cp experiments/runtime-discovery/cases/r9.json "$run_dir/case.json"
image_id=$(docker inspect --format '{{.Image}}' r9)
trivy image --format json --output "$run_dir/trivy.json" "$image_id"

sudo systemd-run --scope --unit=runtime-discovery-collect \
  -p CPUAccounting=yes -p MemoryAccounting=yes \
  "$(pwd)/out/runtime-discovery" collect \
  -socket /var/run/docker.sock -containers r9 \
  -case-variant R9 -permission root \
  -interval 30 -window 300 -phase 0 -replicate 1 \
  -out-dir "$run_dir/collect"
```

- The scope gives the collector its own cgroup.
- `-cgroup-path` overrides the directory derived from `/proc/self/cgroup`.
  - An example is `/sys/fs/cgroup/system.slice/runtime-discovery-collect.scope`.
- Without systemd, create and enter a dedicated cgroup v2 manually and pass its directory.
- `-docker-cgroup-path` selects the daemon cgroup; its default is `/sys/fs/cgroup/system.slice/docker.service`.
  - Measuring that cgroup includes the `ps` processes started by `docker top`.
- `memory.peak` is the collector cgroup's lifetime peak, not a peak restricted to the sampling window.
- The six run-key flags are `-case-variant` (case variant), `-permission` (permission label), `-interval` (interval in seconds), `-window` (window in seconds), `-phase` (sampling phase offset in seconds), and `-replicate` (replicate).
- `-phase` is measured from `-phase-base`, an RFC3339 instant.
- Without `-phase-base`, the reference is collect's start time; both the reference and its source are recorded.
- The standard condition is root, a 300-second window, a 30-second interval, zero phase offset, and replicate 1, scheduling ten samples.
- `-permission` records a label; it does not grant privileges.
  - Use `root`, `ptrace` (non-root with `CAP_SYS_PTRACE`), `ptrace_dac` (also `CAP_DAC_READ_SEARCH`), or `none` (non-root without capabilities).
- Apply capabilities to the built executable, not `go run`.
- Socket access, directory permissions, and host security controls also affect success.
- Omitting `-containers` selects all running containers.
- `-ps-args` defaults to `-eo pid,ppid,user`; preserve that column order if you override it.
- Use separate output directories for each run.
- Compare permission conditions on R1/R2/R6 and sampling conditions on R9/R10 separately from standard results.
- For sampling comparisons, use intervals of 10/30/60 seconds with either a fixed 300-second window or ten samples, and phase offsets of 0/3/7 seconds.
- Set `-phase-base` to the workload cycle's reference time when comparing offsets relative to that cycle.

## Preparing ground truth (GT-B)

Create GT-B by combining usage logs or resident-process checks with independently verified package information.

- The collector returns after its last sample, potentially before the scheduled window ends.
- Keep the workload running through that end before copying GT-B.
- For the standard condition above, waiting another 30 seconds is sufficient.

```sh
sleep 30
docker cp r9:/var/log/usage.jsonl "$run_dir/usage.jsonl"
jq -sr '[.[] | .path? | select(. != null and . != "")] | unique[]' \
  "$run_dir/usage.jsonl" > "$run_dir/usage-paths.txt"
docker exec r9 dpkg-query -S /usr/bin/curl /usr/bin/git
```

- On a merged-`/usr` image, query `dpkg-query -S` with the form the `.list` files record (`/lib/x86_64-linux-gnu/...`) or grep the `.list` files directly.
- Asking for the `/usr/lib/...` form of a path a package recorded as `/lib/...` returns "no path found".
- R5, R6, R8, R9, and R10 emit `/var/log/usage.jsonl`.
- Among the self-built variants, only R7a/R7b do not emit usage logs.
- R5/R6 record startup and periodic maps snapshots.
- R9 records libraries identified by the dynamic loader alongside process execution.
- The common event format is one JSON object per line.

```json
{"ts":"2026-09-11T00:00:00Z","pid":42,"starttime":12345,"event":"exec","path":"/usr/bin/git","ok":true}
```

- `ts` is RFC3339 with optional fractional seconds.
- `pid` and process start ticks identify a process generation.
- Usage events are `exec`, `open`, `dlopen`, `dlclose`, and `exit`.
- An `exit` carries `"ok":true` to record that exit was observed, with the command's exit code in a separate `status` field.
- R8 also writes `meta` and `stage` lines; R10 adds `maps_unloaded` to `dlclose`.
- Preserve these fields.
- Keep events from before the window when they start an interval overlapping it.
- `match -gtb` accepts a JSON object, not raw JSONL.

1. Independently verify ownership for every path in `usage-paths.txt`, including libraries, using the running image's package metadata.
   - Account for symlink aliases when querying ownership.
2. Save the verified mappings as a JSON array in `$run_dir/path-packages.json`, with entries such as `{"path":"/usr/bin/curl","package":"curl"}`.
3. Wrap the log with the following command.

```sh
jq -s --slurpfile mappings "$run_dir/path-packages.json" '{
  case_id: "R9", kind: "usage_log", usage_log: .,
  path_packages: $mappings[0]
}' "$run_dir/usage.jsonl" > "$run_dir/gtb.json"
```

- `path_packages` must cover every usage-event path in the log, including library paths outside `gt_b_scope`.
- An unmapped path means no package's non-use can be certified: all packages without positive evidence become undetermined.
- Independently established positive use remains valid.
- Only packages in `gt_b_scope` receive GT-B labels.
- Collect fresh logs for every run.
- Ensure logging covers that scope before interpreting missing events as non-use.
- GT-A expectations and collector output are not independent ground truth.
- For official images, collect a limited resident-process check after the window.
  - Save `docker top`, inspect resident executables/libraries, and independently verify package ownership and versions.
- Encode positive observations as `{"case_id":"R1","kind":"limited","resident_packages":[{"package":"nginx","used":true}]}`.
- Declare the justified scope in your saved case definition before measurement.
- The supplied official-image definitions omit the scope; without scope, coverage stays zero.
- Limited checks cannot establish non-use; `used:false` is ignored.
- Once ground truth is ready, run the following commands to match and tear down.

```sh
go run ./experiments/runtime-discovery match \
  -observation "$run_dir/collect/r9__R9_root_i30_w300_p0_r1.json" \
  -trivy "$run_dir/trivy.json" -case "$run_dir/case.json" \
  -gtb "$run_dir/gtb.json" -intel-cache ./out/intel-cache \
  -out-intel-snapshot "$run_dir/intel.json" \
  -act-now-epss 0.10 -watch-epss 0.01 \
  -out-json "$run_dir/match.json" -out-csv-dir "$run_dir/csv"
sudo bash experiments/runtime-discovery/cases/run.sh down r9
```

- Omit `-gtb` when independent truth is unavailable; FP/FN remain undetermined.
- `match` needs no live container or root filesystem.
- Without `-intel-snapshot`, it looks up KEV/EPSS through the intelligence cache and may fetch updated feeds.
- `-out-intel-snapshot` saves the intelligence used by the run.
- To reproduce its classification, pass that file with `-intel-snapshot "$run_dir/intel.json"`, keeping the other inputs and thresholds fixed.
- You can also extract the `intel` object from an earlier match result.
- Snapshot runs perform no KEV/EPSS lookup.
- Only snapshot runs pin intelligence sufficiently for reproducible classification.

## Reading the outputs

Inspect collection results in the observation JSON and `manifest.json`, and match results in the JSON and eight CSV files.

- Each collection directory contains one observation JSON per container.
- `manifest.json` lists container files and collection-level errors.
- Observation filenames include the container name and run key, such as `r9__R9_root_i30_w300_p0_r1.json`.
- Observations include identities, timing, host architecture, process evidence, ownership, listeners, privileges, load measurements, and failures.
- Inspect observations even after a successful exit.
- Match JSON includes image identity verification, usage verdicts, evidence, confirmation rates, exposure, ranking comparisons, and GT-B accuracy metrics.

| CSV | Contents |
| --- | --- |
| `case_summary.csv` | Finding/package confirmation and rates, FPR/FNR and GT coverage, `guess_dependency_rate`, `guess_dependency_lower`, `guess_dependency_upper`, `intel_condition`, `intel_source`, image identity verification, and exposure verdict. |
| `classification.csv` | Finding counts and confirmation rates overall, by priority and package class, and for the degraded intelligence condition. |
| `factors.csv` | Verdict/factor breakdown with package counts and total, act-now, watch, and low finding counts. |
| `gap_classes.csv` | E1–E4/unclassified confirmation gaps, recoverability, package/finding counts, and act-now/watch finding counts. |
| `path_resolution.csv` | `ownership`, `trivy_match`, and distinct `paths` tallies. |
| `permissions.csv` | `operation`, `result`, `occurrences`, and `message`, plus the run's `target_finding`, `confirmed`, `unconditional_rate`, `conditional_rate`, and `state_observation_failed`. Includes a row when no operation failed. |
| `gt_b.csv` | Population, undetermined count, coverage, TP/FP/TN/FN, FPR/FNR, and upper/lower bounds. |
| `g4.csv` | Priority, N/A status, total findings, top-20 rank changes, labeled count, `exposure_stages_in_top20`, and labeled/unlabeled examples. |

- Every CSV includes `case_id` and the six run-key columns: `case_variant`, `permission`, `interval`, `window`, `phase`, and `replicate`.
- Files are overwritten on rerun.
- Aggregation is external.

## Checking without Docker

You can exercise `match` without Docker, root, or a Trivy installation using the hand-written inputs in `testdata/`.

- Run the following command to match the synthetic data.

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

- Inspect the match JSON and eight CSV files.
- `testdata/` contains no intelligence snapshot, so this first run can require network access.
- Inspect the reported intelligence condition and errors.
- For subsequent reproducible runs, add `-intel-snapshot ./out/dry-run/intel.json`.
- The synthetic limited GT-B confirms positive use only.

## Limitations

The following limitations apply to support and interpretation of observations.

- There is no daemon mode, Kubernetes/containerd support, or eBPF collection.
- Address decoding uses the host's native byte order, and observations record the host architecture.
- R10's workload still hard-codes the amd64 library path `/usr/lib/x86_64-linux-gnu/libsqlite3.so.0`.
- Parsers have hand-written fixtures; real-host measurements remain necessary.
- Sampling can miss short-lived activity.
- Mapped language extensions need not match Trivy package paths.
- Missing evidence does not establish safety or lower priority.
- A listener does not prove internet reachability.
