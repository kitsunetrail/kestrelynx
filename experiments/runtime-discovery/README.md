# Runtime discovery experiment

**English** | [日本語](README.ja.md)

- This experimental harness identifies packages used by running containers from procfs and eBPF evidence.
- It links that evidence to Trivy findings.
- It is separate from the product binary and is not included in the container image.
- The public logs cover [runtime prioritization](../../docs/development/runtime-prioritization.md) and [event evidence](../../docs/development/runtime-event-evidence.md).

## What it does

- Samples processes, mapped files, listeners, and effective privileges at regular intervals.
- Collects execution and file-open events through the sibling [runtime-events tool](../runtime-events/README.md).
- Compares observations with independent ground truth to report confirmations, occurrence capture, and container attribution.

## Requirements

- Linux with BTF and the execution and file-open tracepoints used by runtime-events.
- Live measurements used bpftrace v0.25.0; the minimum working version remains undetermined.
- Native Docker Engine with cgroup v2 and access to its UNIX socket and host procfs.
- Docker Desktop WSL integration is unsupported because it takes over the socket; the tools stop at startup when connected to Docker Desktop.
- Root access through sudo.
- Trivy, Go 1.26 with repository version 1.26.4, Bash, curl, jq, and python3.
- Available case ports and network access for builds, scan data, workload requests, and intelligence retrieval.

## Try it

Run these commands from the repository root.

### Preparation

Create the output directory for measurement results and binaries.

```sh
mkdir -p experiments/runtime-discovery/out
```

Build the `runtime-discovery` binary used for sampling and matching.

```sh
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
```

Build the `runtime-events` binary used for event collection support and trace conversion.

```sh
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
```

Run `check-tracing.sh` with sudo to verify tracing script loading and collection and conversion of known events.

```sh
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
```

Check results are saved as `smoke.log` and `events.jsonl` under `experiments/runtime-discovery/out/check-tracing/`.

### Single-case measurement

Use `case-run.sh` to measure one case, running collection, ground truth preparation, and matching.

```sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512 30 300
```

The arguments are as follows.

- The first argument, `13`, is `<case>`, a required case number selected from `13` through `22` or `26` through `28`.
- The second argument, `1`, is `<replicate>`, a number that distinguishes repetitions under the same conditions, appears as `r<replicate>` in the run directory name, and defaults to `1`.
- The third argument, `startup`, is `<sync>`, the start condition, which can be `startup` to begin observation before the measured work or `attach_running` to join work already running, and defaults to `startup`.
- The fourth argument, `512`, is `<pages>`, the number of event buffer pages selected from `64`, `256`, or `512`, or `none` to disable event collection, and defaults to `64`.
- The fifth argument, `30`, is `<interval>`, the sampling interval in positive integer seconds, and defaults to `30`.
- The sixth argument, `300`, is `<window>`, the observation window in positive integer seconds, and defaults to `300`.

The run directory is `experiments/runtime-discovery/out/<case>-root-<interval>-<window>-p0-r<replicate>-<sync>-<tag>/`. The `<tag>` values are `nofilter64p`, `nofilter256p`, `nofilter512p`, and `noevents` for `<pages>` values of `64`, `256`, `512`, and `none`, respectively.

In the run directory, first read `record.md`, `match_hc.json`, and `csv_hc/series.csv`. Then check `csv_hc/occurrence_capture.csv`, `csv_hc/attribution.csv`, and `csv_hc/event_drops.csv`. Keep generated data out of commits.

### Multi-case measurement

Use `case-batch.sh` to measure several cases, running the conditions listed in a plan file in order.

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/example.txt
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/tools/plans/example.txt`, is `<plan file>`, the path to a plan file listing the cases and measurement conditions to run.

Each measurement's results are saved in a separate run directory, and the batch log is saved as `experiments/runtime-discovery/out/case-batch-<UTC timestamp>.log`.

### Plan file

Each line in a plan file represents one measurement, with fields ordered as `<case> <replicate> <sync> <pages> [interval] [window]`. Each field is passed directly to `case-run.sh` as an argument. Lines beginning with `#` and blank lines are ignored, and omitting the last two fields sets `<interval>` to `30` and `<window>` to `300`.

Rows whose `<case>` is `23`, `24`, `23+24`, or `23+host` are routed to `attribution-control-run.sh`. For these rows, `<case>`, `<replicate>`, and `<pages>` are passed, and the `<sync>` field is ignored. The `<interval>` and `<window>` fields are also not passed, and measurement uses a 30-second interval and a 300-second window.

The contents of `plans/example.txt` are these three lines.

```text
13 1 startup 256
14 1 startup 256
15 1 startup 256
```

The fields are as follows.

- The first field, `13`, `14`, or `15`, is `<case>`, the case number to measure on each line.
- The second field, `1`, is `<replicate>`, a number that distinguishes repetitions of each case under the same conditions.
- The third field, `startup`, is `<sync>`, the start condition that begins observation before the measured work.
- The fourth field, `256`, is `<pages>`, which sets the number of event buffer pages to 256.
- The omitted fifth field is `<interval>`, which uses the default 30-second sampling interval.
- The omitted sixth field is `<window>`, which uses the default 300-second observation window.

The following plan files for cases 26 through 28 are included in `experiments/runtime-discovery/tools/plans/`. All use 512 event buffer pages.

- `coverage-main.txt` measures all three cases at a 30-second interval with a 900-second window, repeating each of the `startup` and `attach_running` start conditions twice, for 12 runs.
- `coverage-rest.txt` measures the remaining combinations of a 10-second interval with a 900-second window, a 30-second interval with a 300-second window, and a 10-second interval with a 300-second window once for each of the three cases and both start conditions, for 18 runs.
- `coverage-symlink-check.txt` measures all three cases once with `startup`, a 30-second interval, and a 300-second window, for three runs with `<replicate>` set to `4`.

### Attribution check

Use `attribution-control-run.sh` to check event attribution for cases 23 and 24 with separate runs, concurrent runs, and a host control.

```sh
sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh 23+24 1 512
```

The arguments are as follows.

- The first argument, `23+24`, is `<condition>`, where `23` runs case 23 alone, `24` runs case 24 alone, `23+24` runs both at once, and `23+host` runs case 23 while the host runs the same program.
- The second argument, `1`, is `<replicate>`, a number that distinguishes repetitions under the same conditions, appears as `r<replicate>` in the run directory name, and defaults to `1`.
- The third argument, `512`, is `<pages>`, the number of event buffer pages selected from `256` or `512`, and defaults to `256`.

This example saves its results in `experiments/runtime-discovery/out/23+24-root-30-300-p0-r1-startup-nofilter512p/`. Per-container matching results are saved as `match_hc-case23.json` and `match_hc-case24.json`, with CSV files under `csv_hc-case23/` and `csv_hc-case24/`. Attribution for other cases is included in the results from `case-run.sh`.

### Reprocessing and aggregation

Use `case-post.sh` to repeat ground truth preparation and matching from saved measurement results.

```sh
bash experiments/runtime-discovery/tools/case-post.sh "<run dir>"
```

The arguments are as follows.

- The first argument, `"<run dir>"`, is a placeholder for the run directory to reprocess, with multiple directories accepted when separated by spaces, and omitting it selects all runs for cases 13 through 24 under `experiments/runtime-discovery/out/` that have collection records.

To restart from trace conversion, place the environment variable assignment `RECONVERT=1` before `bash` in the command.

By default, threat intelligence is retrieved using `experiments/runtime-discovery/out/intel-cache`, and the intelligence used is written to each run's `intel.json`. Set the environment variable `KL_INTEL_SNAPSHOT` to the path of saved JSON to reproduce classification with the same inputs and thresholds. Each run's `intel.json` contains only the intelligence for that run's CVEs, so do not use it to reprocess other runs.

Use `aggregate.py` to aggregate event evidence results for cases 13 through 24.

```sh
python3 experiments/runtime-discovery/tools/aggregate.py
```

The summary table is written to `experiments/runtime-discovery/out/AGGREGATE-events.md`.

Use `record.py` to regenerate the record for an individual run.

```sh
python3 experiments/runtime-discovery/tools/record.py "<run dir>"
```

The arguments are as follows.

- The first argument, `"<run dir>"`, is a required placeholder for the run directory whose record you want to generate.

The record is saved as `<run dir>/record.md` and also printed to standard output.

### Ground truth and coverage scoring for cases 26 through 28

#### Collecting ground truth logs

Use `truth-run.sh` to run the same image as the measurement under strace and collect independent logs for ground truth. This command does not require sudo.

```sh
bash experiments/runtime-discovery/tools/truth-run.sh 26 1 900
```

The arguments are as follows.

- The first argument, `26`, is `<case>`, a required case number selected from `26`, `27`, or `28` for ground truth preparation.
- The second argument, `1`, is `<replicate>`, a number that distinguishes truth run repetitions, appears as `r<replicate>` in the run directory name, and defaults to `1`.
- The third argument, `900`, is `<window>`, the truth run's observation window in seconds, and defaults to `900`.

The output directory is `experiments/runtime-discovery/out/<case>-truth-r<replicate>/`. Because strace affects timing and scheduling, use this run only to collect ground truth and do not reuse it as a measurement. For cases 27 and 28, replace the first argument with `27` and `28`, respectively.

#### Running measurements

Run the measurement for coverage scoring separately with `case-run.sh`. This example measures case 26 at a 30-second interval with a 900-second window.

```sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 26 1 startup 512 30 900
```

The arguments are as follows.

- The first argument, `26`, is `<case>`, the case number to measure.
- The second argument, `1`, is `<replicate>`, a number that distinguishes repetitions under the same conditions.
- The third argument, `startup`, is `<sync>`, the start condition that begins observation before the measured work.
- The fourth argument, `512`, is `<pages>`, which sets the number of event buffer pages to 512.
- The fifth argument, `30`, is `<interval>`, which sets the sampling interval to 30 seconds.
- The sixth argument, `900`, is `<window>`, which sets the observation window to 900 seconds.

This example saves its results in `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p/`.

Pass `coverage-main.txt` to `case-batch.sh` to measure the main conditions for cases 26 through 28 together.

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-main.txt
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/tools/plans/coverage-main.txt`, is `<plan file>`, a plan file containing 12 runs that measure all three cases at a 30-second interval with a 900-second window twice under each start condition.

Pass `coverage-rest.txt` to `case-batch.sh` to measure the remaining combinations of sampling interval and observation window.

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-rest.txt
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/tools/plans/coverage-rest.txt`, is `<plan file>`, a plan file containing 18 runs that measure the remaining combinations once under each start condition for all three cases.

For short measurements that check symlink resolution and the application's own packages, replace the first argument with `experiments/runtime-discovery/tools/plans/coverage-symlink-check.txt`.

#### Building ground truth

Use `truth.py` to build `truth.json` from the image's package inventory and independent logs.

```sh
python3 experiments/runtime-discovery/tools/truth.py \
  experiments/runtime-discovery/out/26-truth-r1 \
  experiments/runtime-discovery/cases/26.json \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/out/26-truth-r1`, is `<truth run dir>`, the truth run directory created by `truth-run.sh`.
- The second argument, `experiments/runtime-discovery/cases/26.json`, is `<case json>`, the case definition JSON file corresponding to the truth run.
- The third argument, `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p`, is the optional `<measurement run dir>`, which also enables a check that the truth run and measurement run performed equivalent operations.

The `truth.json` file is written to the truth run directory. Set the environment variable `KL_TRUTH_TMPDIR` to change where the rootfs is extracted. See [REFERENCE.md](REFERENCE.md) for details.

#### Scoring coverage

Use `coverage.py` to match measurement results against ground truth for the same case and score coverage of package use.

```sh
python3 experiments/runtime-discovery/tools/coverage.py \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p \
  experiments/runtime-discovery/out/26-truth-r1/truth.json
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p`, is `<run dir>`, the measurement run directory to score.
- The second argument, `experiments/runtime-discovery/out/26-truth-r1/truth.json`, is `<truth.json>`, the path to ground truth generated from a truth run for the same case.

Scoring results are written to `coverage.json` and `coverage.md` in the measurement run directory. For cases 27 and 28 and other measurement conditions, replace the case definition, truth run, and measurement run paths passed to `truth.py` and `coverage.py` with the corresponding paths.

#### Aggregation and ranking comparison

Use `coverage_aggregate.py` to aggregate coverage scores across measurements.

```sh
python3 experiments/runtime-discovery/tools/coverage_aggregate.py experiments/runtime-discovery/out
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/out`, is `<out dir>`, both the parent directory searched for measurement runs and the output directory for aggregated results, and defaults to `experiments/runtime-discovery/out`.

Aggregated results are written to `<out dir>/AGGREGATE-coverage.md` and `<out dir>/AGGREGATE-coverage.csv`.

Use `coverage_rank.py` after coverage scoring to compare priority ranking changes across runs.

```sh
python3 experiments/runtime-discovery/tools/coverage_rank.py experiments/runtime-discovery/out
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/out`, is `<out dir>`, both the parent directory searched for measurement runs and the output directory for ranking comparisons, and defaults to `experiments/runtime-discovery/out`.

Ranking comparisons are written to `<out dir>/AGGREGATE-rank.md` and `<out dir>/AGGREGATE-rank.csv`.

### Load and privilege measurement for cases 26 through 28

#### Measuring load

Use `load-run.sh` to record collector and tracer load, operational command durations, and web response times while joining an already-running workload with `attach_running`.

```sh
sudo bash experiments/runtime-discovery/tools/load-run.sh 26 1 procfs 30 300
```

The arguments are as follows.

- The first argument, `26`, is `<case>`, a required case number selected from `26`, `27`, or `28`.
- The second argument, `1`, is `<replicate>`, a number that distinguishes repetitions under the same conditions, appears as `r<replicate>` in the run directory name, and defaults to `1`.
- The third argument, `procfs`, is `<config>`, selected from `none` for no observation, `procfs` for the collector alone, or `events` for the collector and a tracer with 512 event buffer pages, and defaults to `procfs`.
- The fourth argument, `30`, is `<interval>`, the interval between sample starts in positive integer seconds, and defaults to `30`.
- The fifth argument, `300`, is `<window>`, the observation window in positive integer seconds, and defaults to `300`.

The run directory is `experiments/runtime-discovery/out/<case>-load-<config>-<interval>-<window>-r<replicate>-attach_running/`. Raw measurements and logs are assembled into `load.json`, which the `load.py` command below aggregates into `AGGREGATE-load.md` and `AGGREGATE-load.csv`. Replace the third argument with `events` to include event collection.

Run the control with `none` and the same case, replicate number, interval, and observation window to compare the effect of observation.

```sh
sudo bash experiments/runtime-discovery/tools/load-run.sh 26 1 none 30 300
```

The arguments are as follows.

- The first argument, `26`, is `<case>`, the same case number as the measurement being compared.
- The second argument, `1`, is `<replicate>`, the same replicate number as the measurement being compared.
- The third argument, `none`, is `<config>`, which runs the workload and host-side web requests without starting a collector or tracer.
- The fourth argument, `30`, is `<interval>`, unused for sampling in this configuration but used to pair the control with the measurement.
- The fifth argument, `300`, is `<window>`, the same observation-window duration in seconds as the measurement being compared.

This example saves its results in `experiments/runtime-discovery/out/26-load-none-30-300-r1-attach_running/`. The control generates no observation record and saves operational command timing, web timing, Docker daemon CPU usage, and other measurements in `load.json`. Rerunning the same conditions recreates the run directory, so change `<replicate>` to retain repetitions.

`load-run.sh` starts `watch-run.sh` before starting the tracer and collector. Monitoring runs every 10 seconds by default and saves each sample in `watch.jsonl`. It requests a stop under the following conditions.

- Tracer CPU usage exceeds one core-equivalent for three consecutive samples.
- The count of `Lost N events` notifications increases for three consecutive samples.
- The run directory exceeds 1 GiB.
- The shared output directory exceeds 4 GiB.
- Free space on the output filesystem falls below 20 GiB.
- Three consecutive web responses fail in recorded order.

The environment variables `KL_WATCH_INTERVAL`, `KL_WATCH_CPU_CORES`, `KL_WATCH_RUN_BYTES`, `KL_WATCH_ROOT_BYTES`, `KL_WATCH_FREE_BYTES`, and `KL_WATCH_WEB_FAILURES` override the sampling interval, CPU threshold, per-run size limit, shared output size limit, minimum free space, and consecutive web failure threshold, respectively. Size values are in bytes. `KL_WATCH_HARD_DEADLINE_GRACE_S` sets the allowance added to supervised process deadlines and defaults to `120` seconds.

Stop requests are recorded in `stop_request.txt`, and the runner and `supervise` perform the stop sequence. Monitoring continues after a stop request and distinguishes confirmed termination from its own monitoring bound. An early stop after the observation window opens still preserves available measurements and reasons in `load.json`. See [REFERENCE.md](REFERENCE.md#load-and-privilege-measurement) for details.

#### Checking privilege conditions

Use `privilege-run.sh` to check the operations needed for event collection under each privilege condition. For non-root conditions, set `KL_PRIV_USER` to an existing unprivileged user.

```sh
sudo KL_PRIV_USER=kltest bash experiments/runtime-discovery/tools/privilege-run.sh bpf_perfmon
```

The arguments are as follows.

- The first argument, `bpf_perfmon`, is the required `<condition>`, selected from `root` to run as root, `bpf_perfmon` for `CAP_BPF` and `CAP_PERFMON`, `bpf_perfmon_dac` to add `CAP_DAC_READ_SEARCH`, or `sysadmin` for `CAP_SYS_ADMIN`.

Outputs are `experiments/runtime-discovery/out/privilege-<condition>.json` and `privilege-<condition>.md`, with per-operation raw logs, `supervise.json` records, and other evidence under `privilege-<condition>-artifacts/`.

Replace `kltest` with an existing unprivileged username. The script neither creates a user nor allows a non-root condition to run as UID 0. The `root` condition does not require `KL_PRIV_USER`. In addition to both prepared binaries, the command requires bpftrace, setcap, and the native Docker Engine.

Capabilities are applied to copies of bpftrace and `runtime-events` in a dedicated working directory under `/var/tmp`. The system bpftrace, the built `out/runtime-events`, and sysctls remain unchanged. The working directory is removed once every operation's termination and evidence preservation are confirmed; otherwise, the script reports its location and exits non-zero.

#### Aggregation

Use `load.py` to aggregate saved load measurements.

```sh
python3 experiments/runtime-discovery/tools/load.py experiments/runtime-discovery/out
```

The arguments are as follows.

- The first argument, `experiments/runtime-discovery/out`, is the optional `<out dir>`, both the parent directory searched for load measurement runs and the output directory for aggregated results, and defaults to `experiments/runtime-discovery/out`.

Aggregated results are written to `<out dir>/AGGREGATE-load.md` and `<out dir>/AGGREGATE-load.csv`. Each row includes the run's measurements and differences in operational command and web median durations against the `none` control with the same case, interval, observation window, and replicate number.

Differences are reported as unmeasured with reasons when comparison is blocked by a missing control, an early stop, an unestablished window, an incomplete measurement, or missing or different image IDs. Unavailable individual measurements also retain reasons instead of becoming zero, using `not_measured: <reason>` in `load.json` and `n/a (<reason>)` in the aggregate tables.

### Observing running containers

Use `attach_running` to join existing containers and keep evidence separate for each generation across restarts or re-creation under the same name. Build the `runtime-discovery` and `runtime-events` binaries on a development machine and transfer them to the observation environment beforehand.

#### Precheck

Run `prod-precheck.sh` as root to check the observation environment.

```sh
sudo bash experiments/runtime-discovery/tools/prod-precheck.sh \
  /var/tmp/runtime-discovery-prod/precheck 512
```

The arguments are as follows.

- The first argument, `/var/tmp/runtime-discovery-prod/precheck`, is the required `<out dir>`, which stores the results and is created if missing.
- The second argument, `512`, is the optional `[pages]`, selected from `64`, `256`, `512`, or `none`, and defaults to `512`.

The script records the kernel, BTF, tracepoints, bpftrace and bpftool versions, cgroup v2, procfs mount options, sysctls, lockdown, AppArmor, Docker version and cgroup driver, running container identities, and free space on the output filesystem. Results are saved as `<out dir>/precheck.json` and `precheck.md`, with raw results under `raw/`.

When bpftrace is available, all three scripts for 64, 256, and 512 pages are checked with `--dry-run`, regardless of the selected value. The script exits non-zero when a hard requirement is missing, including BTF, required tracepoints, cgroup v2, or a reachable native Docker Engine. Event collection also requires bpftrace and a successful dry-run of the selected script. Missing bpftool is recorded but does not itself cause failure.

The script does not create, start, stop, or modify containers, or change sysctls.

#### Joining running containers

`prod-observe.sh` observes existing containers, scans each observed generation's image with Trivy, and runs `match` against HIGH/CRITICAL Findings.

```sh
sudo KL_PROD_PAGES=512 bash experiments/runtime-discovery/tools/prod-observe.sh \
  /var/tmp/runtime-discovery-prod/run-001 300 api worker
```

The arguments are as follows.

- The first argument, `/var/tmp/runtime-discovery-prod/run-001`, is the required `<out dir>`, which stores this run's records and results.
- The second argument, `300`, is the required `<window seconds>`, a positive integer specifying the requested observation window.
- The remaining arguments, `api worker`, are the optional `[container names...]`, defaulting to containers running at startup when omitted.

Replace the container names with the intended targets. `KL_PROD_MAX_SECONDS` caps the observation window at 1800 seconds by default; larger requests are logged and shortened. `KL_PROD_INTERVAL` sets the interval between sample starts and defaults to 30 seconds. The window after applying the cap must be at least this interval.

The main environment variables are as follows.

- `KL_PROD_PAGES` selects `64`, `256`, `512`, or `none`, defaults to `512`, and disables the tracer and event collection when set to `none`.
- `KL_TRIVY_CMD` selects the image-scanning command, defaults to `trivy`, is split into arguments on spaces, and has its scan output captured from stdout.
- `KL_RD_BIN` and `KL_RE_BIN` specify the transferred binary paths, defaulting to `experiments/runtime-discovery/out/runtime-discovery` and `experiments/runtime-discovery/out/runtime-events`, respectively.
- `KL_PROD_ALLOW_UNMEASURED_LOAD=1` explicitly runs both tracer and collector through `supervise -no-cgroup`, leaving dedicated-cgroup load measurements unmeasured with reasons.

Prepare a native Docker Engine, Python 3, Trivy, both binaries, and the supporting scripts, plus bpftrace when collecting events. `runtime-events` is also used for clock and cgroup-table collection when events are disabled.

Monitoring begins before tracer startup. By default, it checks every 10 seconds and requests a stop if tracer CPU exceeds one core-equivalent for three consecutive samples, the count of `Lost N events` notifications increases for three consecutive samples, the run exceeds 1 GiB, its parent directory exceeds 4 GiB, or free space falls below 20 GiB.

`KL_WATCH_INTERVAL`, `KL_WATCH_CPU_CORES`, `KL_WATCH_RUN_BYTES`, `KL_WATCH_ROOT_BYTES`, and `KL_WATCH_FREE_BYTES` override the monitoring interval and thresholds; size values are in bytes. `KL_WATCH_HARD_DEADLINE_GRACE_S` sets the allowance added to supervised process deadlines and defaults to `120` seconds. No web requests are issued, so the `KL_WATCH_WEB_FAILURES` condition does not apply. Without a dedicated cgroup, tracer CPU cannot be measured and cannot trigger its threshold condition.

The main outputs are as follows.

- `collect/` stores per-generation observation records and the manifest.
- `match/` and `csv_hc/` store per-generation `match` results.
- `scans/` stores Trivy results by image ID.
- `timeline.jsonl` records observation startup, registration results, stop reasons, scanning and matching results, and other milestones.
- `restarts.jsonl` appends detected restarts, re-creations, and correction events.
- `run_window.json` stores the planned window for the whole run, independently of generation splitting.
- `collector_supervise.json` and, when a tracer is used, `tracer_supervise.json` record startup, stopping, termination confirmation, and load.
- `watch.jsonl`, `watch.log`, and `stop_request.txt` store monitoring results and stop requests.

A changed `StartedAt` under the same ID is detected as a restart, and replacement by another ID under the same name as re-creation. Mapping inputs are read again for the new generation. Observation windows and evidence are separated by generation, and each generation is matched against the scan for its own image ID.

The script does not create, start, stop, or modify target containers, or issue a workload. Stop handling applies to its own observation processes. A required-step failure produces a non-zero exit while retaining results for completed generations. See [REFERENCE.md](REFERENCE.md#observing-running-containers) for details.

#### Aggregating the three evidence states

Use `prod_summary.py` to summarize a saved run.

```sh
sudo python3 experiments/runtime-discovery/tools/prod_summary.py \
  /var/tmp/runtime-discovery-prod/run-001
```

The arguments are as follows.

- The first argument, `/var/tmp/runtime-discovery-prod/run-001`, is the required `<run dir>`, both the input directory and the summary output directory.
- `--before <RFC3339 ts>` and `--after <RFC3339 ts>` optionally select generations for the before/after comparison, each choosing the latest generation that had started by the specified time.
- `--container <name>` optionally restricts the summary to one container name.

Results are saved as `<run dir>/prod_summary.md` and `prod_summary.csv`. Classification prefers the verdict including event evidence, then falls back to the verdict including read-only additions and finally the original rules when the later series did not run. An unconfirmed verdict alone does not cause fallback to another series.

| State | Definition |
| --- | --- |
| Confirmed | The selected series reports `confirmed` |
| Undeterminable (started before observation) | An unconfirmed language package whose generation started before the effective observation start |
| No evidence | Everything else, with sub-reasons such as permission failure, no observation, unsupported mapping, or loss |

The effective observation start uses the attachment-confirmation time recorded in the run's timeline, or collector startup when attachment was unconfirmed or events were disabled. “Undeterminable” describes a condition that predates observation; it does not establish earlier use.

The summary partitions each generation's HIGH/CRITICAL Finding count into the three states and reports package counts separately. For containers with multiple generations, a before/after table compares the first and last generations by default. It shows package class, name and version, states before and after, common/added/removed membership, the earliest recorded evidence time and type in the later generation, and the remaining reason. A version change produces separate removal and addition entries.

## Cases

The following table shows each case's container behavior and what it checks. Cases 1 through 12 use the [manual sampling procedure](REFERENCE.md#manual-measurement), cases 13 through 22 and 26 through 28 use `case-run.sh`, and cases 23 and 24 use `attribution-control-run.sh`. Cases 13 through 24 investigate event evidence and added package mapping, while cases 26 through 28 are used for ground truth and coverage scoring.

| No. | Container behavior | What it checks |
| --- | --- | --- |
| 1 | Resident web server with master and workers | Package ownership and publication on all interfaces |
| 2 | Non-root key-value service | apk ownership and loopback publication |
| 3 | Web server using host networking | Listener attribution |
| 4 | Database with multiple processes and no published ports | Resident process observation |
| 5 | Python service with a compiled extension | Language-package mapping gaps |
| 6 | Dynamically linked C server on a minimal image | Ownership through `status.d` |
| 7a / 7b | Same static Go server on different base images | Effect of available package metadata |
| 8 | Processes retaining deleted or replaced files | Deleted executables, deleted libraries, and atomic replacement |
| 9 | Repeated short-lived commands | Sampling misses with five-second sleeps |
| 10 | Shared library loaded and unloaded for seven seconds each | Temporary mapping capture |
| 11 | Non-root web server | Effective privileges |
| 12 | Web server with changed capabilities | Added `NET_ADMIN` and dropped `NET_RAW` |
| 13 | Repeated short-lived commands | Individual executions and loader-resolved library use |
| 14 | Repeated shared-library loads and unloads | Per-load capture and verified unloading |
| 15 | Python import with compiled caches | Extension, installed-file, and cache-path mapping |
| 16 | Same Python import without compiled caches | Cache-condition comparison |
| 17 | Node.js dependency in a standard directory layout | Files opened and closed during loading |
| 18 | Same dependency in a linked directory layout | Links and real paths reaching the same package |
| 19 | Java loading separate jars on the class path | Startup opens and retained descriptors |
| 20 | Java loading a bundled jar | Evidence at the outer-archive granularity |
| 21 | Java opening a jar through a delayed loader | Opens caused by the load |
| 22 | Static Go server with an embedded dependency | Linking the binary path to scan findings |
| 23 / 24 | Identical programs and paths in separate containers | Attribution with separate, concurrent, and host controls |
| 26 | Python web application with periodic OS operations inside the container | Package coverage across startup, lazy, and unused groups |
| 27 | Node.js web application with periodic OS operations inside the container | Package coverage across startup, lazy, and unused groups |
| 28 | Java application with periodic OS operations inside the container | Package coverage across startup, lazy, and unused jar groups |

Cases 26 through 28 periodically run curl, git, and openssl inside their containers independently of the firing signal. The groups in `coverage_plan` express fixture intent, while independent evidence determines actual use and non-use.

## Reading results

### Files to read first

Start with each run's `record.md` and the cross-run `out/AGGREGATE-events.md`.

### Three measures of event evidence

The following table shows the three measures to check separately and the CSV files containing their detailed counts.

| Measure | Meaning | Detailed output |
| --- | --- | --- |
| Confirmed findings | Findings linked to use in three evidence series: previous rules, with read-only additions, and with event evidence | `csv_hc/series.csv` |
| Occurrence capture | Capture rates among eligible executions and loads after excluding undecidable occurrences, scored against independent logs | `csv_hc/occurrence_capture.csv` |
| Container attribution | Correct attribution, host non-attribution, and evaluability of errors | `csv_hc/attribution.csv` |

### Observation states

Check `event_state` and observation window incompleteness in `csv_hc/event_drops.csv`.

- `event_state=observed` means startup and attachment were confirmed and no items indicate observation window incompleteness.
- `event_state=degraded` means collection with confirmed startup and attachment has loss, interruption, or unmeasured loss categories, so captured occurrences alone do not establish completeness.

### Coverage scoring (cases 26 through 28)

For cases 26 through 28, read `coverage.md` for package recall and false-positive rate by category and evidence series. The three evidence series are previous rules, with read-only additions, and with event evidence.

- Recall is the proportion of used packages whose use was confirmed, and is N/A when there are no used packages.
- False-positive rate (FPR) is the proportion of packages with established non-use whose use was confirmed, and is N/A when no packages have established non-use.
- The main figures include use from startup through the measurement window's end, and the `window` figures are supplementary.
- In the miss table for the series with event evidence, check each miss's primary cause and candidate tags.
- `HOLD` means image identity or equivalent operations could not be established and scoring is withheld, so check the stated reason.

### Ranking comparison

Read `out/AGGREGATE-rank.md` for changes from the baseline without runtime information in `act_now` and `watch`. The matching implementation limits ranking comparisons to two series: previous rules and with event evidence.

- Check the run-by-series-by-priority details and the replicate-agreement summary.
- Distinguish missed Findings outside the stored top 20 from those whose recorded ranks stayed unchanged.

## Limitations

- Evidence can only raise priority; missing evidence never establishes safety or lowers priority.
- Sampling can miss short-lived activity, and `attach_running` cannot recover a one-time load completed before attachment.
- An open jar or executed Go binary does not prove execution of each bundled dependency.
- Java cases are excluded from reported occurrence capture because their independent logs lack thread identity.
- Cross-container misattribution cannot be evaluated without an independent process correspondence table.
- Minimum tracing privileges, event-observation overhead, and operation in production-equivalent environments remain unverified.
- The added cases do not pin apt package versions, so comparisons require the same image ID.
- The match grouping key cannot distinguish language packages with identical names and versions across different language ecosystems.
- strace slows the truth run, so correspondence uses operations and their instances rather than equal elapsed time across runs.
- Static Go binaries and their embedded modules are outside this coverage evaluation.

- Before the first layout reading, event matching uses only the scan index without OS ownership or the symlink table because layout immutability cannot be established.
- Opening a directory alone does not count as package use.
- When the link and its target each have a single, different owner, both packages count as used, following the ground truth.

## Details

- [Inputs, outputs, and flags](REFERENCE.md#inputs-and-outputs) describe saved files, run keys, and command options.
- [Manual measurement](REFERENCE.md#manual-measurement) covers sampling cases, startup ordering, and helper commands.
- [Ground truth and matching](REFERENCE.md#ground-truth-gt-b) describe independent logs, identity, and attribution rules.
- [Observation states and CSV files](REFERENCE.md#observation-states) explain completeness, unavailable rates, and all fourteen tables.
- [Checks and limitations](REFERENCE.md#checking-without-docker) cover synthetic inputs and detailed evidence limits.
