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

- Run these commands from the repository root.
- The tracing check verifies script loading and collection and conversion of known events.
- Check results are saved as smoke.log and events.jsonl under experiments/runtime-discovery/out/check-tracing/.
- Case 13 starts short-lived processes and runs collection, ground-truth preparation, and matching.

```sh
mkdir -p experiments/runtime-discovery/out
go build -o experiments/runtime-discovery/out/runtime-discovery ./experiments/runtime-discovery
go build -o experiments/runtime-discovery/out/runtime-events ./experiments/runtime-events
sudo bash experiments/runtime-discovery/tools/check-tracing.sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 13 1 startup 512
# Runs: experiments/runtime-discovery/out/<case>-root-30-300-p0-r<replicate>-<sync>-<tag>/
# Read first: record.md, match_hc.json, csv_hc/series.csv
# Check: csv_hc/occurrence_capture.csv, csv_hc/attribution.csv, csv_hc/event_drops.csv
```

- The arguments are `<case> [replicate] [startup|attach_running] [64|256|512|none] [interval] [window]`, with interval and window defaulting to 30 and 300 seconds.
- This command accepts case 13 through case 22 and case 26 through case 28, with `none` disabling event collection.
- `startup` observes before the measured work; `attach_running` joins work already running.
- Use a separate run directory for each condition and keep generated data out of commits.

### Run several cases

- Each plan line contains `<case> <replicate> <sync> <pages> [interval] [window]`, with the last two fields defaulting to 30 and 300 seconds.

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/example.txt
```

### Check attribution

- The first argument selects the condition: `23` runs case 23 alone, `24` runs case 24 alone, `23+24` runs both at once, and `23+host` runs case 23 while the host runs the same program.
- The arguments are `<23|24|23+24|23+host> [replicate] [256|512]`.
- This command covers only the case 23 and 24 pair; attribution for other cases is reported by `case-run.sh`.

```sh
sudo bash experiments/runtime-discovery/tools/attribution-control-run.sh 23+24 1 512
```

- This example saves its run under experiments/runtime-discovery/out/23+24-root-30-300-p0-r1-startup-nofilter512p/.
- Per-container results are match_hc-case23.json and match_hc-case24.json, with CSV files under csv_hc-case23/ and csv_hc-case24/.

### Reprocess and aggregate

- Replace `<run-dir>` with a saved run directory.
- `case-post.sh` accepts several directories; `RECONVERT=1` restarts from trace conversion.
- Set `KL_INTEL_SNAPSHOT` to saved intelligence JSON to reproduce classification with the same inputs and thresholds.

```sh
bash experiments/runtime-discovery/tools/case-post.sh "<run-dir>"
RECONVERT=1 bash experiments/runtime-discovery/tools/case-post.sh "<run-dir>"
python3 experiments/runtime-discovery/tools/aggregate.py
python3 experiments/runtime-discovery/tools/record.py "<run-dir>"
# Summary: experiments/runtime-discovery/out/AGGREGATE-events.md
# Run record: <run-dir>/record.md
```

### Ground truth and coverage scoring for case 26 through case 28

- Create a separate truth run for each case to record package use under strace using the same image as the measurement.

```sh
for c in 26 27 28; do
  bash experiments/runtime-discovery/tools/truth-run.sh "$c" 1 900
done
```

- Run a measurement with an explicit sampling interval and observation window, as in this example for case 26 with a 30-second interval and a 900-second window.

```sh
sudo bash experiments/runtime-discovery/tools/case-run.sh 26 1 startup 512 30 900
```

- Alternatively, run the supplied plans, which cover both startup conditions with intervals of 10 or 30 seconds and windows of 300 or 900 seconds.

```sh
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-main.txt
sudo bash experiments/runtime-discovery/tools/case-batch.sh experiments/runtime-discovery/tools/plans/coverage-rest.txt
```

- Build `truth.json` from the image inventory and independent logs, supplying a measurement directory to check that the two runs performed equivalent work.

```sh
python3 experiments/runtime-discovery/tools/truth.py \
  experiments/runtime-discovery/out/26-truth-r1 \
  experiments/runtime-discovery/cases/26.json \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p
```

- Score each measurement against its case's truth to write `coverage.json` and `coverage.md` in the measurement directory.
- Change the case number and measurement directory for case 27, case 28, and the other measurement conditions.

```sh
python3 experiments/runtime-discovery/tools/coverage.py \
  experiments/runtime-discovery/out/26-root-30-900-p0-r1-startup-nofilter512p \
  experiments/runtime-discovery/out/26-truth-r1/truth.json
```

## Cases

- Cases 1–12 use the [manual sampling procedure](REFERENCE.md#manual-measurement).
- Cases 13–24 investigate event evidence and added package mapping.
- Pass case 13 through case 22 or case 26 through case 28 directly to `case-run.sh`, and use the attribution command for case 23 and case 24.

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

- Each added case periodically runs curl, git, and openssl inside its container independently of the firing signal.
- The groups in `coverage_plan` express fixture intent, while independent evidence determines actual use and non-use.

## Reading results

- Start with each run's `record.md` and the cross-run `out/AGGREGATE-events.md`.
- Keep these three measures separate and use the CSV files for their detailed counts.

| Measure | Meaning | Detailed output |
| --- | --- | --- |
| Confirmed findings | Findings linked to use under previous rules, added mapping, and event evidence | `csv_hc/series.csv` |
| Occurrence capture | Capture rates among eligible executions and loads after excluding undecidable occurrences, scored against independent logs | `csv_hc/occurrence_capture.csv` |
| Container attribution | Correct attribution, host non-attribution, and evaluability of errors | `csv_hc/attribution.csv` |

- `event_state=observed` means startup and attachment were confirmed without reported window incompleteness; inspect `csv_hc/event_drops.csv`.
- `event_state=degraded` means loss, interruption, or unmeasured loss categories limit the window; captured occurrences alone do not establish completeness.

- For case 26 through case 28, read `coverage.md` for package recall and false-positive rate by category and evidence series.
- Recall measures confirmed used packages, while FPR measures confirmations among packages whose non-use was established, with zero denominators shown as N/A.
- The main figures include startup use through the measurement window's end, the `window` figures are supplementary, and the S2 miss table gives each miss's primary cause and any candidate tags.
- `HOLD` means image identity or equivalent operations could not be established, so scoring is withheld and the reason must be checked.

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

## Details

- [Inputs, outputs, and flags](REFERENCE.md#inputs-and-outputs) describe saved files, run keys, and command options.
- [Manual measurement](REFERENCE.md#manual-measurement) covers sampling cases, startup ordering, and helper commands.
- [Ground truth and matching](REFERENCE.md#ground-truth-gt-b) describe independent logs, identity, and attribution rules.
- [Observation states and CSV files](REFERENCE.md#observation-states) explain completeness, unavailable rates, and all fourteen tables.
- [Checks and limitations](REFERENCE.md#checking-without-docker) cover synthetic inputs and detailed evidence limits.
