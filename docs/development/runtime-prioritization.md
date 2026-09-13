# Runtime Evidence Prioritization: Feasibility Research

- **Status:** Stage 1 measured, stage 2 investigation planned
- **Started:** 2026-09-09
- **Last updated:** 2026-09-13

## Purpose and motivation

Investigate whether runtime evidence can be linked to vulnerability findings accurately enough to improve prioritization.

**This capability is not part of current KestreLynx.** This investigation does not promise a user-facing release. If the requirements below cannot be satisfied, the runtime feature will be dropped rather than shipped in a degraded form.

This page records the initial plan. Experiments, results, limitations, and decisions will be appended as the investigation proceeds.

- **Image findings and actual execution**
    - A scanner reports vulnerabilities across all packages inside an image, including modules that are never executed in a given deployment.
- **Existing prioritization**
    - KestreLynx already prioritizes findings using CISA KEV and EPSS.
    - These global signals do not establish whether a vulnerable component actually runs in the user's environment.
- **Environment-local evidence**
    - Investigate whether a binary from a vulnerable package is running as a process, whether the service is listening on a port, and what privileges it has.
    - Use this evidence to explain and sharpen prioritization.

## Design stance

- **Evidence only promotes**
    - Positive runtime evidence can raise a finding's priority, for example into “act now”.
    - The absence of evidence never lowers a finding's priority.
    - Observation gaps caused by short-lived processes, restarts, or insufficient permissions must never be interpreted as safety.
- **Observation classifications**
    - Classify observations as `confirmed`, `inferred`, `unknown`, or `unobserved`.
    - Treat executables and loaded OS shared libraries mapped to packages as `confirmed`, and short-lived processes missed by sampling and language packages as `unobserved` unless their use can be directly linked to packages through event evidence.
    - Never treat a listening port alone as proof of internet reachability.
- **Opt-in runtime observer**
    - When explicitly enabled, the runtime observer runs on the Docker host and samples procfs and the Docker API to link executables and loaded shared libraries to vulnerable packages and collect listening ports and effective privileges.
    - Sampling and eBPF event observation require separate opt-ins, so sampling remains available on hosts that do not meet the eBPF kernel requirements.
    - With the runtime observer disabled, every existing feature must keep working unchanged, including the standard image scan, which requires no extra privileges.
- **Initial observation target**
    - Start with state sampling on Docker Engine using procfs and the Docker API to map executables and loaded shared libraries to OS packages, requiring access to the host PID namespace and root-equivalent permissions to read other processes' `/proc` entries.
    - Treat eBPF event observation as a later stage if measurements show insufficient confirmation of findings equivalent to “act now” or “watch” in real deployments and users can accept its kernel and permission requirements, with attack detection outside scope.
    - Leave Kubernetes-side evidence collection for a later stage.

## Validation items

1. **Package-to-process mapping accuracy**
    - Can packages and runtime information be linked accurately within a limited, well-defined scope?
    - Can each link be explained, for example why a process's executable is attributed to a particular OS package?
2. **Safe handling of unknowns**
    - Can unknowns and observation gaps be handled without ever producing a false low-priority judgment?
3. **Operational burden**
    - Do the required installation steps, permissions, and host load stay within what the target users tolerate?
4. **Value beyond KEV and EPSS**
    - Does runtime evidence usefully narrow which findings need attention beyond what KEV and EPSS already provide?
5. **Behavior with the runtime observer disabled**
    - Does disabling the runtime observer leave all existing functionality fully intact?

All five questions are conditions for proceeding. If they cannot be satisfied, the runtime feature will be dropped.

## Non-goals of this investigation

- **Event observation of short-lived processes and language packages**
    - Keep event observation of short-lived processes and language packages outside the initial investigation and consider it in a later stage based on measured observation gaps.
    - Keep attack detection and attack timelines outside scope.

- **Kubernetes evidence collection**
    - Kubernetes-side evidence collection begins after this investigation establishes feasibility on Docker Engine.
    - First, use containerPort and Service declarations to infer expected listening ports and securityContext to infer expected effective privileges, treating information available through the existing read-only Kubernetes adapter as `inferred` evidence without the runtime observer or additional permissions.
    - Then, follow the initial Docker implementation with opt-in DaemonSet observation for `confirmed` evidence, subject to confirmed demand from Kubernetes users.
    - Apply the same sampling and conditional event observation stages, with separate opt-ins, to DaemonSet observation.

## Verification method

- **Verification environment**
    - Ran a verification program (harness) independent of the product on 1 WSL2 host.
    - Used Linux 6.6.114, Docker Engine 29.1.3, and Trivy 0.71, focusing on HIGH/CRITICAL findings.
- **Linkage 1: process → OS package → Trivy finding (ownership)**
    - To confirm use of vulnerable packages, match executables and loaded libraries against OS package ownership information.
    - Link packages confirmed as used to Trivy findings for the same image, without guessing unresolved ownership.
- **Linkage 2: listening port → process → exposure (ports)**
    - To check service exposure, match listening processes against Docker's port publication settings.
    - Never treat a listening port alone as proof of internet reachability.
- **Linkage 3: process → execution user and special privileges (privileges)**
    - To establish which privileges each process runs with, check its execution user and whether it has special privileges.
- **Combining the linkages and validating collection**
    - Attach only information confirmed for the same process at the same observation time to findings, to avoid mixing information from different processes.
    - Record unsuccessful observations as failures.
- **Ground truth (the list of packages actually used, for scoring)**
    - To check mapping accuracy, create a list of packages used through a method independent of the harness.
    - For self-built images, compare against the program's own usage logs to check for misses and false positives within the logged scope.
    - For official images, manually map files used by resident processes to packages and check only for misses.
    - Treat checks whose targets were selected after observation as reference values, and neither method confirms execution of the vulnerable code itself.
- **Test cases**
    - To check coverage and misses, test resident services, different package formats, file deletion and replacement, and short-lived execution and loading.
    - Completed 36 measurement runs across 12 cases and 13 image variants, including 2 reruns after fixes.
- **Permission and sampling conditions**
    - Used a baseline of 10 samples taken as root every 30 seconds over 300 seconds, and compared 4 permission conditions with nginx, Redis, and Distroless.
    - To check whether brief usage could be captured, compared 7 conditions with different observation intervals, windows, and start times.
    - To assess operational burden, measured harness CPU time and peak memory, and Docker daemon CPU time.

See the [harness README](https://github.com/kitsunetrail/kestrelynx/blob/main/experiments/runtime-discovery/README.md) for specific permission names and procedures.

## Results (2026-09-12)

- **What worked**
    - Resolved the owning packages of executables and OS shared libraries for the resident processes checked.
    - Assigned 0 files with unresolved ownership to packages by guessing, and did not confuse any of the 3 deleted or replaced targets with the current files at the same paths.
    - Distinguished execution privileges per process and port publication settings, while treating host-network exposure as unknown.
    - The following table applies only to the single host used for the main measurements, with Docker access provided separately.

    | Observer permission condition | Package-use confirmation | Listening-process identification | Execution-privilege confirmation |
    | --- | --- | --- | --- |
    | root | Baseline | Available | Available |
    | Non-root with 2 minimal privileges | Same as root | Same as root | Same as root |
    | Non-root with 1 privilege | Same as root | Unavailable, exposure unknown | Available |
    | Non-root with no privileges | Observation failed in all samples | Unknown | Unknown |

    - For 1 container over 300 seconds in the main measurements, harness CPU time was 0.09–0.41 seconds and peak memory was 6.5–20 MB.
    - Docker daemon CPU increased by 0.16–0.21 seconds, except Redis at 1.13 seconds, whose cause remains uninvestigated.
    - Maximum observation delay was 37 ms, without cumulative drift.
- **What did not work**
    - Predeclared ground truth covered only 4.0–5.6% of HIGH/CRITICAL packages in the applicable cases, leaving overall accuracy undetermined.
    - Comparison against usage logs showed 0 false positives but covered only 1–2 packages per case.
    - Could not map language packages such as Python extensions and Go dependencies, and could not map static Go executables through OS package ownership information.
    - Could not reliably capture curl and git, which ran for about 0.1 seconds and then waited 5 seconds, and the following table counts samples that captured them rather than the proportion of executions captured.

    | Interval | Window | Phase offset | Samples | curl captures | git captures |
    | --- | --- | --- | --- | --- | --- |
    | 10 s | 300 s | 0 s | 30 | 1 | 0 |
    | 30 s | 300 s | 0 s | 10 | 0 | 0 |
    | 60 s | 300 s | 0 s | 5 | 0 | 0 |
    | 10 s | 100 s | 0 s | 10 | 0 | 0 |
    | 60 s | 600 s | 0 s | 10 | 1 | 0 |
    | 30 s | 300 s | 3 s | 10 | 0 | 0 |
    | 30 s | 300 s | 7 s | 10 | 1 | 0 |

    - Capture depended on observation timing, so these measurements cannot estimate a general miss rate.
    - Captured SQLite in all 7 conditions as it alternated between loading and unloading every 7 seconds.
- **Per-case results**
    - Fractions represent findings linked to usage evidence / findings in scope under the baseline condition.
    - “act now” and “watch” counts include only HIGH/CRITICAL findings, and N/A means no applicable findings.

    | Image or case | HIGH/CRITICAL | act now | watch | All severities |
    | --- | --- | --- | --- | --- |
    | nginx Debian | 9/153 | 1/2 | 2/20 | 66/616 |
    | Redis Alpine | 0/0 | N/A | N/A | 0/0 |
    | nginx host network | 9/153 | 1/2 | 2/20 | 66/616 |
    | PostgreSQL | 5/113 | N/A | 1/10 | 71/409 |
    | Python + cryptography | 0/54 | N/A | 0/2 | 22/180 |
    | Distroless dynamic C | 0/0 | N/A | N/A | 18/29 |
    | Debian static Go | 0/56 | N/A | 0/2 | 0/222 |
    | Distroless static Go | 0/0 | N/A | N/A | 0/0 |
    | Deleted/replaced files | 0/59 | N/A | 0/3 | 18/232 |
    | Short-lived curl/git | 0/99 | N/A | 0/9 | 23/410 |
    | Temporary SQLite loading | 3/59 | N/A | 1/3 | 28/232 |
    | nginx-unprivileged Alpine | 16/34 | 2/2 | 2/4 | 42/109 |
    | nginx special-privilege changes | 9/153 | 1/2 | 2/20 | 66/616 |

    - In nginx Debian, 2 libssl3 “watch” findings moved up in rank while unobserved findings retained their rank.
- **Production sample**
    - Measured 4 containers on a separate Ubuntu host in 1 run as root, every 30 seconds over 300 seconds.
    - Observations succeeded 10/10 times for all containers with AppArmor enabled, while non-root conditions remained untested.

    | Container type | HIGH/CRITICAL confirmed / total | HIGH/CRITICAL breakdown: language / OS | watch confirmed / total | All severities confirmed / total |
    | --- | --- | --- | --- | --- |
    | Static Go binary | 0/36 | 23 / 13 | N/A | 0/107 |
    | JVM with a bundled JDK | 0/17 | 15 / 2 | 0/3 | 16/246 |
    | Node.js service 1 | 0/21 | 19 / 2 | 0/3 | 0/48 |
    | Node.js service 2 | 0/29 | 27 / 2 | 0/2 | 0/67 |

    - All 103 HIGH/CRITICAL findings remained unconfirmed, comprising 84 language-package findings and 19 unobserved OS-package findings.
    - All 8 “watch” findings also remained unconfirmed, comprising 6 language-package findings and 2 OS-package findings.
    - There were 0 “act now” findings, so that group could not be evaluated, and this result from 1 run on 1 host cannot be generalized across real deployments.
    - Across the 4 containers, harness CPU time was 0.44 seconds, peak memory was 16.8 MB, and Docker daemon CPU increased by 0.59 seconds.
- **Harness defects found on real hosts**
    - Fixed misclassification of insufficient permissions, incorrect file ownership judgments, and omission of findings without a priority classification from the counts.
    - The separate issue of some findings missing from product notifications and other outputs remains unresolved.
    - Additional checks to distinguish replaced files and an assessment of where further observation could help in static Go cases remain unvalidated.

## Decision (2026-09-13)

- **Proceed to stage 2 investigation**
    - Prioritization of HIGH/CRITICAL findings did not improve in this production sample, so investigate how to confirm use by short-lived processes and use of language packages.
    - Begin the investigation while the stage 2 entry conditions remain unevaluated, retaining the principle that missing evidence never lowers priority.
- **Design leads**
    - For static Go, consider matching the binary detected by Trivy to the running file.
    - For JVM, consider confirming use through files kept open, and for Node.js, through records of when files were opened.
- **Open questions**
    - Acceptable operating environments and permissions for users, methods for mapping language packages, and effectiveness across real deployments remain unconfirmed.

## Next steps

- **Validate event observation and mapping**
    - To capture brief usage, validate records collected when execution or file loading occurs and their mapping to packages.
- **Evaluate permissions, accuracy, and load**
    - To establish feasible deployment conditions, confirm what users will accept and the permissions required in each environment.
    - To assess practicality, measure accuracy and effects on prioritization across multiple hosts and days, along with load at larger scales and during initial observation.
- **Define shared evidence and preserve existing functionality**
    - Define how to represent observations and their supporting evidence for use across Docker and Kubernetes.
    - During product integration, reassess all 5 feasibility conditions, including ensuring that observation failures never lower priority and that disabling the observer preserves compatibility.

## Change log

### 2026-09-13

- **Recorded stage 1 results**
    - Added the verification method, results, required permissions, load, production sample, fixed defects, and remaining limitations.
- **Defined the stage 2 investigation approach**
    - Begin investigating how to confirm use by short-lived processes and use of language packages while entry conditions remain unevaluated.

### 2026-09-10

- **Kubernetes stage defined**
    - Keep the initial investigation limited to Docker Engine while defining observation classifications and evidence types for both Docker and Kubernetes identifiers.
    - Define the Kubernetes sequence as inferred evidence without the runtime observer, followed by opt-in DaemonSet observation, starting after Docker feasibility is established and requiring confirmed user demand for DaemonSet observation.
- **eBPF approach defined**
    - Start with procfs and Docker API state sampling that includes loaded shared libraries and requires access to the host PID namespace and root-equivalent permissions.
    - Make eBPF event evidence a separate opt-in for a later stage, conditional on measured confirmation gaps and users accepting its kernel and permission requirements, while keeping attack detection outside scope.

### 2026-09-09

- **Research started**
    - Recorded the motivation, design stance, five feasibility questions, non-goals, and initial verification plan.
    - Experiments and results are pending.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
