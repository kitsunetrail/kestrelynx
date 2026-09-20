# Runtime Evidence Coverage: Validation Plan

- **Status:** Development-machine measurements completed; minimum privileges, overhead, and production-environment validation remain untested.
- **Started:** 2026-09-19
- **Last updated:** 2026-09-20.

## Purpose

Evaluate package coverage before deciding whether to adopt runtime evidence for remediation prioritization.

- **What previous investigations established**
    - [Runtime Evidence Prioritization: Feasibility Research](runtime-prioritization.md) and [Runtime Evidence Observation with eBPF: Feasibility Research](runtime-event-evidence.md) tested whether selected packages could be linked to evidence of use.
    - Those measurements focused on one or two target packages per workload.
    - They did not establish what proportion of all packages actually used by a workload could be confirmed.

- **What this investigation evaluates**
    - Measure coverage across all used packages, identified by name and version.
    - Check whether unused packages are incorrectly confirmed as used.
    - Compare how missed packages affect remediation priorities.
    - This page records the plan; measurements and an adoption decision remain pending.

## Approach

- **Establish independent ground truth**
    - Record package usage using a separate method that does not rely on the collection tools being evaluated.
    - Use those records to determine whether each bundled package was actually used by the workload.
    - Include packages without vulnerability findings in the coverage evaluation.
    - Measure recall and false positives for each observation method against the same ground truth.

- **Compare observation methods and their combined coverage**
    - Evaluate sampling that maps running executables and loaded libraries to OS packages using the existing rules.
    - Evaluate read-only additions that identify Java archives kept open by a process and map Python extensions to packages.
    - Evaluate eBPF evidence of execution and file-opening events.
    - Report each method's contribution and the combined coverage without counting the same package more than once.

- **Use evidence only to raise priority**
    - Evidence of use may raise remediation priority.
    - Missing evidence or a package classified as unused must never lower priority or imply safety.
    - Distinguish file access and loading from execution of a package's code.
    - Static Go binaries are excluded from package-level coverage evaluation because all modules embedded in a running binary are treated as used.

## Questions to validate

1. **Coverage of all used packages**
    - Measure the proportion of used packages confirmed by each method and by their combination.
2. **False confirmations**
    - Check whether any package independently established as unused is confirmed as used.
3. **Differences between package groups**
    - Compare OS packages used by resident processes, OS packages used by short-lived operations, and language packages.
4. **Sensitivity to observation conditions**
    - Compare observation start times, window lengths, and sampling intervals.
5. **Reasons for misses**
    - Separate brief use, use before observation began, unsupported package mapping, collection losses, and other causes.
6. **Effects on remediation decisions**
    - Compare changes in “act now” and “watch” counts and rankings, including findings associated with missed packages.

## Out of scope

- **Coverage of static Go binaries**
    - All modules embedded in a running binary are treated as used.
    - Use is then decided by the binary's execution, so package-level coverage evaluation does not apply.

- **Proof of vulnerable-code execution**
    - Package use does not establish that a vulnerable function executed or that exploitation is possible.
    - Attack detection and network reachability assessment are outside this investigation.

- **Deployment-wide feasibility**
    - This plan evaluates controlled workloads on Docker Engine.
    - Minimum privileges, operational overhead, user acceptance, and effectiveness across production environments remain separate questions.

## Verification method (plan)

- **Three application workloads**
    - Run a Python web application with about 30 bundled packages, using only a subset through startup imports and imports triggered by requests.
    - Run a Node.js web application that uses only a subset of its bundled packages, with loading at startup and on demand.
    - Run a Java application with multiple archives on its classpath, including archives loaded at startup, loaded later, and never loaded.
    - Run periodic operations using OS command-line tools inside each application container.
    - Include OS libraries used by resident processes.

- **Observation conditions**
    - Compare observation started before the workload with observation attached to an already running workload.
    - Use observation windows of 5 and 15 minutes and sampling intervals of 30 and 10 seconds.
    - Use an event collection buffer of 512 pages, with zero collection losses as the baseline requirement.
    - Record actual losses for each run.
    - Run every condition at least once and the main conditions twice.

- **Independent ground truth**
    - Inventory all bundled packages by name and version.
    - In separate ground-truth runs, use system-call tracing independent of eBPF collection to record all executions and file openings.
    - Map recorded files to packages using OS package ownership records and language package metadata.
    - For Python, collect the loaded modules and their source files at application exit.
    - For Node.js, collect the modules retained in the runtime's loaded-module cache.
    - For Java, collect class-loading records to identify the archives used.
    - Establish used packages from the combined file and runtime records.
    - Bundled packages are unused within the prescribed workload only when record completeness and ownership are verified and neither set of records shows use.
    - Packages without sufficient evidence for either classification remain unknown.
    - Resolve incomplete records or ambiguous ownership before treating the ground truth as complete.

- **Reproducible execution**
    - Separate ground-truth runs from measurement runs because tracing changes execution speed.
    - Use the same image, trigger sequence, and observation window for both.
    - Fix the order of application requests and operational tasks so both runs perform the same work.
    - Preserve records of startup activity when evaluating observation attached to a running workload.
    - Keep use before observation began distinguishable from misses during observation.

- **Metrics**
    - Calculate recall as correctly confirmed used packages divided by all packages independently established as used.
    - Count false positives as packages established as unused but confirmed as used.
    - Report the unused-package population alongside the false-positive count.
    - Count each package name and version once within each evaluated group.
    - Report results by workload, observation condition, and method.
    - Separate OS packages used by resident processes, OS packages used by short-lived operations, and Python, Node.js, and Java packages.
    - Break down misses into brief use, use before observation began, unsupported mapping, collection losses, and other causes.

- **Acceptance criteria**
    - Require at least 80% recall in each package group.
    - Apply this threshold to the combined evidence from sampling, read-only additions, and events.
    - Show the results for each method alongside the combined result.
    - Require zero false positives.
    - Keep condition-specific results visible so an overall total cannot hide gaps.
    - Preserve the rule that absent evidence or unused status never lowers priority.

- **Comparison of remediation decisions**
    - Fix the image identity, scan results, and KEV and EPSS snapshots.
    - Compare four configurations: no runtime information, sampling only, sampling with read-only additions, and those methods with event evidence.
    - Compare “act now” and “watch” counts and rankings across the four configurations.
    - Count findings associated with missed packages that meet the criteria for “act now” or “watch”.
    - Report package coverage separately from vulnerability finding counts.

## Results (2026-09-20)

**Conclusions**

- Language packages met the criteria under startup for every workload, and short-lived OS packages were all confirmed under both start conditions.
- Python and Node.js language packages under attach_running, and Node.js resident OS packages under both start conditions, fell short.
- False positives were 0 packages across all conditions and methods.
- Runtime evidence was adopted conditionally for remediation prioritization despite remaining coverage gaps.

**Measurement scale and scope**

- **Environment**: Docker Engine on WSL2 on a development machine, with administrative privileges.
- **Workloads**: Three applications—Python and Node.js web applications and a Java application—each running curl, git, and openssl periodically, with packages without vulnerability findings also evaluated.
- **Runs**: Three separate ground-truth runs, 30 measurement runs, and 0 runs on hold in the final aggregation.
- **Observation conditions**: Intervals of 10 and 30 seconds, windows of 300 and 900 seconds, and a 512-page buffer, with two runs for the 30-second interval and 900-second window per workload and start condition, and one run for each other combination.

**Terms**

- **Ground truth**: Records establishing use or non-use through system-call tracing independent of the evaluated observation tools and language-specific loading records.
- **Language packages**: Packages distributed and managed through the Python, Node.js, or Java ecosystem.
- **Resident OS**: OS packages used by resident processes such as the application.
- **Short-lived OS**: OS packages used by operations that exit quickly, such as curl, git, and openssl.
- **Previous rules**: Periodic reads of procfs that link executables and loaded libraries to OS packages, as described in [How to Map Running Container Processes to OS Packages with procfs](../articles/procfs-process-to-package-mapping.md).
- **With read-only additions**: The previous rules plus confirmations obtained by [mapping language packages detected by Trivy to runtime files](../articles/trivy-language-packages-runtime-mapping.md), which only reads procfs and installs no observation program.
- **With event evidence**: The read-only additions plus confirmations from the evidence recorded by [observing container execution and file opens with bpftrace](../articles/bpftrace-container-exec-open-events.md).
- **startup**: Observation starts before the workload.
- **attach_running**: Observation attaches to an already running workload.
- **Recall**: The proportion of packages established as used by ground truth whose use was correctly confirmed.
- **False positives**: The number of packages established as unused by ground truth but confirmed as used.

**Ground truth**

| Container behavior | Bundled packages | Packages used | Unused packages | Unknown |
| --- | --- | --- | --- | --- |
| Python web application with periodic operations | 152 packages | 63 packages | 89 packages | 0 packages |
| Node.js web application with periodic operations | 390 packages | 109 packages | 281 packages | 0 packages |
| Java application with periodic operations | 163 packages | 49 packages | 114 packages | 0 packages |

- **Counting**: A package is one name-and-version combination, so the same name with a different version counts as a separate package.
- **Repeated runs**: Measuring the same condition twice does not count the same package twice.
- **Overlapping groups**: An OS package used by both the resident process and the short-lived operations, such as libc6, is counted in both the resident OS and short-lived OS groups, so the two groups' counts cannot be added together.
- **Meaning of short-lived OS confirmations**: A short-lived OS package also counts as confirmed when the evidence came from the resident process, so short-lived OS recall does not measure how many of the short-lived executions themselves were captured.
- **Unused populations (OS / language)**: Python had 78 / 11 packages, Node.js 80 / 201 packages, and Java 111 / 3 packages, with the same unused OS population used for false-positive evaluation in both OS groups.
- **Unknown scope**: The 0 unknown packages apply to the scored inventory, while five additional Java package placements still had unresolved versions.

**Coverage of package use**

The table shows recall with event evidence, with parentheses giving “packages correctly confirmed as used / packages established as used by ground truth.” Packages used only before observation began remain in the evaluation.

| Container behavior | Start condition | Language package recall (with event evidence) | Resident OS recall (with event evidence) | Short-lived OS recall (with event evidence) |
| --- | --- | --- | --- | --- |
| Python web application with periodic operations | startup | 100% (19/19 packages) | 89% (16/18 packages) | 100% (33/33 packages) |
| Python web application with periodic operations | attach_running | 37% (7/19 packages) | 83% (15/18 packages) | 100% (33/33 packages) |
| Node.js web application with periodic operations | startup | 99% (71/72 packages) | 75% (6/8 packages) | 100% (31/31 packages) |
| Node.js web application with periodic operations | attach_running | 0% (0/72 packages) | 75% (6/8 packages) | 100% (31/31 packages) |
| Java application with periodic operations | startup | 100% (9/9 packages) | 82% (9/11 packages) | 100% (31/31 packages) |
| Java application with periodic operations | attach_running | 100% (9/9 packages) | 82% (9/11 packages) | 100% (31/31 packages) |

- **Incorrect confirmations**: The previous rules, those rules with read-only additions, and those additions with event evidence had 0 false-positive packages across all 30 runs, with 0 incorrect confirmations outside the bundled-package inventory.
- **Sensitivity to conditions**: For a fixed workload, group, and start condition, intervals, windows, and repetitions produced no differences in recall, false positives, or miss counts and primary causes with event evidence, and neither longer windows nor shorter intervals made use before observation began confirmable.
- **Language-package increments.**
    - The previous rules confirmed 0 packages, while those rules with read-only additions confirmed seven Python packages containing extensions and nine Java packages.
    - Under startup, a further 12 Python packages and 71 Node.js packages were confirmed with event evidence.
    - These are increments between cumulative methods, with standalone counts for read-only additions and event evidence and overlaps between methods still unaggregated.

**Reasons for misses**

Every miss remaining with event evidence was assigned to one of the following groups, without duplicating primary causes.

- **Use before observation began**: Execution or loading finished before observation started, so no evidence of that use remains once observation begins.
    - Under attach_running, 12 Python pure-module packages and all 72 Node.js packages were missed because their files were no longer held open.
    - Resident OS misses under attach_running included time-zone data in every workload and base-files in Python.
    - With read-only additions, use was still confirmable after observation began for seven Python extension packages, whose files stay loaded in memory, and nine Java packages, whose jars stay open.
- **Unsupported package mapping**: Limitations in linking observed files to package names and versions through ownership records or metadata.
    - Under startup, every workload missed the resident OS packages owning awk and time-zone data because the matcher lacked the container symlink resolution supported by ground-truth collection.
    - Under attach_running, the package owning awk was affected in every workload's resident OS group.
    - Node.js startup missed one package belonging to the application itself outside `node_modules`.

**Acceptance criteria**

The established recall threshold and 0 false-positive packages were required for each group and start condition with event evidence.

| Container behavior | Package group | startup | attach_running |
| --- | --- | --- | --- |
| Python web application with periodic operations | Language packages | Met | Not met |
| Python web application with periodic operations | Resident OS | Met | Met |
| Python web application with periodic operations | Short-lived OS | Met | Met |
| Node.js web application with periodic operations | Language packages | Met | Not met |
| Node.js web application with periodic operations | Resident OS | Not met | Not met |
| Node.js web application with periodic operations | Short-lived OS | Met | Met |
| Java application with periodic operations | Language packages | Met | Met |
| Java application with periodic operations | Resident OS | Met | Met |
| Java application with periodic operations | Short-lived OS | Met | Met |

- Decisions hold across all intervals, windows, and repetitions, with every failure due to recall and the Node.js failures preventing the resident OS group from meeting the criteria as a whole.

**Effects on remediation decisions**

- **Evaluation**: Scan results and threat information were fixed per image, and findings belonging to missed packages were counted by the remediation priority categories “watch” and “act now” (act-now).
- **Findings belonging to missed packages.**
    - Under startup, every workload had 0 findings.
    - Under attach_running, Python had two watch findings, Node.js had two watch findings and one act-now finding, and Java had 0 findings.
- **Comparison limits**: These are not counts of changed classifications or rankings, and comparison of overall classification counts and ranking differences across four configurations—no runtime information, the previous rules, those rules with read-only additions, and those additions with event evidence—remains pending.
- **Incorrect increases**: Incorrect confirmations of unused packages caused 0 priority increases across all conditions and methods.

**Adoption decision**

Runtime evidence is adopted for remediation prioritization under the following conditions.

- **Reasons.**
    - Evidence only raises priority, so misses do not become incorrect judgments of non-use or safety.
    - Missing confirmation because loading preceded observation is a temporary state avoidable through continuous observation from before container startup.
- **Conditions.**
    - Keep the observation process running continuously, with observation from before container startup as the standard operating mode.
    - Retain and display language packages in containers started before observation as “Indeterminate (container started before observation began),” separately from confirmed use and no evidence, and indicate resolution at the next container restart while observation remains active.
    - Enforce in both implementation and presentation that absent evidence or unused status never lowers priority or excludes a package from remediation.
- **Remaining work** (not preconditions for adoption; carried out during implementation afterwards)
    - Resolve symlinks inside containers in the matcher.
    - Support the application's own package outside `node_modules`.
    - Compare ranking differences with and without runtime information.
    - Verify minimum privileges, overhead, and behavior in production.

**Corrections made during measurement**

Saved inputs for all 30 runs were reprocessed with the same corrections and rules, and only reprocessed values were used in the main results.

- Fill gaps in package file-placement records when adjacent records agree on the mapping.
- Attribute startup events before registration to the correct container without extending into periods of identifier reuse.
- Preserve time-zone offsets during UTC conversion, with 0 changes to reported values.
- Change the assessment rule after measurement so one periodic operation with a different outcome does not place the entire run on hold.

**Scope of the results**

- One ground-truth run per workload was reused, without independent ground-truth repetitions for each condition.
- Comparisons apply to the same saved image, with no guarantee that the same build procedure reproduces it.
- The absence of interval and window effects applies only to the tested workloads and operation sequences, while other usage frequencies and request patterns, representativeness of actual usage paths, minimum privileges, overhead, and production behavior remain untested.

## Next steps

- **Coverage of all used packages**
    - Done: Measure the proportion of used packages confirmed by each method and by their combination (cumulative comparison of the previous rules, those rules with read-only additions, and those additions with event evidence).
    - Pending: Aggregate standalone confirmation counts for read-only additions and event evidence, and overlaps between methods.

- **False confirmations**
    - Done: Check whether any package independently established as unused is confirmed as used.

- **Differences between package groups**
    - Done: Compare OS packages used by resident processes, OS packages used by short-lived operations, and language packages.

- **Sensitivity to observation conditions**
    - Done: Compare observation start times, window lengths, and sampling intervals.

- **Reasons for misses**
    - Done: Separate brief use, use before observation began, unsupported package mapping, collection losses, and other causes.

- **Effects on remediation decisions**
    - Done: Use fixed scan results and threat information to count “act now” and “watch” findings belonging to packages still missed with event evidence, and incorrect priority increases for unused packages.
    - Pending: Compare changes in “act now” and “watch” counts and rankings, including findings associated with missed packages (overall classification counts and ranking differences across four configurations: no runtime information, the previous rules, those rules with read-only additions, and those additions with event evidence).

- **Remaining changes and validation of applicability**
    - Pending: Resolve symlinks inside containers in the matcher and reassess ownership mapping for mawk and tzdata, including false confirmations.
    - Pending: Add matching support for the application's own package outside `node_modules`.
    - Pending: Reflect which use before observation began can and cannot be confirmed afterwards under attach_running in the specification and presentation.
    - Pending: Verify minimum privileges, overhead, start conditions, and actual usage paths in production to assess where these results apply.
    - Done: Decided to adopt runtime evidence for remediation prioritization subject to three conditions (2026-09-20).
    - Pending: Implement the adoption conditions by retaining and displaying the indeterminate state, operating observation continuously, and enforcing in both implementation and presentation the rule that absent evidence or an unused classification must never lower priority or exclude a package from remediation.

## Change log

### 2026-09-19

- **Recorded the validation plan**
    - Documented the purpose, observation methods, workloads, independent ground truth, metrics, acceptance criteria, and comparison of remediation decisions.
    - Measurements and the adoption decision remain pending.

### 2026-09-20

- **Recorded development-environment measurements**
    - Added the scope of three ground-truth runs and 30 measurement runs, ground truth, recall, false positives, condition differences, reasons for misses, and acceptance decisions.
    - Recorded effects on remediation decisions, corrections made during measurement, and the scope of the results.
- **Recorded work status**
    - Recorded completed validation items and pending standalone method aggregation, remediation count and ranking comparisons, matching extensions, specification updates, and production-environment validation.
    - Decided to adopt runtime evidence subject to three conditions, with the criteria still unmet for language packages under attach_running and resident OS packages in the Node.js case.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
