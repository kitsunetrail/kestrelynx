# Runtime Evidence Coverage: Validation Plan

- **Status:** Under investigation
- **Started:** 2026-09-19
- **Last updated:** 2026-09-19

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

## Next steps

- **Prepare the evaluation**
    - Finalize the measurement procedure and extend the test harness with the three workloads.
    - Add independent ground-truth collection and package-level scoring.

- **Measure and assess**
    - Run the planned conditions and record recall, false positives, and reasons for misses.
    - Compare remediation decisions using the fixed scan and threat-information snapshots.
    - Publish results and limitations before deciding whether to adopt runtime evidence for prioritization.

## Change log

### 2026-09-19

- **Recorded the validation plan**
    - Documented the purpose, observation methods, workloads, independent ground truth, metrics, acceptance criteria, and comparison of remediation decisions.
    - Measurements and the adoption decision remain pending.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
