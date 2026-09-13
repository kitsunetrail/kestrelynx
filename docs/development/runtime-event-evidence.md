# Runtime Evidence Observation with eBPF: Feasibility Research

- **Status:** Investigating
- **Started:** 2026-09-13
- **Last updated:** 2026-09-13

## Purpose

Extend the sampling approach validated in [Runtime Evidence Prioritization: Feasibility Research](runtime-prioritization.md) to examine whether execution and file-loading events can address the remaining confirmation gaps.

- **What sampling could not confirm**
    - Sampling could link resident executables and shared libraries to OS packages, but could not reliably capture short-lived programs.
    - Shorter sampling intervals still produced captures that depended on timing, leaving the proportion of executions missed undetermined.
    - Language packages and runtimes installed outside the OS package manager remained outside the established mapping coverage.

- **Production motivation**
    - In one run on one production host with four containers, all 103 HIGH/CRITICAL findings remained unconfirmed, including 84 language-package findings.
    - All eight “watch” findings remained unconfirmed, and there were no “act now” findings to evaluate.
    - The sample included a static Go binary, a JVM with a bundled JDK, and two Node.js services.
    - Some findings concentrated on programs that do not stay resident, including 23 HIGH/CRITICAL findings attached to a bundled scanner that runs only when scanning.
    - These observations motivate further investigation but do not establish effectiveness across real deployments.

- **Investigation status**
    - Measurements for this investigation have not started.
    - The significance of the production confirmation gap and users' acceptance of the required privileges remain unevaluated.

## Approach

- **Try methods without kernel event tracing first**
    - Match a running static binary against Trivy's findings for that binary, using evidence tied to the scanned image and observed file.
    - Check whether files a process keeps open can identify language packages, particularly Java archives.
    - Extend package mapping for already observed Python extensions where installed package records support it.
    - Measure these additions first to establish which gaps still require event observation.

- **Test event feasibility before building a dedicated observer**
    - Use an existing tracing tool to investigate successful execution and file-opening events and their links to findings.
    - Proceed to a minimal purpose-built program only after event evidence demonstrates useful mapping and reliable container attribution.
    - Use that program to measure minimum privileges and overhead in a form closer to a possible product implementation.
    - Treat tracing-tool overhead as a measurement of that configuration, without assuming it bounds future product overhead.

- **Use evidence of use only to raise priority**
    - Evidence here means an observed record that a process executed, loaded, or held open a file belonging to the package.
    - Evidence may only raise priority, and missing evidence must never lower priority or imply safety.
    - Independently valid evidence remains valid when another part of observation fails.
    - Record the failed method and its unavailable measurements separately.
    - Distinguish a file being opened from a program being executed, and describe bundled dependencies at the granularity actually observed.

- **Measure the share of findings and the capture rate of executions and loads separately**
    - Measure the share of Trivy findings linked to evidence of use within the observation window to show how many vulnerability findings gained supporting evidence of use.
    - Separately measure the share of individual executions and loads independently logged by programs inside the container that event observation captured to show how much activity was missed.
    - Never conclude from either measure alone, because capturing one execution or load can raise the share of findings with evidence of use while the capture rate of individual executions and loads remains low.

- **Keep observation optional**
    - Give event observation a separate opt-in from sampling, so sampling remains usable without event-tracing support.
    - Preserve existing functionality when runtime observation is disabled.
    - Limit initial collection to file paths, execution facts, and the identity and timing needed to attribute them, excluding command-line arguments and environment variables by default.

## Questions to validate

1. **Capture of brief activity**
    - Can execution and temporary loading be captured consistently when measured against individual occurrences?
2. **Correct counting**
    - Can load operations be scored correctly when one operation opens several files or uses cached content without opening any?
3. **Package mapping and evidence limits**
    - Which language ecosystems permit unambiguous links to scanned packages, and can bundled dependencies be explained without implying that each dependency's code executed?
4. **Container attribution**
    - Can events be assigned to the correct container without confusing another container or a host program with the target?
5. **Prioritization value**
    - How many previously unconfirmed findings gain evidence, especially within “act now” and “watch”, and how does their ranking change?
6. **Operational feasibility**
    - What kernel features, privileges, and workload overhead are required, and what remains to establish whether users accept them?

## Out of scope

- **Vulnerable-code execution and attack detection**
    - Do not attempt to prove that a vulnerable function executed.
    - Keep attack detection, attack alerts, and attack timeline reconstruction outside this investigation.

- **Network history and reachability**
    - Do not collect established-connection history or infer network reachability from event evidence.

- **Kubernetes node observation**
    - Defer Kubernetes-side collection until feasibility on Docker Engine has been established.

- **Mandatory event observation**
    - Do not make event tracing a prerequisite for sampling or existing image-scanning functionality.

- **Older-kernel guarantees**
    - Limit conclusions to tested kernels and configurations, without claiming support for older kernels from success on newer ones.

## Verification method (plan)

Extend the tooling described in the [harness README for the sampling investigation](https://github.com/kitsunetrail/kestrelynx/blob/main/experiments/runtime-discovery/README.md), keeping the investigation independent of the product.

- **Reused test cases**
    - Extend the short-lived curl and git case with independent records for each execution.
    - Extend the temporary SQLite loading case with independent records for each load operation.
    - Extend the Python case to cover native extensions and Python modules under different cache conditions.

- **Additional language cases**
    - Add a Node.js application that loads a known vulnerable dependency under conventional and linked package layouts.
    - Add a JVM application that loads a known vulnerable dependency from ordinary and bundled archives.
    - Add a static Go program with scanner-detected vulnerable dependencies and independently logged execution.
    - Verify that each intended dependency appears in the scan and that the test application records the intended execution or loading.

- **Attribution control and production sample**
    - Run two containers and a host program with overlapping executable names and paths to expose incorrect attribution.
    - Include container restarts and process-identifier reuse in the attribution checks.
    - Observe the production sample of a static Go binary, a JVM with a bundled JDK, and two Node.js services after they are already running.
    - Report the production sample separately because it lacks independent logs establishing every execution or load occurrence.

- **Observation timing**
    - Start observation, confirm readiness, and only then trigger the application's execution or loading.
    - Confirm that a known test event arrives, the target container is recognized, and supporting package information has been collected before triggering.
    - Record container startup and application startup as separate times.
    - Compare controlled startup with observation that joins an already running application, recording any activity triggered again within the window.
    - Fix repetition counts and planned occurrence counts before measurement.

- **Unobserved cases**
    - Record an occurrence as outside-window only when independent logs establish that it happened outside the observation period.
    - Record an occurrence as missed-in-window when independent logs establish that it happened during observation but was not captured.
    - Record the reason as unknown when occurrence or timing cannot be established, including unobserved activity in the production sample.
    - Never interpret an unobserved case as proof that a package was unused.

- **Three-way comparison**
    - Evaluate the same saved data using the previous rules, then those rules with read-only additions, then those additions with event evidence.
    - Keep all findings in the main denominator, including findings affected by collection failures.
    - Report confirmation gains separately for read-only additions and event evidence, broken down by priority, ecosystem, and evidence granularity.
    - Compare ranking changes and report observed binary and file counts alongside finding counts.

- **Independent occurrence records**
    - Have test applications record unique occurrence identifiers, process identity, timing, target files, and success independently of the observer.
    - Match executions individually and associate each load operation with its corresponding set of file events.
    - Exclude failed operations, activity outside the window, and loads satisfied entirely from cache from the applicable capture denominator.
    - Calculate individual file-opening capture rates only where independent records of those openings exist, and report rates with no eligible occurrences as unavailable.

- **Accuracy and collection losses**
    - Report misattribution rate as incorrectly assigned events divided by all assigned events.
    - Report correct-attribution rate as executions assigned to the correct container divided by independently logged executions.
    - Check false confirmations against independently established usage and report how much of the tested population those checks cover.
    - Record lost events, buffer overflow, unresolved paths, ambiguous matches, and interrupted observation separately.

- **Overhead and privilege conditions**
    - Compare observation enabled and disabled using repeated runs with alternating or varied order.
    - Measure observer CPU and memory, Docker daemon CPU, event volume, and the target application's CPU, throughput, and response time.
    - After feasibility is established, compare root with non-root conditions granting tracing-specific privileges, those privileges plus protected-file reading, and a broader administrative privilege.
    - Record success or failure for each operation, separating tracing permissions, file access, and host security restrictions.
    - Document Docker access and sampling privileges alongside event-observation privileges to show the combined requirements.
    - Record tested kernel features, active security restrictions, and resource limits without treating root access as a guarantee of success.

## Next steps

- **Prepare and measure**
    - Extend saved-data collection and independent application logs, then measure the additions that require no event tracing.
    - Run the existing tracing tool and assess both finding confirmation and occurrence capture.
- **Evaluate the next implementation step**
    - Build the minimal observer only after event-derived results support proceeding, then measure privileges and overhead.
    - Publish results, limitations, and remaining user-acceptance questions before deciding whether to integrate, narrow, or stop the investigation.

## Change log

### 2026-09-13

- **Investigation planned**
    - Recorded the staged approach, validation questions, scope, and verification plan before starting measurements for this investigation.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
