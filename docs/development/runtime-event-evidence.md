# Runtime Evidence Observation with eBPF: Feasibility Research

- **Status:** Development-machine measurements completed; minimum privileges, overhead, and production-environment validation remain untested
- **Started:** 2026-09-13
- **Last updated:** 2026-09-16

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
    - Development-machine measurements ran on September 13–16, 2026. See the [measurement results](#results-2026-09-16).
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

## Results (2026-09-16)

Event evidence linked findings for short-lived curl and git processes and Node.js dependencies to observed use where the previous methods could not, but coverage depends on when observation starts and whether records are lost.

Tests ran on a development machine using WSL2, Linux 6.6, bpftrace 0.25, and root privileges, with five-minute observation windows and one to three runs per case.

**Findings linked to evidence of use**

- **Total findings**: All HIGH/CRITICAL findings from Trivy's scan of the image for that case.
- **Packages used**: Packages independently established as used from the independent log (the record the program inside the container keeps, separately from the observation tools, of what it executed or loaded and when), with their names.
- **Their findings**: HIGH/CRITICAL findings belonging to the packages used, which is the upper bound linkable in that case.
- **Confirmations by each method**: Findings linked by each method to evidence that a file belonging to the package was executed or loaded during the observation window.

“Confirmations / findings in used packages” measures how completely findings were linked, while “confirmations / total findings” measures the share of all findings that gained evidence.

Programs inside the container independently logged executed files, loaded libraries, imported or required modules, and opened jars. These records were matched to package ownership information from the OS package database, Python's RECORD, Node.js's package.json, jar pom.properties, and metadata embedded in Go binaries to independently establish which packages were used.

git was also used, but it contributed no HIGH/CRITICAL findings to the counts.

The comparison uses three methods, with each column adding evidence to the methods on its left.

- **Previous rules**: The method used in [Runtime Evidence Prioritization: Feasibility Research](runtime-prioritization.md) periodically inspects processes through procfs and links executables and loaded libraries to OS packages.
- **Read-only additions**: Without eBPF, this method expands mapping through information readable from procfs, covering module information embedded in Go binaries, jars held open by the JVM, and Python extension mappings.
- **Event evidence**: This method uses eBPF to record execution and file-opening events and link them to findings.

This table compares total findings, findings in used packages, and confirmations by each method when observation started before the workload.

| Container behavior | Total findings | Packages used | Their findings | Previous rules | Additions | Event evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Runs curl and git every five seconds, with each process lasting a few milliseconds | 101 | 5 (curl, libcurl4, and 3 dependency libraries) | 14 | 0 | 0 | 14 |
| Repeatedly loads and unloads a shared library | 61 | 1 (libsqlite3) | 3 | 3 | 3 | 3 |
| Python imports cryptography, with and without a cache | 61 | 1 (cryptography) | 5 | 0 | 5 | 5 |
| Node.js requires lodash, using npm | 17 | 1 (lodash) | 4 | 0 | 0 | 4 |
| Node.js requires lodash, using pnpm | 47 | 1 (lodash) | 4 | 0 | 0 | 4 |
| Java loads a log4j-core jar, using ordinary jar, fat jar, and delayed-loading setups | 11 | 1 (log4j-core) | 3 | 0 | 3 | 3 |
| Runs a static Go binary | 62 | 1 (golang.org/x/text) | 4 | 0 | 4 | 4 |

- Including event evidence linked every finding in used packages in every case.
- Only event evidence linked the 14 findings in the short-lived curl and git case and the 4 findings in each Node.js setup.
- When observation starts after the workload, Node.js's one-time require has already finished. Confirmations fall to 0 of the 4 findings in used packages for both npm and pnpm, even with event evidence. All other confirmation counts, including Python's, remain unchanged.

**Capture of individual executions and loads**

In the table, occurrences are the eligible executions or loads recorded in an independent log, and captured counts those matched one-to-one with eBPF records.

This table shows how many individual executions and loads were captured when observation started before the workload.

| Activity inside the container | Captured / occurrences |
| --- | --- |
| Runs curl and git every five seconds, with each process lasting a few milliseconds | 116/116 |
| Repeatedly loads and unloads a shared library | 22/22 |
| Python imports cryptography, with and without a cache | 1/1 each |
| Node.js requires lodash, using npm and pnpm | 1/1 each |
| Runs a static Go binary with embedded dependency modules | 1/1 |

- Short-lived curl and git executions also reached 116/116 when observation started after the workload.
- Java jar loading is excluded because its independent logs lack thread identity.
- Capturing every eligible occurrence does not establish loss-free collection, and this rate is separate from the share of findings linked to evidence of use.

**Container attribution**

Attribution determines which container a recorded execution belongs to; in the table, correctly attributed counts executions assigned to the right container, and executions counts those recorded in an independent log.

This table shows attribution in runs without collection losses, using two containers from the same image separately or concurrently.

| Execution setup | Correct / logged |
| --- | --- |
| Each container runs separately | 116/116 each |
| Both containers run concurrently | 232/232, 236/236 |

- All independently logged executions in these conditions were attributed correctly, with concurrent counts combining both containers without duplication.
- In tests running the same program on the host, all 41 and 48 host executions remained unattributed to any container.
- The matching method cannot evaluate the rate of confusion between containers, so these results do not establish that rate.

**Recording buffers and losses**

The memory area where the kernel-side observation program writes each event and holds it until the collection tool reads it is called the recording buffer. When events arrive faster than they are read, the area fills and the overflow is lost.

This table shows how many events were lost to recording-buffer overflow at each buffer capacity.

| Observed workload | Buffer pages | Lost events |
| --- | --- | --- |
| Repeated short-lived curl and git executions | 64 | 2763–2790 |
| Repeated short-lived curl and git executions | 256 | 0–12 |
| Repeated short-lived curl and git executions | 512 | 0 |
| Two containers from the same image running concurrently | 256 | 1465 |
| Two containers from the same image running concurrently | 512 | 0 |
| Python importing cryptography without a cache | 256 | 66 |
| Python importing cryptography without a cache | 512 | 0 |
| All other cases | 256 | 0 |

- Increasing the buffer to 512 pages produced zero losses in the measured runs for short-lived curl and git, concurrent containers, and Python without a cache.
- Only measurements with zero losses are treated as complete observation windows.
- Each case had only one to three runs, so a capacity that produced zero losses here may behave differently under other environments or loads.

**Lessons from the test environment**

- Kernel-side path filters exceeded verifier limits and could not load, so paths were filtered after recording.
- Nested PID namespaces gave the observer and workload different process numbers, so matching used process numbers within the namespace together with the namespace identity.
- Alpine with musl uses a legacy file-opening mechanism, making its activity invisible when only newer mechanisms are observed.
- Buffer capacity affects losses, so capture rates must be read alongside loss records.

## Next steps

- **Prepare and measure**
    - Done: Read-only additions were measured.
    - Done: Existing tracing tools measured finding confirmation and capture of individual executions and loads.
    - Pending: Verification in a production-equivalent environment remains.
- **Evaluate the next implementation step**
    - Pending: A minimal dedicated CO-RE program remains to be built and used to measure minimum privileges and overhead.
    - Pending: Results, limitations, and questions about what users will accept remain to be published before deciding whether to proceed with implementation.

## Change log

### 2026-09-13

- **Investigation planned**
    - Recorded the staged approach, validation questions, scope, and verification plan before starting measurements for this investigation.

### 2026-09-16

- **Recorded development-environment measurements**
    - Added finding confirmations, occurrence capture, attribution, collection losses, and lessons from the development environment.
- **Recorded work status**
    - Recorded completed preparation and measurements.
    - Recorded pending minimum-privilege, overhead, production-equivalent environment, and production-sample observation and reporting work.
    - Recorded conditional CO-RE implementation and measurement work.
    - Recorded pending publication of unresolved questions before a decision.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
