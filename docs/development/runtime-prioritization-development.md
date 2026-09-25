# Runtime Evidence Prioritization Development

- **Status:** Design finalized (not yet implemented)
- **Started:** 2026-09-25
- **Last updated:** 2026-09-25

## Purpose

KestreLynx scans the images of running containers with the Trivy vulnerability scanner, prioritizes findings using CISA KEV, a catalog of vulnerabilities known to be exploited, and EPSS, an estimate of exploitation likelihood, and sends diff notifications to Slack and webhooks. Add runtime evidence showing that packages are used in the deployment environment to support these decisions.

The [runtime evidence prioritization feasibility research](runtime-prioritization.md) and subsequent coverage, event-observation, and observation-environment validations inform the rules for treating packages as in use, their effect on prioritization, and the placement and permissions of the observation component. The design is finalized, and implementation and its validation are the next work.

## Scope of In-Use Classification

The Sensor, the component that observes runtime information, determines whether both OS packages and language packages are in use.

- **OS packages**
    - Cover packages installed through apt or apk whose file ownership can be established from dpkg or apk databases
    - Treat a package as in use when a file it owns is the executable of a running process or a loaded shared library
    - Exclude rpm-based packages from the initial implementation
- **Language packages**
    - Treat all packages included in a running process as in use, regardless of function calls or actual loading
    - For languages such as Go and Rust, treat packages as in use when the binary containing them is running
    - For languages such as Python, Node.js, and Java, treat all packages of that language in the container as in use when a corresponding runtime process, such as python, node, or java, is running there
    - Classify unsupported languages as Unavailable
- **Observation methods**
    - Combine periodic reads with execution and file event observation through eBPF, a mechanism for observing events in the kernel
    - Use eBPF to capture programs that run briefly, such as curl, git, and scripts run by cron
    - Always include eBPF in the Sensor
    - Do not use eBPF to track language-package loading
    - When eBPF cannot run, continue determining use through periodic reads alone and include a warning in notifications
- **Observation states**
    - **In use** — Use is confirmed through an executable, a loaded shared library, or a corresponding runtime process
    - **Not observed** — Use has not been confirmed during the observation window; this does not mean unused or safe
    - **Unavailable** — Use cannot be determined because of insufficient read permissions, a stopped or initializing Sensor, an unsupported language, or similar conditions

For example, openssl loaded by nginx is in use, while perl that no process executes has no observed use.

## Effect on Prioritization

The act now, watch, and low priority levels continue to depend on KEV, EPSS, severity, and Status, the remediation status reported by Trivy. Runtime evidence affects ordering within a priority level and the supporting context displayed.

- Place OS packages and language packages in use earlier within the same priority level
- Attach supporting context, such as executables, published ports, and execution users, to packages in use
- Do not lower priority or omit findings from notifications because use is not observed or observation is unavailable

Act now reflects known exploitation or exploitation likelihood. Use in a particular environment is a separate consideration, so being in use does not raise a package’s priority level. Some packages also cannot be observed, so lowering priority without confirmation would defer attention to packages that are harder to see.

## Observation Component Placement and Permissions

- **Placement**
    - Add the Sensor optionally
    - Run it in a separate container using the same image as the main application, started with the `sensor` subcommand
    - Keep existing functionality and output unchanged when runtime evidence is disabled
- **Permissions**
    - Share the host PID namespace
    - Grant `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` ([observation environment validation](runtime-environment-validation.md) confirms that non-root execution with these capabilities produces the same observation results as root)
    - Drop `CAP_BPF` and `CAP_PERFMON`, used to load eBPF programs, immediately after loading at startup
- **Separation from the main application**
    - Give the main application no observation privileges
    - Give the Sensor no network access, Docker socket, or notification credentials
    - Pass evidence to the main application through files on a shared volume
    - Have the main application validate evidence as untrusted input
- **Separation inside the Sensor**
    - The process reading `/proc` has privileges and does not parse file contents
    - The process parsing package databases has no privileges and is prohibited from performing filesystem operations
- **Restriction mechanisms**
    - Run as non-root
    - Apply `no_new_privs`
    - Apply the distributed seccomp profile
    - Apply Landlock to the parsing process
    - Use Docker’s default AppArmor profile
- **eBPF implementation**
    - Load eBPF programs directly from Go
    - Do not bundle external tools
- **Residual risk**
    - State in public documentation that the scope of readable data is unrestricted if the privileged process is compromised
- **Comparison with similar tools**
    - The [Falco deployment instructions](https://falco.org/docs/setup/container/) use root and capabilities including `CAP_SYS_ADMIN`
    - The [Tetragon deployment instructions](https://tetragon.io/docs/installation/container/) use `--privileged`
    - Give the Sensor a narrower permission scope than these deployment configurations
    - Limit the comparison to the privileges specified in the deployment instructions

## Notification Display

Runtime evidence adds a marker and supporting context to identify OS packages and language packages in use.

- **Slack in-use display**
    - Add a `▶ in use` marker and supporting context to OS packages and language packages in use
    - Show executables and loaded shared libraries as evidence for OS packages
    - Show that the corresponding runtime is running or that the binary containing the packages is running as evidence for language packages
    - Also indicate when a brief execution was captured
- **Slack full view**
    - Append counts of OS packages and language packages by observation state
    - Include a note that not observed does not mean unused
- **Slack language-package display**
    - Replace the trailing `[lang]` with the ecosystem name, identifying the package distribution and management system
    - Use Trivy’s package-type values, such as `[python-pkg]`, `[node-pkg]`, `[jar]`, and `[gobinary]`
- **Additional webhook fields**
    - Add `class` (`os` / `lang`) and `ecosystem` to each finding
    - Add `runtime` to OS-package and language-package findings when runtime evidence is enabled
    - Keep existing fields unchanged and make additions only

In environments where eBPF cannot run, notifications include a warning stating this and explaining that use continues to be determined through periodic reads alone.

Ecosystem labels and the webhook `class` and `ecosystem` fields are introduced regardless of whether runtime evidence is enabled.

Changes in whether a package is in use do not trigger diff notifications.

## Change log

### 2026-09-25

- Recorded the plan

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
