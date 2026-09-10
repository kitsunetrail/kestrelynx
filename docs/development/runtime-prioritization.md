# Runtime Evidence Prioritization: Feasibility Research

- **Status:** Research
- **Started:** 2026-09-09
- **Last updated:** 2026-09-10

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

## Verification method (initial plan)

- **Processes and package ownership**
    - Verify on real containers running on a Docker host.
    - Use the Docker API's `top` endpoint to map PIDs to containers and procfs to map executables and loaded shared libraries to installed OS packages.
    - Start with OS packages, for example using dpkg ownership information.
- **Ports and privileges**
    - Collect listening ports and effective privileges through procfs and the Docker API.
    - Keep listening-port observations distinct from conclusions about internet reachability.
- **Accuracy and operational cost**
    - Measure mapping accuracy, failure modes, and collection overhead.
    - Measure the share of Trivy findings in the test containers confirmed through procfs and the share left `unobserved` because of short-lived processes or language packages, both overall and by existing priority groups equivalent to “act now” and “watch”.
    - Record the installation steps and permissions required for observation.
- **Unmapped cases**
    - Examine binaries deleted during upgrades, language packages absent from maps, short-lived processes and temporary dlopen activity missed between samples, connection history unavailable from snapshots, and distroless images.
    - Record observed files with unresolved package ownership as `unknown` and missing observations as `unobserved`, without filling gaps with guesses.
- **Prioritization and compatibility**
    - Assess whether positive evidence provides useful narrowing beyond KEV and EPSS.
    - Verify that unknown or unobserved information never lowers priority.
    - Verify that all existing functionality remains intact with the runtime observer disabled.

## Next steps

- **Define the first verification scope**
    - Specify the Docker containers and OS-package ownership cases for the initial experiments.
- **Define a shared evidence model**
    - Define observation classifications (`confirmed`, `inferred`, `unknown`, and `unobserved`) and evidence types so they can be associated with either Docker container IDs or Kubernetes namespace/pod/container identifiers.
- **Run the initial observations**
    - Check executable and loaded shared-library mappings to OS packages, listening ports, and effective privileges on the Docker host.
    - Record mapping failures, observation gaps, required permissions, and collection overhead.
- **Assess feasibility**
    - Evaluate the results against the five questions above.
    - Append experiments, results, limitations, and the resulting decisions to this page.

## Update history

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

This article is a KestreLynx development record. [About KestreLynx](../index.md)
