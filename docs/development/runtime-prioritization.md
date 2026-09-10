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
    - Never treat a listening port alone as proof of internet reachability.
- **Opt-in runtime observer**
    - The runtime observer is a component that, when explicitly enabled, runs on the Docker host and reads procfs and the Docker API to determine which vulnerable package binaries are running as processes, which ports they listen on, and what effective privileges they have.
    - With the runtime observer disabled, every existing feature must keep working unchanged, including the standard image scan, which requires no extra privileges.
- **Initial observation target**
    - Start with Docker Engine only, using procfs and the Docker API.
    - Do not use eBPF, kernel modules, or privileged in-container agents.
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

- **Kubernetes evidence collection**
    - Kubernetes-side evidence collection begins after this investigation establishes feasibility on Docker Engine.
    - First, use containerPort and Service declarations to infer expected listening ports and securityContext to infer expected effective privileges, treating information available through the existing read-only Kubernetes adapter as `inferred` evidence without the runtime observer or additional permissions.
    - Then, follow the initial Docker implementation with opt-in DaemonSet observation for `confirmed` evidence, subject to confirmed demand from Kubernetes users.

## Verification method (initial plan)

- **Processes and package ownership**
    - Verify on real containers running on a Docker host.
    - Enumerate processes through procfs and map their executables back to installed packages.
    - Start with OS packages, for example using dpkg ownership information.
- **Ports and privileges**
    - Collect listening ports and effective privileges through procfs and the Docker API.
    - Keep listening-port observations distinct from conclusions about internet reachability.
- **Accuracy and operational cost**
    - Measure mapping accuracy, failure modes, and collection overhead.
    - Record the installation steps and permissions required for observation.
- **Unmapped cases**
    - Examine binaries deleted during upgrades, language-runtime dependencies loaded as libraries, and distroless images.
    - Record cases that cannot be mapped as explicit `unknown` results rather than guesses.
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
    - Check executable-to-package mapping, listening ports, and effective privileges on the Docker host.
    - Record mapping failures, observation gaps, required permissions, and collection overhead.
- **Assess feasibility**
    - Evaluate the results against the five questions above.
    - Append experiments, results, limitations, and the resulting decisions to this page.

## Update history

### 2026-09-10

- **Kubernetes stage defined**
    - Keep the initial investigation limited to Docker Engine while defining observation classifications and evidence types for both Docker and Kubernetes identifiers.
    - Define the Kubernetes sequence as inferred evidence without the runtime observer, followed by opt-in DaemonSet observation, starting after Docker feasibility is established and requiring confirmed user demand for DaemonSet observation.

### 2026-09-09

- **Research started**
    - Recorded the motivation, design stance, five feasibility questions, non-goals, and initial verification plan.
    - Experiments and results are pending.

---

This article is a KestreLynx development record. [About KestreLynx](../index.md)
