# Kubernetes Sensor Feasibility

- **Status:** Design and feasibility validation only (implementation not started).
- **Started:** October 2, 2026.
- **Last updated:** October 3, 2026.

## Purpose

Verify whether the Sensor, the component that observes runtime information, can operate on Kubernetes nodes, and identify which parts of its Docker placement, permissions, and isolation can carry over and which need changes.

The subject is the Sensor defined in [Runtime Evidence Prioritization Development](runtime-prioritization-development.md). This validation prepares for connecting runtime evidence from nodes to the image discovery and scanning implemented in [Developing Kubernetes Support](kubernetes-support.md).

So far, startup and reads from other Pods have been verified on real systems, and placement and permission boundaries have been designed. Kubernetes implementation will begin after operational validation of the Docker Runtime features is complete.

## Approach

- **Verify what can be tested without changing KestreLynx code first**
    - Use the Sensor image and its probe mode to check startup permissions, isolation, and reads from other Pods on real systems
    - Separate what works through configuration from what requires code changes, such as container identification
- **Carry over the Docker permissions and division of responsibilities**
    - Limit observation privileges to the Sensor and keep them out of the main application and relay container
        - In Kubernetes, the Sensor runs on each node while the main KestreLynx application may run on another node, so a relay container on each node passes evidence written there by the Sensor to the main application
        - All Sensor network communication is prohibited to keep the component with observation privileges off the network, so the relay container, which has no observation privileges, handles communication with the main application
        - The main application retrieves evidence from the relay container
    - Combine read privileges with restrictions on writes, communication, and parsing
- **State the verified scope**
    - Distinguish successful startup and reads from correctly associating evidence with containers and using it in assessments
    - Record results by environment without generalizing to untested configurations

## Validation method

### Environments

- On October 3, 2026, single-node K3s was tested on WSL2 without AppArmor and on an Ubuntu VPS with AppArmor enabled
    - AppArmor restricts file access and operations between processes for individual programs
    - AppArmor behavior was also compared with Docker on the same VPS
- The cgroup hierarchy, which groups processes, was checked on WSL2 using cgroup v2 and the systemd driver
    - Checks covered Pods with different resource guarantee classes, called QoS classes, native sidecars that provide supporting functions, and pause containers that maintain the Pod execution environment

### Startup and reads

- The Sensor's probe mode checked permission acquisition, isolation, and preparation of eBPF observation programs that run in the kernel
    - The Sensor ran as non-root and shared the host PID namespace to see host processes
    - Comparisons varied Linux capabilities, which divide privileges into individual permissions, seccomp, which restricts system calls, and AppArmor
    - Checks covered `no_new_privs`, which prevents acquiring additional privileges, Landlock, which restricts file access, and isolation self-checks
- Reads from other Pods were tested against root and non-root containers
    - On the VPS, targets using the default AppArmor profile were compared with targets using Unconfined, which removes AppArmor restrictions
    - Target identity information was supplied in the Docker format accepted by the existing probe, so these checks did not validate Kubernetes discovery or matching
    - No write operations were performed against target Pods, and these checks were kept separate from the Sensor's isolation self-checks

## Results

### Permission acquisition and seccomp

Permission acquisition for the non-root Sensor was compared under the following conditions.

| Condition | Result |
| --- | --- |
| Only add capabilities to the Pod | The Sensor could not use observation privileges |
| Prohibit additional privileges before startup | The Sensor could not acquire permissions attached to the executable either |
| Allow startup permission acquisition, then let the Sensor set `no_new_privs` and restrictions on memory dumps and related access | The Docker mechanism worked |

With Localhost configured to use a seccomp profile on the node, the results were as follows.

| Profile availability | Result |
| --- | --- |
| The unchanged Docker profile was installed | Startup succeeded, and isolation self-checks confirmed that prohibited operations were denied |
| The profile was missing | Startup failed instead of removing restrictions |

- Installing the profile through an init container that prepares the environment before startup also worked
    - Using the runtime's default restrictions for the init container and selecting the installed profile only for the Sensor avoided depending on a profile that did not yet exist
- Working configurations applied Landlock, read the kernel type information needed for eBPF, and loaded and attached eBPF programs
    - Associating events with the correct Kubernetes containers remains unverified

### Reading other Pods' `/proc`

- With its privileges, the Sensor could read process information exposed through `/proc` and filesystem directory listings from the tested root and non-root Pods
    - Some reads were denied when permissions could not be acquired, confirming that the Sensor's privileges enabled the verified reads
    - On the VPS, setting the Sensor's AppArmor profile to Unconfined allowed reads without changing the target Pods' AppArmor settings
- Package databases, namespace information, and IPv6 network information were not checked individually, so these results do not establish that package usage assessment works

### cgroup namespaces and container identification

- The tested Pods used private cgroup namespaces, which provide separate views of the cgroup hierarchy, and the current Sensor exited during normal startup because it requires the host namespace
    - Other processes' cgroup paths vary with the reader's position, so matching cannot rely on removing a fixed prefix
- Mounting the host cgroup hierarchy read-only at a separate location exposed the full hierarchy and allowed the Sensor's own cgroup to be identified through its member processes
    - The design will use this hierarchy to match Pod, container, and cgroup identities with member processes
- Native sidecars had separate cgroups within their Pods, while pause containers could not be distinguished from ordinary containers by path format alone
    - The main application must match against Kubernetes API container information to exclude pause containers
- The existing probe only understands Docker path formats, so cgroup matching failed even for targets whose reads succeeded
    - Access to the host hierarchy is verified, but Kubernetes container matching in KestreLynx is neither implemented nor verified

### AppArmor and stalled startup

The results and planned use of each Sensor AppArmor setting are as follows.

| Sensor AppArmor setting | Result | Planned use |
| --- | --- | --- |
| Default profile | On K3s on the VPS with AppArmor enabled, signals to itself were denied and startup stalled | Will not be used as the Sensor default |
| Unconfined | Startup, isolation self-checks, eBPF, and reads from target Pods succeeded, and startup also worked on a node without AppArmor | Default for the Sensor only |
| Dedicated profile | Startup and reads succeeded and self-checks confirmed that prohibited operations were denied, but startup failed on a node without AppArmor | Optional for clusters whose nodes all have AppArmor enabled |

- With the default profile, stacked AppArmor identity labels no longer matched its permissions, preventing capabilities and `no_new_privs` from being applied across all threads
    - The process kept consuming CPU with only some privileges, and neither the probe's watchdog nor normal termination requests stopped it, requiring forced Pod deletion
    - Label stacking did not occur with Docker on the same VPS, and reproduction in other environments remains unverified
- The dedicated profile allows signals to itself and operations for reading other processes
    - Whether kernel audit logs still contain denials under the dedicated profile remains unchecked
- Startup that keeps spinning without completing is a bug to fix by exiting within a bounded time with a clear error
    - Termination must not depend solely on the watchdog that failed here or on signals that may be denied

## Decisions

The following are design decisions informed by the validation results; Kubernetes implementation is still pending.

### Placement and evidence transfer

- The Sensor and relay container will each have a separate DaemonSet that places them on every target node
    - The Sensor will share the host PID namespace, while the relay container will receive neither host process visibility nor observation privileges
- The Sensor will write to a node-local evidence directory, and the relay container will access that directory read-only
    - The in-cluster main application will retrieve evidence from the relay container using TLS server authentication and a bearer token
    - The main application will independently validate received evidence before using it

### cgroup matching

- The requirement to use the host cgroup namespace will be removed only when Kubernetes mode is explicitly selected
- The host cgroup hierarchy will be mounted read-only at a separate location without overlaying the container's own hierarchy
    - Matching will use the host hierarchy and member processes instead of removing a fixed prefix from relative paths

### AppArmor and remaining isolation

- The Sensor will default to AppArmor Unconfined, with the dedicated profile optional for clusters whose nodes all have AppArmor enabled
    - The relay container and main application will retain their default AppArmor settings
    - This configuration leaves the Sensor without the AppArmor defense layer provided by Docker's default profile
- The observation component will retain the Docker permission and isolation restrictions
    - It will run as non-root and non-privileged, acquire only necessary permissions, and drop permissions needed only for eBPF preparation once that preparation is complete
    - After acquiring permissions, it will restrict further privilege acquisition and memory dumps and related access across all threads
    - Seccomp will restrict operations and prohibit Sensor communication even though the Pod has a network namespace
    - The root filesystem will remain read-only, with writes limited to the Sensor's own evidence
- Package database parsing will run in separate child processes without observation privileges
    - Landlock and seccomp will restrict file operations, communication, and program execution in the parser
- These isolation mechanisms restrict operations such as writes and communication but do not guarantee that the privileged observation component cannot read secrets in other Pods

## Unverified areas and next steps

- The initial implementation scope is Linux, cgroup v2, and containerd with runc, with the main application inside the cluster
    - This defines the implementation scope and does not mean that every configuration has been verified
- Implement container matching and verify that evidence is associated with the correct target
    - Identify ordinary containers and native sidecars across Pod QoS classes while excluding pause containers and the Sensor itself
    - Verify that differences in cgroup management and hierarchy, process movement, and identity reuse do not assign evidence to another container
    - Read package databases, namespace information, and IPv6 information, and associate usage, listening-socket, and privilege evidence
- Verify termination after stalled startup and differences between AppArmor environments
    - Implement termination when capabilities and `no_new_privs` cannot be applied across all threads
    - Check label stacking and read access on other distributions and kernels and with custom profiles on target Pods
    - Check the dedicated profile's audit logs, distribution, updates, and loading after restarts
- Implement the relay container and evidence transfer, and validate operation across multiple nodes
    - Check relay container isolation, retrieval using TLS and tokens, and evidence validation and storage
    - Verify that partial Sensor or relay container failures do not mix evidence or freshness between nodes
    - Measure traversal and transfer overhead and losses as Pod counts, cgroup counts, short-lived containers, and event volume increase
    - Verify seccomp profile compatibility with Sensor versions, updates, and rollback
- Implementation and these checks will proceed after operational validation of the Docker Runtime features is complete

## Update history

### October 3, 2026

- Recorded feasibility validation results

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
