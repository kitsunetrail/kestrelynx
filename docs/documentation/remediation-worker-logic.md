---
title: Work container execution
---

# Work container execution

KestreLynx uses work containers for npm, pnpm, pip, uv, Go, and Gradle updates, running them as work Pods on Kubernetes.

Maven updates do not use a work container.
See [Maven package selection](remediation-maven-logic.md#maven-package-selection) for Maven processing.

An update proceeds through the following steps.

1. Prepare the image to use
2. Create a work container or Pod
3. Transfer the input files
4. Run the update with the package manager
5. Collect the result for validation before acceptance
6. Attempt to delete the work container or Pod

See [Terms](remediation.md#terms) for the terminology used on this page.

## Work container execution {#worker-execution}

KestreLynx checks the image and inputs, then runs the update in a work container with restricted privileges and resources.
See [Work Pod execution](#kubernetes-work-pods) for the Kubernetes checks before and after creation.

### Pinning official images {#worker-images}

Work containers use the official Node.js, Python, Go (`golang`), and Gradle (`gradle`) images.
Their contents are pinned by digest, a value identifying image contents, using the list built into KestreLynx under [Supported runtimes](remediation-reference.md#supported-runtimes).

Changes to the contents of the same tag are not followed.
The pinned contents and supported runtime versions change with KestreLynx updates.

The following conditions apply to fetching and using images.

- Docker itself or software such as containerd on Kubernetes nodes fetches the required images
- A mirror must provide the contents with the same digest as the list of supported versions
- Gradle images are pinned by digest for each Gradle version and JDK combination, and only combinations that passed integration tests on the execution platform are used

If an image cannot be fetched, the language package update is deferred (`deferred`) to a later cycle.
A fetch failure does not cause the package manager to run inside KestreLynx's own container instead.

See [Work container configuration](configuration.md#remediation-worker) to configure the image source.

### Container inputs {#worker-inputs}

Before the update starts, KestreLynx places the target dependency files, related configuration files, its work program, and fetched and verified tools in the container.
The work program is supplied with KestreLynx and runs the package manager and assembles the result inside the container.

KestreLynx passes only the files accepted as inputs for each manager, rather than the entire repository.

Representative dependency and configuration files passed to each manager are listed below.

| Manager | Example input files |
| --- | --- |
| npm | `package.json`, `package-lock.json` |
| pnpm | `package.json`, `pnpm-lock.yaml`, and `pnpm-workspace.yaml` when present |
| pip | `requirements.txt` |
| uv | `pyproject.toml`, `uv.lock` |
| Go | `go.mod`, `go.sum` |
| Gradle | `gradle.lockfile`, `build.gradle` or `build.gradle.kts`, `settings.gradle` or `settings.gradle.kts`, and `gradle.properties`, among others |

See [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) for the input list and conditions, including catalog and wrapper configuration.

Files outside the accepted inputs, such as `.npmrc` and `pip.conf`, are not passed.
There is no general removal of secrets, such as those in comments, from accepted input files.

The work program, tools, and credentials held by KestreLynx are handled as follows.

| Input type | Handling |
| --- | --- |
| Work program and tools | Verify the contents before passing them |
| GitHub token and image registry credentials | Do not pass them |
| KestreLynx configuration file and Docker socket | Do not pass them |

See [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) for tool checks and [Credential destinations](outbound-communication.md#credential-destinations) for where credentials are sent.

### Runtime restrictions {#worker-restrictions}

Work containers restrict privileges, resources, writable locations, and execution.

The following restrictions apply to both Docker and Kubernetes.

- Run as non-root, drop all Linux capabilities, and set `no-new-privileges`
- Limit memory, CPU, output volume, and execution time
- Restrict writable locations to temporary storage with size limits
- Verify that the runtime, tools, and work program match the specified contents

Docker and Kubernetes restrict the root filesystem and process count differently.

| Restriction | Docker | Kubernetes |
| --- | --- | --- |
| Root filesystem | Restrict non-root writes through ownership, permissions, and temporary mounts without setting the root filesystem itself to read-only | Set it to read-only |
| Process count | Enforce the container PID limit | Enforce the node-side PID limit |

The operations executed during an update differ by manager.

| Manager | Operations executed |
| --- | --- |
| npm, pnpm, pip, uv | Update dependencies with package scripts and source builds disabled |
| Go | Update dependencies with the official image's `go` command |
| Gradle | Execute the project's build scripts and permitted plugin code, updating the lockfile with `dependencies --update-locks` |

Executed build scripts must stay within the scope described in [Build script syntax](remediation-dependency-formats.md#gradle-build-forms).

The plugins KestreLynx permits Gradle to execute are defined in [Plugin allowlist](remediation-dependency-formats.md#gradle-plugins).
External plugins must match a permitted combination of plugin ID, plugin version, and Gradle version.

See [Go execution settings](remediation-go-logic.md#go-worker-settings) and [Gradle worker settings](remediation-gradle-logic.md#gradle-worker-settings) for manager-specific execution settings, and [Processing limits](configuration.md#remediation-limits) for workload limits.

Docker uses a bridge network without restricting destinations through a network allowlist.
On Kubernetes, users apply a NetworkPolicy; the supplied example denies ingress and limits egress to DNS and IPv4 TCP 443 destinations outside specified ranges.

See [Work container network](outbound-communication.md#worker-network) for the scope of access to public HTTPS sites, excluded addresses, and CNI requirements and limitations.

### Result collection {#worker-results}

Result collection retrieves the updated files and checks whether their contents can be used to decide acceptance.

On Docker, unencrypted results are collected from standard output.
On Kubernetes, results encrypted with a key for each execution are collected from Pod logs and decrypted.

After collection, KestreLynx attempts to delete the work container or Pod and validates the result contents.
Pod logs contain only the encrypted result and fixed status messages.

KestreLynx determines the files to collect for each manager and includes them in the instructions sent to the work container.
Users do not need to specify output files.

For npm, pnpm, uv, and Go, it collects the dependency files listed in [Container inputs](#worker-inputs), excluding pnpm's `pnpm-workspace.yaml`.
For pip, it collects `requirements.txt` and the dependency resolution report.

See [Gradle worker settings](remediation-gradle-logic.md#gradle-worker-settings) for the files collected from Gradle.

The following checks precede the acceptance decision.

- Check the consistency of returned files, sizes, hashes, executed operations, and exit status
- Reject files outside the collection scope specified by KestreLynx and contents that contradict the result record

If a collected result is returned together with a deletion error, KestreLynx records the deletion failure and continues validation.
A deletion failure alone does not block PR creation; acceptance still depends on the usual checks of result contents and exit status.

Deletion of containers or Pods that could not be removed is retried during subsequent cleanup.

## Work Pod execution {#kubernetes-work-pods}

On Kubernetes, language package updates run in disposable Pods in the configured work namespace.
Work Pods are also used for [Re-resolution through dependent packages](remediation-reresolution-logic.md#dependent-reresolution) by supported managers.

Users apply the required resources by following [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates).
A ValidatingAdmissionPolicy restricts the specifications of Pods that may be created.

Within the Pod, the receiving container places the input files first, and the work container then runs the update.

KestreLynx performs the checks and execution in the following order.

1. In each cycle that updates language packages, use trial creation without persisting Pods (`dryRun`) to verify that compliant Pods are accepted and violating Pods are rejected
2. Create the work Pod and verify that the created Pod matches the requested specification
3. Transfer the files described in [Container inputs](#worker-inputs) through the receiving container in the verified Pod
4. Run the update in the restricted environment and [collect the result](#worker-results) from Pod logs
5. Attempt to delete the Pod after processing

Remaining Pods are removed at startup and during periodic cleanup.
See [Runtime restrictions](#worker-restrictions) for privilege and writable-location restrictions.

The reason and handling for an update that cannot proceed depend on the failed check or limit.

| Situation | Reason code | Handling |
| --- | --- | --- |
| Pod creation rules cannot be verified | `work_admission_unverified` | Manual handling |
| The cluster version cannot be retrieved | `work_admission_unverified` | Deferred |
| Pod count or resource limits are reached | `work_pod_limit` | Deferred |

Deferred updates are retried in later cycles, and Pod creation rules are rechecked in each cycle that updates language packages.
For manual handling, check the required resources in [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates); for Pod counts and related settings, see [Kubernetes work container configuration](configuration.md#remediation-worker-kubernetes).
