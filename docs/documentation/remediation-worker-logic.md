---
title: Work container execution
---

# Work container execution

KestreLynx uses work containers for npm, pnpm, pip, uv, Go, Gradle, and Rust updates, running them as work Pods on Kubernetes.

Maven updates do not use a work container.
See [Maven package selection](remediation-maven-logic.md#maven-package-selection) for Maven processing.

An update proceeds through the following steps.

1. Prepare the image to use
2. Create a work container or Pod
3. Transfer the input files
4. Run the update with the package manager
5. Collect the result for validation before acceptance
6. Attempt to delete the work container or Pod

See [Terms](index.md#terms) for the terminology used on this page.

## Work container execution {#worker-execution}

KestreLynx checks the image and inputs, then runs the update in a work container with restricted privileges and resources.
See [Work Pod execution](#kubernetes-work-pods) for the Kubernetes checks before and after creation.

### Pinning official images {#worker-images}

Work containers use the official Node.js, Python, Go (`golang`), Gradle (`gradle`), and Rust (`rust`) images.
The runtime table records the execution version, official image pinned by digest, and end-of-support date for each Node.js, Python, Go, Gradle, and Rust series used for language package updates.

The image contents are pinned by digest (a value identifying image contents), as recorded in the runtime table.

Changes to the contents of the same tag are not followed.

The runtime table is supplied with KestreLynx and replaced by newer published tables.
See [Updating the runtime table](#runtime-table-updates) for the conditions for fetching and replacing it.

The following conditions apply to fetching and using images.

- Docker itself or software such as containerd on Kubernetes nodes fetches the required images
- A mirror must provide the contents with the same digest as recorded in the runtime table
- Gradle images are pinned by digest for each Gradle version and JDK combination, and only combinations that passed integration tests on the execution platform are used
- Rust uses an official `rust` image that passed integration tests on the execution platform

If an image cannot be fetched, the language package update is deferred (`deferred`) to a later cycle.
A fetch failure does not cause the package manager to run inside KestreLynx's own container instead.

See [Work container configuration](configuration.md#remediation-worker) to configure the image source.

### Updating the runtime table {#runtime-table-updates}

When remediation planning and fetching the runtime table are enabled, KestreLynx fetches the published table and replaces the table in use if the published one is newer.
Fetching the table is enabled by default.

1. At startup and at the start of each scan cycle, fetch the table from tag `1` of `ghcr.io/kitsunetrail/kestrelynx-runtimes`
2. Check size and count limits, that images are the official Docker Hub `node`, `python`, `golang`, `gradle`, and `rust` images, digest and version formats, consistency between series and versions, and the update time
3. Save a table that passes the checks and has a newer update time than the table in use to `runtimes/table-1.json` under `remediation.storage_dir`
4. Replace the entire table with the successfully saved table, without mixing it with the table supplied with KestreLynx

A table with an update time 24 hours or more in the future is not used.
Rows with runtime types that the KestreLynx in use does not recognize, or names it cannot interpret, are skipped; other rows are used.

Work containers restrict writable locations to temporary storage with size limits.
To do this, KestreLynx replaces locations in the image that anyone can write to, or that are declared as volumes (data storage areas), with temporary storage.

The locations that can be replaced with temporary storage depend on the KestreLynx in use.
If a row requests replacement of another location, that row is also skipped while other rows are used.

If fetching, checking, or saving fails, KestreLynx continues using the current table and logs a warning.
The cycle continues, and the table does not change during a cycle.

Saved tables are also checked, and the table to use is selected as follows.

| Situation | Table used |
| --- | --- |
| No saved table at startup | Table supplied with KestreLynx |
| Saved table is newer than the supplied table at startup | Saved table that passes the checks |
| Saved table is not newer than the supplied table at startup | Table supplied with KestreLynx |
| Fetched table is newer than the current table and passes the checks | Fetched table, if saving succeeds |
| Fetching or checking fails | Table currently in use |
| Fetching is disabled | Table supplied with KestreLynx; saved tables are not used |

At startup and when replacing the table, KestreLynx logs its source (supplied, saved, or fetched) and update time.
When replacing it, KestreLynx logs each added row, removed row, and row with a changed version on a separate line.

The following changes are delivered through table updates or require a KestreLynx update.

| Change | Delivered by a table update | Requires a KestreLynx update |
| --- | --- | --- |
| Execution versions and pinned digests for existing series | Yes | No |
| pip versions | Yes | No |
| Dates such as end-of-support dates | Yes | No |
| New Node.js, Python, Go, and Rust series whose version formats the KestreLynx in use supports | Yes | No |
| New Gradle version and JDK combinations whose version formats the KestreLynx in use supports | Yes | No |
| Row removal | Yes | No |
| Support for additional Gradle plugins, such as Spring Boot | No | Yes |
| Interpretation of `lts/<new-name>` in `.nvmrc` | No | Yes |
| New language types | No | Yes |
| Unsupported version formats, such as Python 4 | No | Yes |
| Additional locations that can be replaced with temporary storage | No | Yes |

Gradle uses only version and JDK combinations that passed integration tests on the execution platform.
Being listed alone does not make a combination usable.

See [Work container configuration](configuration.md#remediation-worker) to disable fetching or change the source, and [Runtime table downloads](outbound-communication.md#runtime-table-download) for destinations and credentials.

### Removing unused work images {#worker-image-cleanup}

On Docker, at the start of each cycle, KestreLynx removes work images it fetched itself that the current runtime table no longer uses.

- Record images before fetching them in `runtimes/pulled-images.json` under `remediation.storage_dir`, and consider only successfully fetched images for removal
- Do not remove an image that also has a tag, and exclude it from future removal
- Exclude a reference that Docker already held for another platform before fetching
- Keep images used by containers and retry in the next cycle
- Do not force removal
- If the record has reached 1,024 entries or cannot be written, do not fetch the work image and defer the language package update

On Kubernetes, KestreLynx does not remove images and leaves their management to the node's container runtime.

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
| Rust | `Cargo.lock`, the root and member `Cargo.toml` files, and empty files at the build target paths |

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
| Root filesystem except for Rust | Restrict non-root writes through ownership, permissions, and temporary mounts without setting the root filesystem itself to read-only | Set it to read-only |
| Root filesystem for Rust | Set it to read-only | Set it to read-only |
| Process count | Enforce the container PID limit | Enforce the node-side PID limit |

The operations executed during an update differ by manager.

| Manager | Operations executed |
| --- | --- |
| npm, pnpm, pip, uv | Update dependencies with package scripts and source builds disabled |
| Go | Update dependencies with the official image's `go` command |
| Gradle | Execute the project's build scripts and permitted plugin code, updating the lockfile with `dependencies --update-locks` |
| Rust | Update each target dependency in turn with Cargo from the official image ([Rust execution settings](remediation-cargo-logic.md#cargo-worker-settings)) |

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

For npm, pnpm, uv, and Go, it collects the dependency files listed in [Container inputs](#worker-inputs), excluding pnpm's `pnpm-workspace.yaml`.
For pip, it collects `requirements.txt` and the dependency resolution report.

See [Gradle worker settings](remediation-gradle-logic.md#gradle-worker-settings) for the files collected from Gradle.
For Rust, KestreLynx collects all input files after each operation and again at the end.

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
