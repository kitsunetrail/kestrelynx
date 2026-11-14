---
title: Remediation support scope
---

# Remediation support scope

Use this page to check supported environments, update targets, input files, and runtimes for remediation plans and pull requests.
For setup, see [Enabling remediation plans](remediation-setup.md#enable-fix-plans).

To look up a file type, start with [Supported input formats](#supported-inputs).
Use the following sections to find what you need.

| What you want to check | Section |
| --- | --- |
| Environments and update targets | [Scope and requirements](#scope-and-requirements) |
| File syntax | [Supported input formats](#supported-inputs) |
| Runtime versions | [Supported runtimes](#supported-runtimes) |

For the terms used on this page, see [Terms](remediation.md#terms).

## Scope and requirements {#scope-and-requirements}

This section shows which targets can have update candidates in a plan and which files remediation pull requests can update.

### Supported environments {#supported-environments}

The table lists operating requirements and requirements for work containers.

| Item | Requirement |
| --- | --- |
| Container environment | Plans and PR creation supported in Docker and Kubernetes modes |
| Source host | GitHub |
| Work container architecture | Linux `amd64` and `arm64` (see the [Supported runtimes](#supported-runtimes) for Gradle restrictions) |
| Runtime for language updates | Versions in [Supported runtimes](#supported-runtimes) |
| Sensor | Not required |

The table shows the target and files you can specify for each environment.

| Running target | `workload` syntax | Files you can map |
| --- | --- | --- |
| Compose service | `compose/<project>/<service>` | Compose (`compose`), Dockerfile (`dockerfile`), dependency directory (`dependencies`) |
| Docker container without Compose | `container/<name>` | Dockerfile (`dockerfile`), dependency directory (`dependencies`) |
| Kubernetes container | `<kind>/<namespace>/<name>/<container>` | Manifest (`manifest`), Kustomize (`kustomize`), Helm values (`helm_values`), Dockerfile (`dockerfile`), dependency directory (`dependencies`) |

For the dependency directory, specify the directory containing dependency declarations and lockfiles.
For the files and directory scope each manager reads, follow its link in [Supported input formats](#supported-inputs).

Across all mappings with the same `workload`, use only one of `manifest`, `kustomize`, or `helm_values` to manage Kubernetes image tags.
For the syntax of each value, see [Source mappings](configuration.md#remediation-mappings).

The table shows Kubernetes plan contents, files a PR can update, and whether a work Pod is required.

| Update target | Plan | PR | Work Pod required |
| --- | --- | --- | --- |
| Published image | Update candidates | Image tag in a plain manifest | No |
| Published image (Kustomize) | Update candidates | `images[].newTag` | No |
| Published image (Helm values) | Update candidates | Image tag in values | No |
| Dockerfile base image | Update candidates | Dockerfile `FROM` | No |
| Re-pulling a floating tag | Re-pull guidance | No PR | No |
| Maven dependencies | Update candidates | `pom.xml` | No |
| npm, pnpm, pip, uv, Go, and Gradle dependencies | Update candidates | Dependency files for each tool | Yes |

For updates that require a work Pod, see [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates).

### docker run containers {#docker-run-containers}

A `container/<name>` mapping supports updates to Dockerfile base images and dependencies.
It does not create PRs to change the image tag specified when starting the container.

Targets are checked under the following conditions in each cycle.

- Targets are containers running when the container list is retrieved in each cycle
- Short-lived jobs run with `--rm` may not be included
- Renamed or recreated containers are reflected from the next cycle, and renaming also requires changing the mapping's `workload`

Set the run time with `schedule.daily_at`; if omitted, execution is every 24 hours (see [Schedule](configuration.md#schedule)).
How an old container still running after its tag is reassigned is handled depends on the operation and image store.

| Operation | Image store | Handling of the old container |
| --- | --- | --- |
| Run `docker build` again with the same tag | containerd image store enabled | Excluded from scans and remediation plans because the old image is removed |
| Run `docker build` again with the same tag | containerd image store disabled (overlay2) | Included in scans and remediation plans because the old image remains |
| Reassign a tag with `docker tag` | containerd or overlay2 | Included in scans and remediation plans |

If the containerd image store removes the old image, recreating the container with the new image makes it eligible.
For configuration examples, see [Mapping docker run containers](remediation-setup-docker.md#docker-run-mappings).

### Supported targets {#supported-targets}

The table shows where each update target is obtained and when a source mapping becomes necessary.

| Update target | Where specified or target file | Source | Source mapping |
| --- | --- | --- | --- |
| Published image | Image specified when starting a container | Public registries and private registries with authentication configured | Required for PRs |
| Base image | Image specified in a Dockerfile's `FROM` instruction | Public registries and private registries with authentication configured | Required for plans |
| npm and pnpm dependencies | Dependency directory | Public npm registry | Required for plans |
| pip and uv dependencies | Dependency directory | Public PyPI | Required for plans |
| Go dependency modules | Dependency directory | Public Go module proxy (`proxy.golang.org`) and `sum.golang.org` | Required for plans |
| Maven dependencies | `pom.xml` | Maven Central | Required for plans |
| Gradle dependencies | `gradle.lockfile` | Maven Central | Required for plans |

Published image comparison results do not require a mapping, but PRs require a mapping to Compose, Kubernetes manifests, Kustomize, or Helm values.
Base image plans require a Dockerfile or Compose mapping, and dependency plans require a dependency directory mapping.

Private npm registries, private PyPI repositories, and private Go modules cannot be update targets.
Image registry credentials are not used to obtain dependencies.

## Supported input formats {#supported-inputs}

The table links each file type to the section describing supported syntax and update scope.

| File | Format description |
| --- | --- |
| Compose file | [Compose formats](remediation-source-formats.md#compose-formats) |
| Kubernetes manifest | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| Kustomize file | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| Helm values file | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| Dockerfile | [Dockerfile formats](remediation-source-formats.md#dockerfile-formats) |
| `package.json` and `package-lock.json` | [npm dependency files](remediation-dependency-formats.md#npm-inputs) |
| `package.json`, `pnpm-lock.yaml`, and `pnpm-workspace.yaml` | [pnpm dependency files](remediation-dependency-formats.md#pnpm-inputs) |
| `requirements.txt` | [pip dependency files](remediation-dependency-formats.md#pip-inputs) |
| `pyproject.toml` and `uv.lock` | [uv dependency files](remediation-dependency-formats.md#uv-inputs) |
| `go.mod` and `go.sum` | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `pom.xml` | [Maven dependency files](remediation-dependency-formats.md#maven-inputs) |
| `gradle.lockfile`, build scripts, and related files | [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) |
| `.nvmrc`, `.node-version`, and `package.json` | [Node.js version declarations](remediation-dependency-formats.md#node-declarations) |
| `.python-version` and `pyproject.toml` | [Python version declarations](remediation-dependency-formats.md#python-declarations) |
| `package.json` and `pyproject.toml` | [Tool version declarations](remediation-dependency-formats.md#tool-declarations) |

## Supported runtimes {#supported-runtimes}

This is the list of supported versions built into KestreLynx, showing supported release lines, execution versions, and end-of-support dates.
The Node.js, Python, and Go runtimes used to update dependencies are selected from the supported release lines in this list.

| Release line | Execution version | End of support | platform |
| --- | --- | --- | --- |
| Node.js 22 | `22.23.5` | 2027-04-30 | `linux/amd64` and `linux/arm64` |
| Node.js 24 | `24.22.3` | 2028-04-30 | `linux/amd64` and `linux/arm64` |
| Node.js 26 | `26.13.1` | 2029-04-30 | `linux/amd64` and `linux/arm64` |
| Python 3.11 | `3.11.18` | 2027-10-31 | `linux/amd64` and `linux/arm64` |
| Python 3.12 | `3.12.16` | 2028-10-31 | `linux/amd64` and `linux/arm64` |
| Python 3.13 | `3.13.18` | 2029-10-31 | `linux/amd64` and `linux/arm64` |
| Python 3.14 | `3.14.10` | 2030-10-31 | `linux/amd64` and `linux/arm64` |
| Python 3.15 | `3.15.2` | 2031-10-31 | `linux/amd64` and `linux/arm64` |
| Go 1.26 | `1.26.11` | 2027-02-10 | `linux/amd64` and `linux/arm64` |
| Go 1.27 | `1.27.4` | 2027-08-19 | `linux/amd64` and `linux/arm64` |
| Gradle 8 / JDK 21 | `8.14.6` | No end date configured | `linux/amd64` |
| Gradle 9 / JDK 17 and 21 | `9.8.2` | No end date configured | `linux/amd64` |

These versions and dates are information maintained by KestreLynx and change with KestreLynx updates.
Gradle supports only `linux/amd64` with the execution versions and JDKs listed in the table.

Other Gradle versions, JDKs, or platforms require manual handling.
The reason code is `gradle_version_unsupported` or `gradle_toolchain_unsupported`.

The KestreLynx developers run the Gradle integration tests and record the passing image digests in the supported version list.
Users do not need to add or configure these records; KestreLynx uses only images with a record for the execution platform.

The table shows the default runtime for each purpose and when declarations determine the selection.

| Purpose | Default runtime |
| --- | --- |
| npm or pnpm updates without a Node.js declaration | Latest release line in LTS (currently Node.js 26) |
| Work container for pip updates | Python 3.13 |
| uv updates | Selected from Python declarations |
| Go updates | See [Go runtime selection](remediation-go-logic.md#go-runtime-selection) |
| Gradle updates | Same Gradle version as the wrapper, with the JDK specified by the toolchain (21 if undeclared) |

Without a Node.js declaration, the current first candidate is Node.js 26, which entered LTS on 2026-10-28.
If it does not meet the package manager's compatibility requirements, other supported release lines are checked from newest to oldest.

For detailed selection conditions, see [Node.js selection](remediation-node-python-logic.md#node-selection).

The following release lines remain in the supported version list but have reached the end of support.

| Release line past end of support | End of support |
| --- | --- |
| Node.js 20 | 2026-04-30 |
| Python 3.9 | 2025-10-31 |
| Python 3.10 | 2026-10-01 |

Release lines past their support deadline are not used for updates.
For selection conditions, see [Runtime selection](remediation-package-logic.md#runtime-and-tool-versions).
