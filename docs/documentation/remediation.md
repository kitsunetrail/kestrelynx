# Remediation plans and pull requests

!!! warning "Experimental feature"

    Remediation plans and fix pull requests are experimental features. Their configuration, notifications, and PR formats may change.

## Overview {#overview}

Remediation plans propose image and dependency updates based on findings in running images.
Enabling fix pull requests also creates PRs for eligible updates to files in the GitHub repositories specified in your configuration.

Proposals and PR states appear in the Slack “Fix plan” section.
See [Terms](#terms) for the terminology used on this page.

When you run a ready-made image as provided, its published image tag is the update target.
When you build from your own source, configure the Dockerfile base image and dependency files as update targets, whether or not you push the resulting image to a registry.

The table shows what each plan proposes and which files a fix PR can change when enabled.

| Update target | Example | What the plan shows | Fix PR |
| --- | --- | --- | --- |
| Published image with a pinned tag | `nginx:1.27.0` | Candidate tags and scan comparisons | Tag changes in Compose files, Kubernetes manifests, Kustomize files, or Helm values |
| Published image with a floating tag | `latest` | Guidance on pulling new content for the same tag | No PR |
| Dockerfile base image | `FROM python:3.12.3-slim` | Base image candidates and scan comparisons | Pinned tag changes in the Dockerfile’s `FROM` |
| Language packages (npm, pnpm, pip, uv, Go, Maven, Gradle) | `pnpm-lock.yaml`, `pom.xml` | Package update candidates | Dependency file changes |

For containers started with `docker run`, fix PRs can update Dockerfiles and dependencies.
They do not change the image tag used to start the container.

The following excerpt shows a Slack notification after creating a dependency update PR.
This fictional example shows the file to change, the PR number, and the versions before and after the update.

```text
🔧 Fix plan

Image: example/app:latest
File to change: pnpm-lock.yaml in example/application
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
```

See [Reading notifications](remediation-results.md) for field meanings, counts, and where to find detailed results.

KestreLynx performs different work depending on whether only plans or fix PRs are enabled.
The table also shows the work you perform.

| Enabled feature | What KestreLynx does | What you do |
| --- | --- | --- |
| Plans only | Selects candidates, reads the configured Compose files, Dockerfiles, dependency files, or other files on GitHub, and compares image scan results | Review proposals, pull or build images, deploy, and check the deployment |
| Fix PRs also enabled | Also updates and checks language packages, and creates and manages PRs for eligible changes | Review and merge changes, pull or build images, deploy, and check the deployment |

With plans only, KestreLynx does not run package managers or write to GitHub.
For details, see [Execution scope of plans and PRs](remediation-logic.md#plan-and-pr-execution).

Remediation plans and fix PRs are available in Docker mode (including Compose and `docker run`) and Kubernetes mode.
GitHub is the only supported source host, and language packages must come from public registries.

See [Scope and requirements](remediation-reference.md#scope-and-requirements) for environment requirements and supported update targets.

## Terms {#terms}

This table defines the shared terminology referenced by the pages in this chapter.

| Term | Meaning |
| --- | --- |
| Finding | A vulnerability detected by scanning |
| Running image | An image used by a running container |
| Published image | A ready-made image pulled from a registry and run as provided |
| Base image | An image specified by `FROM` in a Dockerfile |
| Pinned tag | A tag specifying a complete version, such as `1.27.0` |
| Floating tag | A tag whose content can change, such as `latest` or `22-alpine` |
| Series (image tags) | Versions whose image tags share the same major, minor, prefix, and suffix |
| Mapping | An entry in `remediation.mappings` that links running containers to files in a GitHub repository |
| Workload key | The value in a mapping’s `workload` that identifies a Compose service, Docker container, or Kubernetes container |
| Fixed version | A version reported by vulnerability information to fix the vulnerability |
| Running version | The version detected in the running image |
| Update target | The minimum version used when selecting an update |
| Adopted version | The version confirmed in the dependency files after an update |
| Manual handling | An update left to your judgment without automatic changes by KestreLynx (value: `manual`; Slack: “Needs a decision”) |
| Deferred | Processing postponed to a later cycle because of limits, waiting periods, or similar conditions (value: `deferred`; Slack: “Deferred”) |
| Work container (work Pod) | A disposable container created by KestreLynx to run a package manager (a work Pod on Kubernetes) |
| Cycle | One regularly scheduled run from scanning through notification |

## Page guide {#contents}

This guide lists the pages to read when getting started and pages to consult by topic.
When getting started, read in this order.

1. Read the [Overview](#overview) to understand the proposals and your responsibilities
2. Read [Common preparation](remediation-setup.md), then follow the [Docker](remediation-setup-docker.md) or [Kubernetes](remediation-setup-kubernetes.md) setup steps for the environment you monitor
3. Read [Reading notifications](remediation-results.md) to check proposals and PR states

The following pages cover the overview and setup steps to read when getting started.

| What you want to know | Page |
| --- | --- |
| Feature overview and your responsibilities | [Remediation plans and pull requests (overview)](#overview) |
| Shared settings needed to enable remediation | [Common preparation](remediation-setup.md) |
| Setup for Compose and docker run | [Docker](remediation-setup-docker.md) |
| Setup for Kubernetes | [Kubernetes](remediation-setup-kubernetes.md) |
| Configuring disposable Pods that run package managers on Kubernetes | [Kubernetes work Pods](remediation-setup-work-pods.md) |

Read the notification guide to check results when getting started.
The following pages also cover update results, PR checks, and troubleshooting.

| What you want to know | Page |
| --- | --- |
| Slack fields and where to find detailed results | [Reading notifications](remediation-results.md) |
| Update results and guidance such as “Re-pull” and “Rebuild” | [Reading update results and guidance](remediation-update-results.md) |
| PR descriptions and checks before merging | [PR contents and checks before merging](remediation-pr-results.md) |
| Why an update cannot reach a version reported to fix a vulnerability | [Guidance when a fixed version cannot be reached](remediation-fix-hints.md) |
| Collecting diagnostics and checking plan, update, PR, or record problems | [When no candidate or PR appears](remediation-troubleshooting.md) |

Use the following pages when you need details of candidate selection and PR processing.

| What you want to know | Page |
| --- | --- |
| Execution scope of plans and PRs, and comparison conditions | [Processing flow](remediation-logic.md) |
| How published image candidates are selected | [Published images](remediation-image-logic.md) |
| Changes to manifests, Kustomize files, and Helm values | [Kubernetes tag update PRs](remediation-kubernetes-logic.md) |
| How Dockerfile update candidates are selected | [Base images](remediation-base-image-logic.md) |
| Package candidate and runtime selection, and acceptance of update results | [Common rules for language packages](remediation-package-logic.md) |
| Rules for Node.js and Python dependency updates | [npm, pnpm, uv, pip](remediation-node-python-logic.md) |
| Updates that also change packages depending on the target | [Re-resolution through dependent packages](remediation-reresolution-logic.md) |
| Go module update candidates and checks | [Go](remediation-go-logic.md) |
| Maven update candidates and checks | [Maven](remediation-maven-logic.md) |
| Gradle update candidates and checks | [Gradle](remediation-gradle-logic.md) |
| How disposable containers run package managers | [Work containers](remediation-worker-logic.md) |
| Handling existing PRs and recording PR processing | [PR management and records](remediation-pr-logic.md) |

Use the following pages to look up supported features, file constraints, result values, and reason codes.

| What you want to know | Page |
| --- | --- |
| Supported environments, update targets, and runtimes | [Scope and requirements](remediation-reference.md) |
| Accepted syntax in Compose files, manifests, Kustomize files, Helm values, and Dockerfiles | [Formats of files specifying images](remediation-source-formats.md) |
| Requirements for dependency files and version declarations | [Dependency file and version declaration formats](remediation-dependency-formats.md) |
| Result values and reasons processing did not proceed | [Result values and reason codes](remediation-reason-codes.md) |
| Reasons related to image candidate selection and files to change | [Image and source reason codes](remediation-image-reason-codes.md) |
| Reasons package updates or PR processing did not proceed | [Update and PR processing reason codes](remediation-update-reason-codes.md) |

Related configuration and specifications are on the following pages.

- [Configuration: Remediation plans and pull requests](configuration.md#remediation)
- [How KestreLynx works: Scan notification conditions](notification-conditions.md#notification-conditions)
- [How KestreLynx works: Common remediation plan fields](webhook-remediation-reference.md#remediation-fields)
- [How KestreLynx works: Communication destinations](outbound-communication.md#outbound-communication)
