---
title: Fix pull request contents and pre-merge checks
---

# Fix pull request contents and pre-merge checks

This page explains how to read pull requests created by KestreLynx and what you need to check before merging.
For Slack notifications, see [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks).

For every pull request, KestreLynx has not verified resolution in the completed image or in running containers after deployment.
Dependency installation and application operation are also unverified; see [Resolved findings in comparisons](#verification-results) for details.

For the terms used on this page, see [Terms](remediation.md#terms).

## Pull request contents and pre-merge checks {#pr-body-and-checks}

Pull request bodies describe the proposed changes, the results KestreLynx checked, and assumptions that require your confirmation.
You must perform the pre-merge checks in your own project.

For all pull requests, including Compose, Dockerfile, and language package updates, review the following.

- The changes and the checked results and unverified assumptions described in the pull request body
- The comparison targets and unverified aspects described in [Resolved findings in comparisons](#verification-results)
- The results of any CI checks requested in the pull request body

For npm, pnpm, uv, and pip, follow the pull request's instructions to check installation from the updated dependency files in your project's CI.
For the following pull request types, also perform the additional checks in each section.

| Pull request type | Section |
| --- | --- |
| Pull requests for Kubernetes | [Kubernetes pull requests](#kubernetes-pr-results) |
| Go dependency updates | [Go pull requests and CI checks](#go-pull-requests) |
| Maven dependency updates | [Maven pull requests and CI checks](#maven-pull-requests) |
| Gradle dependency updates | [Gradle pull requests and CI checks](#gradle-pull-requests) |

For pull requests containing only some of the planned updates, see [Partial PRs](remediation-update-results.md#partial-pull-requests).

### Kubernetes pull requests {#kubernetes-pr-results}

Kubernetes pull request bodies identify the changed files and containers, deployment implications of merging, and unverified assumptions.

For Kustomize and Helm values, set `workload` in `remediation.mappings` to the workload key of the container being mapped.
List other containers affected by the same change in `kustomize.affects` or `helm_values.affects`.

The container list in the pull request body combines the containers specified in `workload` and `affects`.
The following list covers manifest, Kustomize, Helm values, and Dockerfile pull requests.

- Common to Kubernetes pull requests (manifest, Kustomize, Helm values, and Dockerfile)
    - A warning that external automatic synchronization or CI may apply the change after merging, whether or not a management tool was detected
    - Management tools such as Argo CD, Flux, or Helm indicated by labels or annotations, with a statement that the actual management relationship is unverified
- Manifest, Kustomize, and Helm values pull requests
    - A warning that changes do not affect existing Jobs when CronJob or Job workloads are included
- Manifest pull requests
    - Workloads running the same image without a manifest mapping, and containers in the same Pod template that are not changed
- Kustomize and Helm values pull requests
    - Containers listed in `workload` and `affects`, and the subset verified as ordinary init containers
    - The scope of checks comparing the file with running images and looking for containers omitted from the list
- Kustomize pull requests
    - A statement that Kustomize was not rendered and that the change affecting no containers outside the list is unverified
- Helm values pull requests
    - A statement that Helm was not rendered and that the key holding the final value and the container list being complete are unverified
    - A statement that overrides from other values files, CI `--set`, or Argo CD `parameters`, `valuesObject`, or `valuesFrom`, and tag management by other tools, are unverified
    - Workloads with labels indicating Flux HelmRelease management, and a warning that unread HelmRelease `spec.values` may take precedence over the values file
    - A statement that use of the values file for deployment is unknown when neither a Helm release nor a Flux HelmRelease is detected
    - The reason for adding double quotes to a new tag when needed for Helm to read it as a string

For Kustomize and Helm values, KestreLynx assumes that you confirmed when configuring the mapping that `workload` and `affects` list every container affected by the change.

Before merging, identify the containers affected by the Kustomize configuration or Helm chart and values used for the actual deployment, and confirm that the pull request body lists all of them.
For details of the checks, see [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) and [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs).

For Helm values pull requests, check the values used for deployment in this order.

1. Confirm that the values file being changed is used for the actual deployment
2. Check overrides from other values files, CI `--set`, Argo CD `parameters`, `valuesObject`, and `valuesFrom`, and Flux HelmRelease `spec.values`
3. Confirm that the key changed by the pull request holds the final image value used for deployment

### Go pull requests and CI checks {#go-pull-requests}

Go pull requests propose updates to `go.mod` and `go.sum`.
The body includes the following information.

- Version checks against the public Go module proxy (`proxy.golang.org`) and hash verification against `sum.golang.org`
- Modules upgraded or added because the new versions of the update targets require them
- Changes to the `go` and `toolchain` lines, and the possibility that raising the `go` line changes language features or `GODEBUG` defaults
- `go.sum` lines that KestreLynx added from `sum.golang.org` records

Before merging, run builds and tests in your project's CI using the updated `go.mod` as it is.
Use the following command.

```sh
go build -mod=readonly ./... && go test -mod=readonly ./...
```

Do not run `go get`, `go mod tidy`, or a build with `-mod=mod` before this check, because they may rewrite the checked `go.mod`.
With `-mod=readonly`, the build stops if a required module is missing or its version is too low, so review the CI results before merging.

KestreLynx checks the versions written in `go.mod`.
For acceptance conditions, see [Go update validation](remediation-go-logic.md#go-update-validation); for unverified aspects, including builds and operation, see [Resolved findings in comparisons](#verification-results).

### Maven pull requests and CI checks {#maven-pull-requests}

Maven pull requests propose updates to `pom.xml`.
The body includes the following information.

- Changed files and edits to literal versions, properties, parent property overrides, or pins in `dependencyManagement`
- Version checks against Maven Central and dependency resolution and scan results from Trivy before and after the update
- Packages outside the targets whose resolved versions changed, and packages added or removed
- The fact that KestreLynx rewrote the POM without running Maven

Before merging, check Maven's resolved dependencies and run the build and verification in your project's CI.
For multi-module projects, run the following commands in the directory containing the root `pom.xml`.

```sh
mvn -B dependency:tree
mvn -B verify
```

Compare the dependency list with the target package names and adopted versions in the pull request body (versions confirmed in the updated dependency files).
Confirm that the update targets resolve to fixed versions.

Parent property overrides and `dependencyManagement` pins remain until removed.
Remove the overrides or pins added by the pull request when upgrading the parent POM to a version that specifies fixed versions of the target packages.

After removing the overrides or pins, confirm that the target packages still resolve to fixed versions.

KestreLynx checks Trivy's resolution of the POM files.
For acceptance conditions, see [Maven update validation](remediation-maven-logic.md#maven-update-validation); for unverified aspects, including builds and operation, see [Resolved findings in comparisons](#verification-results).

### Gradle pull requests and CI checks {#gradle-pull-requests}

Gradle pull requests propose updates to version declarations and `gradle.lockfile`.

The body includes the following information.

- Changed files and edits or overrides to catalogs, dependency declarations, and properties, or added constraints
- The Gradle version in the work container and the following checks on the `gradle.lockfile` that the work container updated and returned
    - No entries were removed
    - The locked configurations are unchanged
    - Each target is at or above the selected published version in every configuration where it was present
    - A `.pom` exists on Maven Central for every added or changed version
- Other packages whose versions come from the same property or catalog value and were checked against Maven Central
- Packages outside the targets whose locked versions changed, and packages added
- Trivy scan results before and after the update, and required pre-merge CI checks

Before merging, display the dependency list and run builds and tests in your project's CI using `gradle.lockfile` as it is.
Use the following command.

```sh
./gradlew dependencies && ./gradlew build
```

In the dependency list, check the target packages named in the pull request body in every configuration where they were present before the update.
In addition to successful builds and tests, confirm that each configuration resolves them to the versions recorded in the pull request's `gradle.lockfile` and that those are fixed versions.

Do not run `--write-locks` or `--update-locks` before this check, because they replace the checked `gradle.lockfile`.

Spring Boot BOM property overrides remain until removed.
Remove an override when upgrading the Spring Boot plugin to a version whose BOM specifies a fixed version of the target package.

Added constraints also remain until removed.
For an update target that a constraint requires at a fixed version or later, decide when to remove the constraint based on updates to the dependent package that requires the target.

Remove the added constraint when upgrading the dependent package to a version that requires a fixed version of the update target.
After removing the constraint, confirm that the update target still resolves to a fixed version.

KestreLynx checks the lockfile and scan results.
For acceptance conditions, see [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation); for unverified aspects, including builds and operation, see [Resolved findings in comparisons](#verification-results).

## Resolved findings in comparisons {#verification-results}

Resolved, Remaining, and Introduced in pull request bodies and Slack describe the results of comparing scans before and after an update.

The labels mean the following.

| Label | Meaning |
| --- | --- |
| `Resolved` | Findings detected in the baseline but not in the candidate |
| Remaining | Findings still present in the candidate |
| Introduced | Findings absent from the baseline but detected in the candidate |

The following table identifies the baseline and candidate for each type of update.

| Update type | Baseline | Candidate |
| --- | --- | --- |
| Published image | The running image | The image retrieved from the registry at the candidate tag |
| Base image (the image specified by Dockerfile `FROM`) | The image retrieved from the registry that the current `FROM` tag points to | The base image retrieved from the registry at the candidate tag |
| Language package | Dependency files retrieved from the repository before the update | Updated dependency files proposed in the pull request |

For base image comparisons, KestreLynx checks that the layers currently referenced by the `FROM` tag match the initial layers of the running image.
For details, see [Scan comparison conditions](remediation-logic.md#comparison-conditions).

For image tag and base image updates, the pull request body separates findings into the following categories.

| Category | Meaning | Display in the pull request body | Included in Slack and webhook counts |
| --- | --- | --- | --- |
| Targeted | Findings with a reported fixed version that the update aims to resolve | Resolved and remaining targeted findings | Included in Resolved and Remaining counts |
| Other | Findings outside the update targets, including those without a reported fixed version | Separate lists and counts from targeted findings | Excluded from targeted Resolved and Remaining counts |
| Introduced | Findings absent from the baseline but detected in the candidate | Separate lists and counts from targeted and other findings | Included in Introduced counts |

Dockerfile base image updates target findings attributed to the base image's layers.
They also include Node.js and Python runtime findings whose layer is unknown when the version environment variables match between the running image and the base image.

For details, see [Handling language runtime findings](remediation-base-image-logic.md#base-runtime-findings).
Other findings remaining in the candidate and introduced findings are displayed separately from resolved and remaining targeted findings.

Compose, Kubernetes manifest, Kustomize, and Helm values pull requests also show the count of other findings no longer detected in the candidate.
The list of other findings no longer detected is included only when such findings exist.

KestreLynx has not verified the following.

- Resolution in the completed image built from the changed Dockerfile
- Resolution in running containers after deployment
- Actual dependency installation using the updated dependency files
- Successful application builds, tests, or operation

!!! note "Resolved findings and runtime state"

    Resolved in a pull request or Slack is a comparison result.
    It does not mean that findings have been resolved in the rebuilt image or in running containers after deployment.

For the checks and acceptance conditions for each update type, see [Verification scope by target](remediation-logic.md#verification-scope).
