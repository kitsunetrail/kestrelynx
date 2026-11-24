---
title: Fix pull request contents
---

# Fix pull request contents

This page explains what the bodies of pull requests created by KestreLynx contain.
For Slack notifications, see [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks); for terminology, see [Terms](index.md#terms).

## Pull request contents {#pr-body-and-checks}

Pull request bodies have three sections: “What”, “Change”, and “Verification”.
Kubernetes pull requests also include the “What this change relies on” and “After merging” sections described in [Kubernetes pull requests](#kubernetes-pr-results) (only “After merging” for Dockerfile pull requests).

The example below shows a Compose pull request body.

> **What**
>
> KestreLynx proposes a new image tag for 2 Compose service(s) in `compose.yml` of `example/app`.
>
> - Running image: `nginx:1.25.3`
> - Services edited: `web`, `worker`
> - Workloads running them: `compose/app/web`, `compose/app/worker`
> - Also running this image, not edited (no Compose mapping): `app/extra (app-extra-1)`, `loose`
>
> **Change**
>
> - `services.web.image`: `nginx:1.25.3` to `nginx:1.25.4`
> - `services.worker.image`: `nginx:1.25.3` to `nginx:1.25.4`
>
> **Verification**
>
> - Running: `nginx:1.25.3`
>     - Config digest: `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
>     - Platform: `linux/amd64`
>     - The running digest comes from the container runtime; whether it is the image config digest or an index or manifest digest is not confirmed.
> - Candidate: `nginx:1.25.4`
>     - Tag digest: `sha256:1111111111111111111111111111111111111111111111111111111111111111`
>     - Platform manifest: `sha256:2222222222222222222222222222222222222222222222222222222222222222`
>     - Config digest: `sha256:3333333333333333333333333333333333333333333333333333333333333333`
>     - Platform: `linux/amd64`
> - Locations: `services.web.image`, `services.worker.image`
> - Verification record
>     - Plan generated at: 2026-10-09T04:00:00Z
>     - Baseline scan: `scan-base-1`
>     - Candidate scan: `scan-cand-1`
> - Findings this update targets (fixed findings of the running image)
>     - Resolved: 2
>     - Remaining: 1
> - Other findings of the running image, outside this update's targets (such as findings with no fixed version)
>     - No longer reported for the candidate image: 1
>     - Remaining in the candidate image: 1
> - Findings introduced by the candidate image: 0
>
> **Resolved (2)**
>
> - `CVE-2026-0001` in `libc6` (`debian`, `os`), severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`
> - `CVE-2026-0002` in `openssl` (`debian`, `os`), severity `HIGH`
>
> **Remaining among the targeted findings (1)**
>
> - `CVE-2026-0003` in `zlib1g` (`debian`, `os`), severity `HIGH`
>
> **Other findings the candidate image no longer reports (1)**
>
> - `CVE-2026-0005` in `libheif1` (`debian`, `os`), severity `HIGH`
>
> **Other findings that remain in the candidate image (1)**
>
> - `CVE-2026-0004` in `tar` (`debian`, `os`)
>
> **Introduced (0)**
>
> - none
>
> Both images were scanned under these conditions:
>
> - Trivy: `0.71.2`
> - Vulnerability database built at: 2026-10-09T01:02:03Z
> - Severity range: `CRITICAL`, `HIGH`
> - Scope: `os packages`

Each section contains the following information.

| Section | Contents |
| --- | --- |
| What | Files to change, running or base image, edited targets, and workloads |
| Change | Image tags or package versions before and after, and locations changed |
| Verification | Compared images or dependency files, scan results, and commands to run in CI before merging language package updates |

For language packages, major version changes (minor version changes for 0.x) appear as bold warnings in “What”.
Version specifier edits that switch the allowed major version also appear as bold warnings.

For pull requests containing only some of the planned updates, see [Partial PRs](remediation-update-results.md#partial-pull-requests).

When dependent packages are also updated, “Packages updated along with the fix” lists the direct dependencies whose versions changed, their versions before and after, and the requirements that blocked the update.
For example, updating `mkdirp` to bring `minimist` to a fixed version produces the entry “`mkdirp`: `0.5.1` to `0.5.6` (it required `minimist` `0.0.8`)”.

If vulnerabilities are carried after the update, the body includes their count and one example ([Carried vulnerabilities](remediation-reresolution-logic.md#dependent-reresolution-carried-findings)).

### Kubernetes pull requests {#kubernetes-pr-results}

Kubernetes pull requests only change repository files; they do not apply changes to the cluster.
“What this change relies on” and “After merging” describe what KestreLynx has not verified.

The body contains the following information for each pull request type.

| Pull request type | Contents of the body |
| --- | --- |
| All (including Dockerfile) | Automatic synchronization or CI may deploy the change on merge |
| Manifest, Kustomize, and Helm values | Use of the changed file for deployment is unverified |
| Manifest, Kustomize, and Helm values (when CronJob or Job workloads are included) | Changes do not affect existing Jobs |
| Manifest | Workloads and containers that use the target’s image but are not changed |
| Kustomize | Kustomization is not rendered, and effects on containers outside the list are unverified |
| Helm values | The chart is not rendered, and the changed key supplying the final value is unverified |
| Helm values (when double quotes are added) | The new tag is written in double quotes so that it is read as a string |

Management tools listed in the body (Argo CD, Flux, and Helm) are [inferred from labels or annotations](remediation-kubernetes-logic.md#management-markers).

For Kustomize and Helm values, the body lists the containers named in the configuration’s `workload` and `affects`.

The containers updated by pull requests can be selected through KestreLynx’s configuration.

- To have KestreLynx also update regular containers and native sidecars listed as unchanged in a manifest pull request, add their [mappings](remediation-setup-kubernetes.md#kubernetes-pull-requests)
- In manifest pull requests, KestreLynx does not edit ordinary init containers, even when mappings are added ([Manifest formats](remediation-source-formats.md#manifest-formats))
- For [Kustomize](remediation-setup-kubernetes.md#kustomize-pull-requests) and [Helm values](remediation-setup-kubernetes.md#helm-values-pull-requests), add containers to `affects` if the change also affects containers outside the list

For the scope of checks, see [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) and [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs).

### Go pull requests {#go-pull-requests}

Go pull requests propose updates to `go.mod` and `go.sum`.
“Verification” includes the following information.

- “Go module update”
    - Version checks against `proxy.golang.org` and hash verification against `sum.golang.org`
    - Changes to `go` and `toolchain`, and possible changes to language features or `GODEBUG` defaults
- “Modules the update also moved, which the targets' new versions require”
    - Modules upgraded or added along with the targets (only when present)
- “go.sum lines of the versions the update moved to, added from the checksum database”
    - Lines added from `sum.golang.org` records (only when present)
- “Before merging, run a CI job that builds and tests with go.mod as it is”
    - The example command `go build -mod=readonly ./... && go test -mod=readonly ./...`
    - Instructions not to run `go get`, `go mod tidy`, or a build with `-mod=mod` before the build and tests
    - Checks based on the Go command’s default behavior of stopping the build when `go.mod` lacks a required module

KestreLynx compares findings for the versions written in `go.mod`, but does not verify application builds, tests, or operation.
For acceptance conditions, see [Go update validation](remediation-go-logic.md#go-update-validation).

### Maven pull requests {#maven-pull-requests}

Maven pull requests propose updates to `pom.xml`.
“Verification” includes the following information.

- “Maven update”
    - Edits to versions and properties, parent property overrides, and `dependencyManagement` pins made without running Maven
    - Version checks against Maven Central, and Trivy dependency resolution and scans
    - Instructions to remove property overrides and `dependencyManagement` pins when upgrading the parent to a release with the fixes
- “Packages whose resolved version also changed”
    - Packages outside the targets whose versions changed, or that were added or removed (only when present)
- “Before merging, check what Maven resolves and run the build”
    - The example command `mvn -B dependency:tree && mvn -B verify`
    - The checks used Trivy’s resolution of the POM files rather than Maven’s

KestreLynx checks dependencies and findings from Trivy’s resolution of the POM files, but does not verify Maven builds, verification, or application operation.
For acceptance conditions, see [Maven update validation](remediation-maven-logic.md#maven-update-validation).

### Gradle pull requests {#gradle-pull-requests}

Gradle pull requests propose updates to version declarations and `gradle.lockfile`.
“Verification” includes the following information.

- “Gradle update”
    - Edits to catalogs, dependency declarations, and properties, and added constraints
    - The Gradle version in the work container
    - No removed lockfile entries or changed configurations
    - Targets at or above the selected published versions in each configuration, with a `.pom` on Maven Central for each added or changed version
    - Instructions to remove BOM property overrides when upgrading the Spring Boot plugin to a release with the fixes
    - Instructions to remove constraints when the dependency that brings the package is upgraded to a release requiring the fixed version
- “Packages whose version the same value sets, confirmed on Maven Central”
    - Packages sharing the edited property or catalog value whose versions were confirmed on Maven Central (only when present)
- “Packages whose locked version also changed, or that were added”
    - Packages outside the targets whose locked versions changed, or that were added (only when present)
- “Before merging, run a CI job that prints the dependencies and builds and tests with gradle.lockfile as it is”
    - The example command `./gradlew dependencies && ./gradlew build`
    - Instructions not to run `--write-locks` or `--update-locks` before builds and tests
    - `--write-locks` and `--update-locks` replace the `gradle.lockfile` that KestreLynx checked

KestreLynx checks versions in the updated lockfile and findings before and after the update, but does not verify application builds, tests, or operation.
For acceptance conditions, see [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation).

## Resolved, remaining, and introduced findings, and what KestreLynx has not verified {#verification-results}

Resolved, Remaining, and Introduced in pull request bodies, and resolution counts in Slack remediation plans, describe scan comparisons as shown in the following table.

| Label | Meaning |
| --- | --- |
| `Resolved` | Findings detected before the update but not after it |
| `Remaining` | Findings still present after the update |
| `Introduced` | Findings absent before the update but detected after it |

The images or files scanned for comparison depend on the update type.

| Update type | Scanned as the state before the update | Scanned as the state after the update |
| --- | --- | --- |
| Published image | The running image | The image retrieved from the registry at the candidate tag |
| Base image (Dockerfile `FROM`) | The image retrieved from the registry that the current `FROM` tag points to | The base image retrieved from the registry at the candidate tag |
| Language package | Dependency files retrieved from the repository before the update | Updated dependency files proposed in the pull request |

For comparison methods, see [Scan comparison conditions](remediation-logic.md#comparison-conditions); for when Dockerfile updates include Node.js and Python runtime findings, see [Handling language runtime findings](remediation-base-image-logic.md#base-runtime-findings).

The example in [Pull request contents](#pr-body-and-checks) includes the finding entries from “Verification”.

For Compose, Kubernetes manifest, Kustomize, and Helm values pull requests, “Verification” separates findings into the following entries.
The table omits parenthetical explanations and counts from the entry names.

| Entry in the body | Contents | Finding list headings |
| --- | --- | --- |
| Findings this update targets | Resolved and remaining findings with reported fixed versions that the update aims to resolve | Resolved, Remaining among the targeted findings |
| Other findings of the running image, outside this update's targets | Counts of findings outside the targets, including those without reported fixed versions, that disappear or remain in the candidate | Other findings the candidate image no longer reports, Other findings that remain in the candidate image |
| Findings introduced by the candidate image | Findings absent before the update but detected in the candidate | Introduced |

Finding lists follow the counts, and “Other findings the candidate image no longer reports” appears only when such findings exist.
For Dockerfile updates, “Other findings of the compared base images” gives remaining and introduced counts for the candidate base.

Language package updates show resolved, remaining, and introduced findings across all packages in the dependency files.

KestreLynx has not verified the following results.

- Resolution of findings in the completed image built from the changed Dockerfile
- Resolution of findings in running containers after deployment
- Actual dependency installation using the updated dependency files
- Successful application builds, tests, or operation

For the conditions under which findings are classified as resolved in scans after deployment, see [Resolution decisions](diff-logic.md#resolved-findings).

For the checks and acceptance conditions, see [Verification scope by target](remediation-logic.md#verification-scope).
