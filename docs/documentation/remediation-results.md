# Reading the results

Remediation plans show update candidates, PR states, and items that require manual handling.
A proposed candidate or merged PR does not mean that vulnerabilities have been resolved in running containers.

## Remediation plans in Slack {#reading-results-in-slack-and-webhooks}

### Example {#slack-example}

The following is an example. In Slack, image references are bold and PR numbers are links.

```text
🔧 Fix plan
Pull requests: 1 created · 1 open

Image: example/app:latest
File to change: pnpm-lock.yaml in example/application
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
Needs a decision: package-b could not be raised to 2.3.0, which fixes the vulnerability, and stays at 2.1.1 in pnpm-lock.yaml (KestreLynx did not look into why it cannot be raised, so check the version ranges of the packages that depend on package-b)

Image: example/service:latest
File to change: docker/Dockerfile in example/application
Pull request: #13 (open)
Update: base image python 3.12.3-slim → 3.12.4-slim
```

### Displayed fields {#slack-fields}

| Display | Meaning |
| --- | --- |
| Image | The running image that produced the findings. |
| Service | The target service, shown when an image reference cannot be used as the heading or in similar cases. |
| File to change | The mapped repository and the file to change. |
| Pull request | A PR link and its status: opened now, open, merged, or closed without merging. |
| Update | Image tag or package changes proposed by the PR. |
| Update candidate | A proposed change that does not necessarily have a PR yet. |
| Newer series | A newer minor or major candidate resolves all or some findings without adding findings; guidance separate from PR candidates. |
| Re-pull | The comparison supports updating to new content under the same tag. |
| Pull policy | The image pull policy and re-pull guidance for the affected workloads, shown on Kubernetes re-pull items. |
| Managed by (from markers) | The management chain shown when Kubernetes resources carry management markers; attribution is inferred from those markers. |
| Rebuild | Expected resolution based on a dependency version constraint, or guidance to pull the base again and rebuild. |
| Needs a decision | Manual handling is needed for the source, version constraints, update method, comparison results, or similar issues, including newer-series candidates that resolve findings but add new findings or KEV-listed findings. |
| Deferred | Processing could not proceed because of limits, waiting periods, retrieval problems, or similar issues. |
| Not comparable | Information or conditions needed for the comparison were missing. |
| Failed | A scan, retrieval, update, or other operation failed. |
| ⚠️ Major version change | An update changes the major version, or the minor version for a 0.x package. |
| ⚠️ Pull request writes are stopped | PR writes have stopped because of problems with records, GitHub state, or similar issues. |

Packages with an update target that need a decision appear on individual lines.
Packages without a target are grouped by reason, with a package list below each reason.

A single “Newer series” line appears for `resolves` or `resolves_partially`, and a “Needs a decision” line for `resolves_with_new`.
`not_resolving`, `not_checked`, and `no_newer_series` produce no line in the remediation plan message.

| Result | Example |
| --- | --- |
| All resolved | `Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 finding(s), compatibility not checked)` |
| Partly resolved | `Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 of 2 findings, compatibility not checked)` |
| Base comparison | `Newer series: base image python 3.11.9-slim → 3.13.1-slim (minor update, resolves 2 finding(s), base images compared, the rebuilt image not checked, compatibility not checked)` |
| New findings added | `Needs a decision: nginx 1.24.1 → 2.0.1 in a newer series resolves 1 finding(s) and adds 2 (major update, compatibility not checked)` |

A change to this line causes the remediation plan message to be sent as a change.
See [Newer series check](remediation-logic.md#newer-series-check) for check scope and candidate selection.

For reason definitions, see [Reason codes](remediation-reference.md#reason-codes); for troubleshooting steps, see [When no candidate or pull request appears](remediation-troubleshooting.md).

### Reading counts {#reading-counts}

| Summary | Unit counted |
| --- | --- |
| `Pull requests: … created · … open` and similar summaries | The status of each update unit handled by PR processing. |
| `… update candidate(s) · … need a decision` and similar summaries | Display categories for each item, such as a file to change or an image to re-pull. |
| `… resolved in a newer series` | Items with newer-series status `resolves` or `resolves_partially`, not resolved findings or PRs. |
| `resolves … finding(s)` | Findings no longer detected in the comparison. |
| `… KEV` | Counts related to vulnerabilities in the CISA KEV catalog included in the displayed results. |

When results include a PR number, the opening summary groups counts by PR processing status.
This summary also includes “need a decision,” “deferred,” and “blocked or failed” update units that do not yet have a PR.

- PR counts differ from the number of packages or vulnerabilities being updated
- An item with both a candidate and a need for a decision counts once in each category
- Even when several packages in the same item need a decision, the decision count does not necessarily match the package count
- Packages left out of a created PR still need a decision

### Finding omitted details {#omitted-details}

Slack may shorten long package lists and similar content with “and … more.”

| Information needed | Where to find it |
| --- | --- |
| Versions, reasons, and exclusion details for each package | [Webhook details](#webhook-details) |
| The actual proposed file changes | The PR diff |
| Source information and check results at planning time | [Saved record details](#saved-details) |
| Details of retrieval or execution failures | [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics) |

### Kubernetes PR display {#kubernetes-pr-results}

Slack displays manifest, Kustomize, and Helm values tag updates with the target file and a link to the PR.
When management markers are present, manifest, Kustomize, Helm values, and Dockerfile PR entries also show the management chain.

PR bodies for Kubernetes include the following information.

- A notice that external automatic synchronization or CI may apply changes after merging, whether or not a management tool is detected
- Management tools such as Argo CD, Flux, and Helm as claims from object markers, without treating the actual management relationship as verified
- A notice in manifest, Kustomize, and Helm values PRs involving CronJobs or Jobs that existing Jobs are not affected
- Workloads running the same image without a manifest mapping, and unchanged containers in the same Pod template, in manifest PRs
- The list of containers declared as affected, plus a separate list of those verified as ordinary init containers, in Kustomize and Helm values PRs
- The premise that the user has confirmed the listed set as complete, and the scope checked without rendering Kustomize, in Kustomize PRs
- The premise that the user has confirmed the selected key as the final value and the listed set as complete, and the scope checked without rendering Helm, in Helm values PRs
- A notice in Helm values PRs that overrides from other values files, CI `--set`, and Argo CD `parameters`, `valuesObject`, and `valuesFrom`, and ownership of the tag by other tools, are not verified
- The workloads with detected Flux HelmRelease markers, with a notice that HelmRelease `spec.values` is not read and may take precedence over the values file
- A notice that it is unknown whether this values file deploys the workloads when neither a Helm release nor a Flux HelmRelease is detected
- The reason for adding double quotes to a new tag when needed to keep it a string in Helm

## Interpreting update results {#interpreting-updates}

### Update targets and adopted versions {#target-and-adopted-version}

| Displayed version | Interpretation |
| --- | --- |
| Running version | The version detected in the scanned image. |
| Update target lower bound | The minimum version used when selecting an update, derived from reported fixed-version information. |
| Adopted version | The version confirmed in the updated dependency files, or the lowest version if multiple versions remain. |

The update target is not necessarily the version the package manager actually selected.
Planning alone does not run dependency updates, so do not interpret the update target as a verified adopted version.

For the lower-bound calculation, see [Fixed-version lower bound](remediation-logic.md#fix-lower-bound); for differences in processing, see [Execution scope of plans and PRs](remediation-logic.md#plan-and-pr-execution).

### Go PRs and CI checks {#go-pull-requests}

Go PRs propose updates to `go.mod` and `go.sum` and include the following information in the body.

- The public Go module proxy (`proxy.golang.org`) and hash verification through `sum.golang.org`
- Modules upgraded or added alongside the targets because the targets' new versions require them
- Changes to the `go` and `toolchain` lines, and the possibility that raising the `go` line changes language features or `GODEBUG` defaults
- `go.sum` lines that KestreLynx added from `sum.golang.org` records

Before merging, run builds and tests in CI using the updated `go.mod` as-is.

```sh
go build -mod=readonly ./... && go test -mod=readonly ./...
```

- Do not run `go get`, `go mod tidy`, or a build with `-mod=mod` before this check
- With `-mod=readonly`, the build stops if a required module is missing or its version is too low, so check the CI results before merging
- KestreLynx checks the versions written in `go.mod`; these checks do not guarantee a successful build or correct application behavior

See [Go update validation](remediation-logic.md#go-update-validation) for acceptance conditions.

### Maven PRs and CI checks {#maven-pull-requests}

Maven PRs propose updates to `pom.xml` and include the following information in the body.

- Changed files and details of directly written versions, properties, parent property overrides, and pins through `dependencyManagement`
- Version checks against Maven Central and Trivy's dependency resolution and scan results before and after the update
- Packages outside the targets whose resolved versions changed, and packages that were added or removed
- That KestreLynx rewrote the POMs without running Maven

Before merging, check the dependencies resolved by Maven and run the build and verification in CI.

```sh
mvn -B dependency:tree
mvn -B verify
```

- For multiple modules, run the checks in the directory containing the root's `pom.xml`
- KestreLynx checks POM resolution by Trivy; these results do not confirm a successful Maven build
- Parent property overrides and `dependencyManagement` pins remain until removed; remove them when upgrading the parent to a version that includes the fix

See [Maven update validation](remediation-logic.md#maven-update-validation) for acceptance conditions.

### Gradle PRs and CI checks {#gradle-pull-requests}

Gradle PRs propose updates to version declarations and `gradle.lockfile` and include the following information in the body.

- Changed files and details of catalog and dependency declaration changes, property changes or overrides, and added constraints
- The work container's Gradle version, and check results for returned lockfile entries, configurations, target versions, and Maven Central `.pom` files
- Other packages whose versions are determined by the same property or catalog value and were checked on Maven Central
- Packages outside the targets whose locked versions changed, and packages that were added
- Trivy scan results before and after the update, and checks to perform in CI before merging

Before merging, list the dependencies in CI and run the build and tests using `gradle.lockfile` unchanged.

```sh
./gradlew dependencies && ./gradlew build
```

- Do not run `--write-locks` or `--update-locks` before this check, because they replace the checked lockfile
- KestreLynx checks the lockfile and scan results; these results do not confirm a successful application build or tests
- Spring Boot BOM property overrides remain until removed; remove them when upgrading the Spring Boot plugin to a version that includes the fix
- Added constraints remain until removed; remove them when the dependency that brings in the package is upgraded to a version that requires a fixed version

See [Gradle update validation](remediation-logic.md#gradle-update-validation) for acceptance conditions.

### Partial PRs {#partial-pull-requests}

For npm, pnpm, uv, Maven, and Gradle, a PR may include only the planned package updates that passed the checks.

| Result | Interpretation |
| --- | --- |
| A package listed under “Update” for the PR | A change included in this PR. |
| A package shown under “Needs a decision” or marked “left out because” | A target excluded from this update that needs separate handling. |
| A package reported as unable to reach the target version and still at its original version | A target that did not reach a fixed version, without necessarily establishing why the update was unsuccessful. |
| An open PR with exclusion details | Packages still need handling even for an update matched to an existing PR. |

“Left out” does not mean that the package was removed from the image.
An item being a PR candidate also does not mean that every package was updated.

Pinned-version pip updates and Go updates are not split into partial PRs.
For eligibility conditions, see [Partial PR selection](remediation-logic.md#partial-pr-selection), [Maven target exclusion conditions](remediation-logic.md#maven-update-exclusions), and [Gradle target exclusion conditions](remediation-logic.md#gradle-update-exclusions); for checks to perform, see [Checking update failures](remediation-troubleshooting.md#check-update-failure).

### Results of re-resolution through dependent packages {#dependent-reresolution-results}

When `mkdirp 0.5.1` requires `minimist 0.0.8`, updating `mkdirp` to `0.5.6` also allows `minimist` to reach a fixed version.
In an example that adopts `minimist 1.2.8`, Slack shows:

```text
minimist 0.0.8 → 1.2.8 (with mkdirp 0.5.1 → 0.5.6)
```

The requirement in `rc 1.2.8` is `minimist ^1.2.0`, which allows a normal update to select a fixed version, so the version of `rc` stays unchanged.

| Slack display excerpt | Meaning |
| --- | --- |
| `with mkdirp 0.5.1 → 0.5.6` | The dependent package `mkdirp` also updates to fix `minimist`. |
| `starlette 0.32.0.post1 cannot be raised to the fixed 1.3.1 (the dependent fastapi 0.108.0 limits the version of starlette)` | Appears when the outcome is `not_fixed` and updating the dependent chain within the declared ranges does not reach a fixed version; multiple dependents are listed with their names and versions, and uv's `no_resolution`, where resolving again for the fixed version finds no solution, uses the same display. |
| `did not reach the fixed version this time` | Appears when no dependent requirement is recorded for that package, and selecting dependent packages again does not bring the target to a fixed version in this attempt. |
| `needs … updated as well, and that update was not adopted because …` | The update is not adopted because of failed checks or another reason. |
| `updating … was not tried` | The attempt is skipped because of unsupported forms, processing limits, or similar conditions. |
| `a version it brings in is less than 72 hours old, so it is tried again after …` | Processing waits until the displayed date and time. |

“Packages updated along with the fix” in the PR body lists direct dependencies whose versions change.
In this example, it shows the versions before and after the update and the requirement that blocks the update:

> - `mkdirp`: `0.5.1` to `0.5.6` (it required `minimist` `0.0.8`)

When the same vulnerabilities remain in other packages, the PR body shows the count and an example of carried vulnerabilities.
This update does not fix those vulnerabilities.

A PR may include normal updates that pass the checks even when re-resolution is not adopted.
“Did not reach the fixed version this time” does not mean that other methods cannot fix the vulnerability.

| Information needed | Location relative to `language_items[]` in the webhook |
| --- | --- |
| Dependent packages updated along with the target | `packages[].through` |
| Outcomes such as adoption or skipped attempts, and their reasons | `update.chain.outcome`, `update.chain.reason`, and `update.chain.detail` |
| Carried vulnerabilities | `source_check.chain_carried` |
| Earliest retry date and time | `retry_after` |

See [Re-resolution through dependent packages](remediation-logic.md#dependent-reresolution) for the processing flow in npm, pnpm, and uv.
Other fields are described in [Re-resolution results](webhook-remediation-reference.md#language-chain-fields) and [Scan comparisons](webhook-remediation-reference.md#language-chain-scan-fields).

#### Fixing release hints {#fix-hints}

For npm, pnpm, and uv, hints appear below a package's line when a dependent package's requirement blocks a fixed version and the outcome is `not_fixed`, `rejected`, or `not_tried`.
Each line shows the dependent package's name and version, which release it is, and whether it can use a fixed version of the target package.

```text
starlette 0.32.0.post1 cannot be raised to the fixed 1.3.1 (the dependent fastapi 0.108.0 limits the version of starlette)
  • fastapi 0.109.0 (newest within the range pyproject.toml specifies): cannot use a fixed starlette
  • fastapi 0.162.0 (newest): can use a fixed starlette
```

The checks cover these two releases of the dependent package.

- The newest stable release within the package.json range for npm and pnpm, or the pyproject.toml range for uv, when the dependent package is a direct dependency of the project.
- The newest published stable release, with its display omitted when it is the same as the newest release within the range.

Prereleases are excluded from the version list, and for uv, releases whose files are all yanked are also excluded from the list retrieved from PyPI.

For uv, dependent requirements are read from PyPI metadata (`requires_dist`), and all requirements are considered regardless of environment markers.

The following table describes the display types.

| Slack display excerpt | Meaning |
| --- | --- |
| `newest within the range package.json specifies` / `newest within the range pyproject.toml specifies` | The newest stable dependent release within the project's range, using package.json for npm and pnpm or pyproject.toml for uv. |
| `newest` | The newest published stable release of the dependent package. |
| `can use a fixed starlette` | That dependent release's requirement includes a published stable version that fixes all target vulnerabilities in the package. |
| `cannot use a fixed starlette` | That dependent release's requirement does not include a published stable version that fixes all target vulnerabilities in the package. |
| `can use a fixed starlette, but this update did not raise it` | Shown for the newest release within the package.json or pyproject.toml range when the dependent release's requirement allows a fixed version, but constraints such as other packages or the Python version prevent re-resolution within the range from reaching it, leaving the chain update outcome as `not_fixed`. |
| `does not use starlette directly` | That dependent release does not declare the target package as a direct dependency, but another path may still bring it in. |
| `which release of express brings in this mkdirp is not checked` | A note for a dependent package that is not a direct dependency, indicating that the direct dependency release bringing in the displayed dependent release is not checked. |

For a dependent package that is not a direct dependency, the note appears below the newest release line when that release can use a fixed version or drops the direct requirement, and the direct dependency path is known.

- Intermediate releases are not checked, so the hints do not identify the minimum release needed for a fix.
- The checks do not establish whether updating to the displayed release resolves dependencies successfully or whether the application works.
- “can use a fixed starlette” describes the dependent package's declared range and does not guarantee that updating to that release fixes the vulnerability.
- “does not use starlette directly” does not establish that the target package leaves the project or that the vulnerability is fixed.

Lines are omitted for information that cannot be evaluated or retrieved.

- For npm and pnpm, evaluation is unavailable because of peer dependencies, aliases, conflicting ranges, unsupported ranges, a bundled shrinkwrap, or similar conditions.
- For uv, evaluation is unavailable when there are differing requirements for the same package, unreadable requirements, or unsupported version specifications.
- Registry queries fail or the lookup time limit is reached.

Queries run after the update decision, with limits of three target-package and dependent-package pairs and 30 seconds in total per item.
The presence or content of hints does not affect the plan or PR.

Hints apply to npm, pnpm, and uv.
Range values are omitted from Slack and included with the checked information in the webhook's `language_items[].update.chain.hints`.

### Re-pull guidance {#repull-guidance}

“Re-pull” means that a comparison with the content currently referenced by the same tag confirmed an improvement.
Because the tag string does not change, this guidance alone does not create a PR to update a Compose, Kubernetes manifest, Kustomize, or Helm values tag.

`resolves 3 of 4 findings` means that three of the four findings being compared were no longer detected in the candidate.
It does not mean that running containers have been replaced with that content.

### Rebuild guidance {#rebuild-guidance}

| Displayed content | Interpretation |
| --- | --- |
| `a rebuild is expected to pick up … or later` | The pip dependency range permits a fixed version, so a rebuild is expected to resolve the finding. |
| Guidance to rebuild the Go standard library with a newer Go | `stdlib` findings do not produce a PR; a separate remediation plan item recommends rebuilding with at least the Go version that fixes all CVEs. |
| `Rebuild: PR #… (base image … … → …) is merged, but the running image is still built from …` | The base-update PR is merged and the running images are unchanged since the PR was created, so deploying an image built from the merged Dockerfile puts the update in place. |
| `which base the running image was built from cannot be confirmed` | The base behind a floating tag could not be confirmed, so the guidance is to pull the current base and rebuild. |
| Guidance to run `docker compose build --pull` | Instructions to pull the base again and rebuild when the Dockerfile was discovered through Compose `build`. |
| pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again | Guidance when the Dockerfile was found only through a configured mapping, including images built in CI. |
| `Node.js in the current … is …; if the rebuild takes over this version, … of the … findings of the detected Node.js … are expected to disappear (the rebuilt image is not checked)` | The number of currently detected CVEs expected to disappear if the rebuild inherits the current base's runtime version, excluding CVEs introduced by the new version; Python is displayed as `Python runtime`. |

None of these cases confirms the version actually installed by a rebuild or resolution in the running image after deployment.
For details, see [Direct dependency version constraints](remediation-logic.md#direct-dependencies), [Base layer matching](remediation-logic.md#base-layer-matching), and [Go standard library rebuild guidance](remediation-logic.md#go-stdlib-rebuild).

### Resolved findings in comparisons {#verification-results}

| Display | Meaning |
| --- | --- |
| `Resolved` | Findings present in the comparison target before the update but no longer detected after the update. |
| Remaining | Findings still present in the comparison target after the update. |
| Introduced | Findings absent from the comparison target before the update but detected after the update. |

The comparison targets depend on the type of update.

| Update type | What the comparison represents |
| --- | --- |
| Distributed image | The baseline image and the candidate image. |
| Dockerfile base image | The current base image and the candidate base image. |
| Language package | Dependency files before and after the update. |

For Compose, Kubernetes manifest, Kustomize, and Helm values image tag updates and Dockerfile base image updates, PR bodies separate targeted findings from other findings.

- Targeted findings have a reported fixed version; for Dockerfile updates, they are limited to findings in the base image’s layers; `Resolved` and Remaining counts for these targets are also the counts used in remediation plans in Slack and webhooks
- Other findings that remain in the candidate are shown separately, along with Introduced findings
- Other findings include those with no reported fixed version and any others outside the update's targets
- Compose, Kubernetes manifest, Kustomize, and Helm values PRs also show counts for other findings that the candidate no longer reports, with a list only when such findings exist

!!! note "Resolution and running state"

    Resolution reported in a PR or Slack refers to a comparison result. It does not establish resolution in the complete rebuilt image or in running containers after deployment.

For the limits of these checks, see [Verification scope by target](remediation-logic.md#verification-scope); for comparison conditions, see [Scan comparison conditions](remediation-logic.md#comparison-conditions).
Dependency installation and application behavior have not been checked.

## Finding detailed results {#detailed-results}

### Webhook details {#webhook-details}

| Information needed | Field specification |
| --- | --- |
| Plan status, comparison conditions, processing limits, and usage | [Common remediation plan fields](webhook-remediation-reference.md#remediation-fields) |
| Distributed image candidates and comparison results | [Distributed image fields](webhook-remediation-reference.md#remediation-image-fields) |
| Base image candidates and layer verification results | [Base image fields](webhook-remediation-reference.md#remediation-dockerfile-fields) |
| Versions, processing, and exclusion reasons for each package, runtimes, tools, and update checks | [Language package fields](webhook-remediation-reference.md#remediation-language-fields) |
| PR status and packages left out of the PR that still need handling | [PR processing fields](webhook-remediation-reference.md#remediation-pr-fields) |
| Results of operations such as PR creation and reconciliation | [PR operation event fields](webhook-remediation-reference.md#remediation-operation-fields) |
| Problems that stopped PR writes | [Write-stopping problem fields](webhook-remediation-reference.md#remediation-problem-fields) |
| Example notification data including a partial PR | [Remediation plan JSON example](webhook-remediation-reference.md#remediation-json-example) |

### Saved record details {#saved-details}

Use `plan.json` for information from planning time and `prs.json` for ongoing PR records.
Check notifications for the current run's results after PR processing.

For stored contents and when they are recorded, see [Stored records](remediation-reference.md#stored-records); for retrieval steps, see [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics).
