---
title: How hints work when a package cannot reach its fix
---

# How hints work when a package cannot reach its fix

This page explains when KestreLynx shows a hint, which releases it checks, how it determines whether a fixed version can be used, and what limits apply to release lookups.
For help reading the notification, see [Hints when a package cannot reach its fix](remediation-fix-hints.md). For terminology, see [Terms](index.md#terms).

## When a hint appears {#fix-hints-conditions}

A package is eligible for a hint when KestreLynx identifies why the update could not reach a fix or why the plan marked the package for manual handling.

### npm, pnpm, uv, and pip

For npm, pnpm, and uv, [re-resolution through dependent packages](remediation-reresolution-logic.md#dependent-reresolution) selects versions of dependents (packages that use the target) again within the project's declared ranges and resolves the dependencies, including the target package.
The following three re-resolution outcomes are eligible for a lookup of published dependent releases.

| Re-resolution outcome | Condition |
| --- | --- |
| `not_fixed` | Re-resolution within the declared ranges does not reach a fixed version of the target |
| `rejected` | The update result cannot be adopted, or re-resolution stops after three consecutive deferrals while waiting for newly used releases to age |
| `not_tried` | Re-resolution is skipped for a reason such as unsupported input or a processing limit |

A lookup requires a record identifying the target package and the dependent whose requirement blocked the update.
On the third consecutive deferral while waiting for newly used releases to age, KestreLynx records `rejected` without looking up releases, so the outcome code alone does not determine whether a release line appears.

For pip, a hint appears when the pins in `requirements.txt` have been updated, pip cannot resolve the dependencies, and KestreLynx identifies a dependent whose requirements exclude the version requested by the update (`dependents_hold_back`).

### Go

For Go, KestreLynx checks the project's `go.mod`, where the `go` line specifies the required Go version and the `toolchain` line specifies the suggested Go toolchain.
The build ceiling in the table is the lowest Go version used to build any of the running binaries covered by the update.

| Condition | Reason code |
| --- | --- |
| The changed `go` version exceeds the build ceiling | `go_line_raised_too_far` |
| The changed `toolchain` version exceeds the build ceiling | `go_line_raised_too_far` |
| The `go` or `toolchain` version changes while the build Go version is unknown | `go_line_raised_too_far` |
| No Go version available for updates meets the required minimum | `go_runtime_unavailable` |

The detailed hint requires an identified dependency module and release declaring the required Go version. A change to `toolchain` alone can trigger the reason code without producing the detailed hint.
Only a `go_line_raised_too_far` hint with an unknown build Go version ends with `; the Go the running binaries were built with is not known)`.

For the recording conditions, see [Go update validation](remediation-go-logic.md#go-update-validation) and [Go runtime selection](remediation-go-logic.md#go-runtime-selection). For the PR body, see [Go pull requests](remediation-pr-results.md#go-pull-requests).

When the current module path cannot be used for the target major version (`fix_in_other_major_version`), the [Go lookup](#fix-hints-go-lookup) includes packages marked for manual handling during planning.
An update that can reach its target on the current path, such as an update from `v0` to `v1`, does not trigger this hint.

### Maven and Gradle

Maven and Gradle hints can identify the source of a version declaration, a dependency path that retains an older version after the update, or a fix in another major version.
A pom is a file that describes Maven dependencies and settings. A project can inherit settings from a parent pom or import a bill of materials (BOM), a pom that manages dependency versions together.

The following conditions and reason codes determine which hint is eligible.

| Condition | Reason code |
| --- | --- |
| The update cannot edit the declaration and identifies the external parent pom, BOM, or Spring Boot BOM that sets the target version | `maven_version_source_unsupported` for Maven or `gradle_version_source_unsupported` for Gradle |
| The target remains below the release selected from Maven Central, the public package repository, after the update | `target_not_updated` |
| For a target vulnerability, the advisory reports a newer fix in another major version and no fix in the installed major version qualifies for this update | `maven_fix_in_other_major` |
| A fix is reported in the installed major version, but Maven Central lists no release in that major version that meets the update target and can replace the installed version | `maven_release_not_found` |

For `target_not_updated`, the hint names an identified dependent that brings in the older version. If a Gradle configuration (a group of dependencies for a particular use) declares it directly and no dependent is found, the hint names the configuration.
For recording version sources, see [Maven version sources and edits](remediation-maven-logic.md#maven-version-sources) and [Gradle version declarations and edits](remediation-gradle-logic.md#gradle-version-sources). For recording the result after an update, see [Maven update validation](remediation-maven-logic.md#maven-update-validation) and [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation).

### Rust

For `cargo_fix_in_other_series`, KestreLynx compares the fixed versions listed by the advisories for the running image during planning to determine whether one version fixes them all.
It makes no additional queries to crates.io for the hint. See [Target crate versions](remediation-cargo-logic.md#cargo-target-versions).

## Releases and requirements checked for npm, pnpm, uv, and pip {#fix-hints-dependent-lookup}

KestreLynx checks stable releases of the dependent at or above its current version. A stable release is a published version other than a prerelease such as a beta.
The manager and whether the project declares the dependent directly determine which releases are checked.

| Manager | Dependent | Stable releases checked |
| --- | --- | --- |
| npm and pnpm | Direct dependency | Newest within the `package.json` range and newest overall |
| uv | Direct dependency | Newest within the `pyproject.toml` range and newest overall |
| npm, pnpm, and uv | Indirect dependency | Newest overall |
| pip | Direct or indirect dependency | Newest overall |

Release selection and the source of the dependent's requirements follow these rules.

| Scope | Rule |
| --- | --- |
| npm, pnpm, and uv | Omit the newest-overall line if it would repeat the newest release within the range |
| uv and pip release lists | Use versions with at least one file that has not been withdrawn (yanked) from PyPI, the Python package index |
| Newer npm and pnpm dependent releases | Read the target dependency declaration from the npm registry |
| Newer uv and pip dependent releases | Read all requirements from the release's `requires_dist` metadata on PyPI regardless of any conditions that restrict a requirement to particular environments |
| Selected npm, pnpm, or uv release matches the current dependent version | Use the recorded blocking requirement without rechecking whether it allows another fix |

Only when pip's newest dependent release matches its current version does KestreLynx use all requirements on the target that applied in the environment for which pip resolved dependencies, in place of reading the published requirements again.

KestreLynx checks whether the dependent's requirements allow a fixed version as follows.

1. Find published stable target releases that fix every target vulnerability
2. Show `can use a fixed …` if at least one such release meets every applicable requirement

Candidates can include fixed versions other than the update target named on the package's first notification line.

For npm, pnpm, and uv, the checked dependent release and the re-resolution outcome determine when the following wording appears.

| Condition | Slack wording |
| --- | --- |
| The newest direct dependency release within the project's range allows a fix and re-resolution for the project has the outcome `not_fixed` | `can use a fixed …, but this update did not raise it` |
| The newest indirect dependent release allows a fix or no longer requires the target directly, and the direct dependency on the path is known | `which release of … brings in this … is not checked` below the newest release line |

Re-resolution also has to satisfy constraints such as other packages' requirements or the Python version. The `not_fixed` wording alone does not identify which constraint prevented the update.

## Information checked for Go hints {#fix-hints-go-lookup}

For a fix in another major version, KestreLynx checks the fix and looks for dependents that require the current module path (the name that identifies the module), without changing project dependencies.
The lookup uses the following information and sources.

| Information | How it is checked |
| --- | --- |
| Fixed version to display | Select the lowest fix in the advisories that fixes every target vulnerability |
| Direct project requirement | Read `go.mod` and `go.sum` from GitHub and check the requirements in `go.mod` |
| Dependents of an indirectly required target | Read `go.mod` for each other module the project requires from the Go module proxy, which serves published modules |
| Newest dependent release | Get the version from the proxy's `@latest` endpoint and read its `go.mod` if it is newer than the current release |

The project's declaration and the dependent's requirements determine the hint as follows.

- If the project's `go.mod` requires the target without `// indirect`, record a direct requirement and skip proxy reads to find dependents
- Otherwise, record each module that requires the target, its version, and the target version it requires
- Show `does not use … directly` if the newest dependent release no longer requires the current module path, or `cannot use a fixed …` if it still does
- Reuse the recorded requirement if the newest version matches the current dependent version, and omit the line if it is older or cannot be compared
- Omit the affected release line if the proxy synthesized the newer release's `go.mod` or required proxy information is unavailable

## Fix checks in Maven and Gradle {#fix-hints-maven-judgement}

For Maven and Gradle, KestreLynx determines whether a release of a dependent or a deciding pom specifies a fixed version in three steps.

1. Select the published releases of the dependent or deciding pom to check
2. Read the target package version specified by each selected release's pom
3. Compare the specified version with the update target and with the fixes for each target vulnerability

### Selecting published releases

KestreLynx selects stable releases at or above the current version of the dependent or deciding pom itself.
A series is a major and minor version pair such as `2.13`. KestreLynx looks for the newest release in each of the following ranges.

- The newest release in the current version's series, including the current version itself
- The newest release overall, omitting the `newest` line if it would repeat the newest release in the current series

### Reading the target package version from a pom

KestreLynx reads the selected release's pom and its parents, checking `dependencies` (direct dependency declarations) and `dependencyManagement` (managed versions and other dependency settings).
The pom's role determines where to look for the version.

| Pom checked | How the target version is read |
| --- | --- |
| Parent pom | Use the version in the nearest `dependencies` declaration, falling back to `dependencyManagement` if the declaration or its version is absent |
| Dependent's pom | Use the nearest `dependencies` declaration and obtain a missing version from `dependencyManagement`, treating an absent declaration as no specification of the target |
| BOM | Read the version specified in `dependencyManagement` |

If no entry for the target is found in `dependencyManagement`, KestreLynx follows BOM imports in order and uses the first BOM that manages the target.
The check follows up to ten parent poms and up to four successive BOM imports from the initial pom, and omits the release line if a depth limit prevents a determination.

A profile is a group of pom settings that can be activated together. A release line is also omitted if a profile in a checked pom, parent, or imported BOM meets both conditions below.

- It can activate by default (`activeByDefault`) or based on the Java version (`jdk`), operating system (`os`), a property (`property`), or a file (`file`)
- It changes dependencies, `dependencyManagement`, properties (named values used by the pom), or the parent pom

Profiles activated only by explicitly selecting their name allow the check to continue.

### Comparing fixes for each vulnerability and selecting the wording

A variant is a version suffix category such as `-jre` or `-android`.
For each vulnerability, applicable fixes include fixes matching the variant of the version specified by the pom and fixes without a variant.

The first matching row in the table determines the lower bound for the comparison.

| Applicable fixes | Requirement for the specified version |
| --- | --- |
| A fix exists in the specified version's series | At or above the highest fix in that series |
| No fix exists in the specified series but one exists in the specified major version | At or above the highest fix in that major version |
| Applicable fixes exist only outside the specified major version | At or above the highest applicable fix overall |
| No applicable fix exists | The vulnerability does not pass the fix check |

For a vulnerability with fixes in `2.12.7` and `2.13.4`, the series of the version specified by the pom determines which fix applies.

| Specified version | Fix in the matching series | Result for the vulnerability |
| --- | --- | --- |
| `2.13.2` | `2.13.4` | Remains vulnerable because it is below the fix in the `2.13` series |
| `2.12.8` | `2.12.7` | Fixed because it reaches or exceeds the fix in the `2.12` series |

If the reported fixes are `2.5.15`, `2.6.15`, `2.7.12`, and `3.0.7` and the pom specifies `2.8.0`, no fix belongs to the `2.8` series.
The comparison uses `2.7.12`, the highest fix in major version 2.

The `-android` and `-jre` examples show when a reported fix applies to a version with a variant.

| Reported fix | Specified version | Used in the comparison |
| --- | --- | --- |
| `33.7.2-android` | `33.8.0-jre` | No, because the variants differ |
| `33.7.2` | `33.7.2-jre` | Yes, because the fix has no variant |

The Slack wording depends on what KestreLynx can establish from the published pom.

| Condition | Slack wording |
| --- | --- |
| The specified version meets the update target and fixes every target vulnerability | `specifies a fixed version` |
| A version is specified but falls below the update target or fails the fix check for at least one target vulnerability | `does not specify a fixed version` |
| A dependent's pom has no direct declaration of the target or no version specified for that declaration, or a parent pom or BOM sets no version for the target | `does not specify …` |

For a hint about another major version, KestreLynx applies the variant and series checks to every target vulnerability and selects the lowest eligible candidate that fixes them all.
The rules under [Target versions and Maven Central releases](remediation-maven-logic.md#maven-target-versions) determine the source and eligibility of candidates.

- For `maven_fix_in_other_major`, use advisory fixes in another major version that are newer than the installed version, exclude prereleases, and accept fixes matching the installed variant or without a variant
- For `maven_release_not_found`, use stable Maven Central releases in another major version that meet the update target and match the installed variant

For the wording shown when a qualifying version is found, see [When fixes exist only in another major version](remediation-fix-hints.md#fix-hints-maven-other-major).

## Timing and limits for reading published release information {#fix-hints-lookup-limits}

KestreLynx looks up published releases of dependents and deciding poms after it has determined the plan outcome and which updates qualify for a PR.
For an item eligible for an update attempt, processing follows this order.

1. Attempt the update
2. Decide whether to include the update in a PR
3. Read published release information for dependents or deciding poms
4. Send the notification

For `maven_release_not_found` in Maven and Gradle, KestreLynx looks for a candidate in another major version during the update only when it cannot select an update in the target package's own current major version, using the Maven Central version list already retrieved for that package.

The presence or content of a hint does not affect the plan or PR.
If published release information is unavailable, the hint retains any dependent or deciding pom already identified.

In the table, an item is one plan entry grouping dependency files by language within a repository, branch, and directory.

| Manager | Sources read | Target and dependent pairs | Releases checked | Read limit | Time limit |
| --- | --- | --- | --- | --- | --- |
| npm and pnpm | Published releases and requirements from the npm registry | 3 per item | Up to 2 per dependent | — | 30 seconds total per item |
| uv | Published releases and `requires_dist` from PyPI | 3 per item | Up to 2 per dependent | — | 30 seconds total per item |
| pip | Published releases and `requires_dist` from PyPI | 3 per item | Newest release per dependent | — | 30 seconds total per item |
| Go hints for another major version | `go.mod` and `go.sum` from GitHub, and `@latest` and `go.mod` from the Go module proxy | 3 per item | Newest release per dependent | 200 proxy `go.mod` reads per item | 30 seconds total per item |
| Maven and Gradle | Version lists, poms, parent poms, and imported BOMs from Maven Central | 3 dependent pairs per item | Up to 2 per dependent or deciding pom | 12 reads per target package | 30 seconds total per item |

One pair consists of the target package name together with the dependent's name and current version.
Checking two releases of that dependent counts as one pair.

File and registry reads count toward the limits as follows.

- Go's 200 reads include the `go.mod` files used to find dependents and the `go.mod` files read for their newest releases
- The 12 reads for Maven and Gradle include version lists and are shared across all dependents of the target package
- The 12-read limit for Maven and Gradle covers additional hint lookups, while the version list reused for `maven_release_not_found` counts toward update reads

### When a published release line is omitted {#fix-hints-omitted-lines}

KestreLynx omits a release line when it cannot establish what the published release allows.
The cause remains on the target package's first line. Whether the omitted release allows a fix remains unverified.

For npm and pnpm, `peerDependencies` lists requirements on packages used alongside the dependent by its consumer, and an alias declares a package under a name other than its published name.
A shrinkwrap is an `npm-shrinkwrap.json` file distributed with a package to pin its dependencies.

The following conditions can prevent a line from being shown when KestreLynx reads a newer release's declarations or looks up required release information.

| Scope | Condition for omitting the line | Example declaration in a published release |
| --- | --- | --- |
| npm and pnpm peer dependencies | The target is listed in `peerDependencies` or, for pnpm, only in `peerDependenciesMeta` as an optional peer dependency | `"multer": "^2.5.0"` in `peerDependencies` |
| npm and pnpm aliases | The target is declared under an alias | `"upload": "npm:multer@^2.5.0"` |
| Conflicting npm and pnpm ranges | The regular (`dependencies`) and optional (`optionalDependencies`) ranges for the target differ | `^2.4.0` for `multer` as a regular dependency and `^2.5.0` as an optional dependency |
| Unsupported npm and pnpm specifications | The target's requirement cannot be evaluated as a numeric version range | `"multer": "latest"` |
| npm and pnpm shrinkwrap | The release contains a shrinkwrap | `npm-shrinkwrap.json` |
| Conflicting uv and pip requirements | Published requirements specify different constraints for the target | `urllib3<1.27; python_version < "3.10"` and `urllib3<3; python_version >= "3.10"` |
| Unreadable uv and pip requirements | A requirement cannot be read as a package name and version specification | `urllib3 @ https://example.com/urllib3.whl` |
| Unsupported uv and pip specifications | The target's version constraint cannot be evaluated | `urllib3===2.2.2` |
| Release lookup failure | Required information cannot be read from the source | — |
| Lookup limit | The read or time limit prevents the check from completing | — |
