---
title: Go updates
---

# Go updates

KestreLynx proposes updates to `go.mod` and `go.sum` in PRs to fix vulnerabilities in dependency modules embedded in Go binaries in running images.
To apply the changes to running images, users must rebuild the binaries and deploy images containing the rebuilt binaries.

Updates proceed in this order.

1. Select update targets from the application's Go binaries
2. Choose target module versions and check that they are published and not retracted
3. Select the Go version to run the update
4. Run `go get` with the selected Go version
5. Check file differences, hashes, dependency requirements, and scan results

For details, see [Go candidate selection](#go-package-selection), [Go runtime selection](#go-runtime-selection), [Go execution settings](#go-worker-settings), and [Go update validation](#go-update-validation).
For terms used on this page, see [Terms](remediation.md#terms).

## Go candidate selection {#go-package-selection}

Update targets are dependency modules embedded in the application's Go binaries.
Trivy labels findings from Go binaries as `gobinary`.

KestreLynx compares the mapped `go.mod` with binaries using these conditions.

| Comparison | Handling |
| --- | --- |
| The binary's main module path matches the `module` in `go.mod` | Select as an update target |
| The main module path does not match | Exclude the binary's findings from the plan |
| Embedded dependency versions do not match `require` | Require manual handling with `go_binary_not_from_source` |
| The package list is truncated | Require manual handling with `go_binary_not_from_source` |

For example, findings from a tool binary in a base image are excluded if its main module path does not match.

For required files and inputs that require manual handling, see [Go dependency files](remediation-dependency-formats.md#go-inputs).

### Target module versions {#go-target-versions}

Target module versions are selected from fixed versions and checked against public release information.

Retraction means the module author uses `retract` in `go.mod` to indicate that a version should not be used.
Selection and verification proceed in this order.

1. For each CVE, choose the lowest fixed version newer than the running version, then use the highest of those versions as the update target
2. Check the target's existence and canonical spelling, including `+incompatible`, using `.info` on `proxy.golang.org`
3. Check `retract` in the `go.mod` of the latest version returned by `@latest` to determine whether the target is retracted
4. If the target is retracted, search `@v/list` for an alternative fixed version

The alternative is the lowest version that meets all of these conditions.

- Has the same major version as the retracted version
- Fits the module path
- Is not a prerelease
- Is newer than the retracted version
- Fixes every target vulnerability
- Is not retracted

The selected alternative is also checked against its canonical version using `.info` before use.
The update notes record that it was selected to replace a retracted version.

Cases where a target cannot be selected automatically are handled as follows.

| Situation | Handling |
| --- | --- |
| Fixed versions exist only under a different module path for another major version | Require manual handling with `fix_in_other_major_version` |
| No version meets the conditions for replacing the retracted version | Require manual handling with `go_release_retracted` |
| The version list needed to find an alternative cannot be retrieved | Require manual handling with `go_release_retracted` |

When another major version is required, the update stage checks [guidance when a fixed version cannot be reached](remediation-fix-hints.md#fix-hints).
For shared rules on fixed-version lower bounds, see [fixed-version lower bounds](remediation-package-logic.md#fix-lower-bound).

### Standard library rebuild guidance {#go-stdlib-rebuild}

Findings for the standard library, `stdlib`, are excluded from `go.mod` update PRs.
A separate fix-plan item explains that rebuilding with the indicated Go version or later fixes the vulnerabilities.

The suggested Go version is the lowest version that fixes every CVE in the series used to build the binary (versions sharing a major and minor version, such as Go 1.26).
If no version in that series qualifies, the guidance suggests a version in a newer series that fixes every CVE.

## Go runtime selection {#go-runtime-selection}

The Go runtime is selected to execute the dependency-file update.
Before selecting Go, KestreLynx reads the target versions' `go.mod` files to check whether they require other targets at versions above their update targets.

If a higher version is required, its `go.mod` is also checked.
The required Go version is the highest version specified by these declarations.

| File containing the declaration | Lines checked |
| --- | --- |
| The input `go.mod` | `go` and `toolchain` |
| The target module version's `go.mod` | `go` |
| The `go.mod` of a target module at the required version above its update target | `go` |

A runtime meeting the required version is selected from KestreLynx's built-in list of supported versions.
For the list, see [Supported runtimes](remediation-reference.md#supported-runtimes).

| Selection | Rule |
| --- | --- |
| Runtime series | Choose the lowest supported series whose listed runtime version meets or exceeds the required version |
| Version to execute | Use Go from the official `golang` image pinned by digest and containing the listed version of the selected series |
| No runtime version qualifies | Require manual handling with `go_runtime_unavailable` |

The Go version used to build the running binaries does not impose an upper bound on the Go runtime used for the update.
Changes to `go` and `toolchain` in `go.mod` are subject to the separate rules in [file and version declaration changes](#go-file-changes).

When a dependency module's requirements prevent Go runtime selection, the guidance identifies the required Go version and the path and version of the module requiring it.
For how this is displayed, see [guidance when a fixed version cannot be reached](remediation-fix-hints.md#fix-hints).

The `packages[].fix_hint.go_line` field used for this guidance is recorded under these conditions.

- If the cause is the `go` line in the `go.mod` of a target version or a required version identified before Go runtime selection, record the module path and version and the required Go version
- If the cause is the project's own `go` or `toolchain` line, do not record `fix_hint.go_line`

## Go execution settings {#go-worker-settings}

Updates run in a work container (a work Pod on Kubernetes).
Go receives the following fixed environment variables.

| Environment variable | Value or handling |
| --- | --- |
| `GOPROXY` | `https://proxy.golang.org` |
| `GOSUMDB` | `sum.golang.org` |
| `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOINSECURE` | Empty |
| `GOFLAGS` | `-mod=mod` |
| `GOTOOLCHAIN` | `local` |
| `GOENV` | `off` |
| `GOWORK` | `off` |
| `CGO_ENABLED` | `0` |
| `GOPATH`, `GOMODCACHE`, `GOCACHE` | Paths in memory-backed temporary storage under `/tmp` |

Commands and caches are handled as follows.

- Use the `go` command in the official image without automatically downloading another toolchain
- On both Docker and Kubernetes, place module and build caches in memory-backed temporary storage under `/tmp`
- On Docker, also mount tmpfs over `/go`
- Update all targets in a single `go get <module>@<version> ...` invocation
- Do not run `go mod tidy`

For direct dependencies, update `require` in `go.mod`; for transitive dependencies, add or update `require` entries with a `// indirect` comment.
Dependent re-resolution is not applied, and accompanying module changes are checked under [collateral module updates](#go-collateral-validation).

For shared restrictions, see [work container restrictions](remediation-worker-logic.md#worker-restrictions); for network destinations, see [dependency downloads](outbound-communication.md#dependency-downloads).

## Go update validation {#go-update-validation}

An update is accepted only if it satisfies all conditions for file changes, `go.sum`, dependency requirements, and scan results.
Go updates are not split by leaving out some targets and updating only the remainder.

For shared acceptance rules and where partial PRs apply, see [accepting update results](remediation-package-logic.md#update-method-and-partial-pull-requests).

### File and version declaration changes {#go-file-changes}

KestreLynx checks file differences and adopted versions, accepting only changes that meet these conditions.

| Check | Acceptance condition |
| --- | --- |
| Changed files | Changes are limited to `go.mod` and `go.sum` |
| Changed parts of `go.mod` | Changes are limited to `require`, `go`, and `toolchain` lines |
| Existing `require` entries | No removals, downgrades, or changes to the presence of `// indirect` comments |
| Other directives | No semantic changes to `module`, `replace`, `exclude`, `retract`, `godebug`, or other directives |
| Adopted target versions | Every target meets or exceeds its target version and satisfies each CVE's fix conditions |

The Go runtime used for the update and the Go versions used to build the running binaries are treated separately.
Declaration changes are checked against two distinct values: the required destination and the upper bound that must not be exceeded.

| Version used for the check | How it is determined |
| --- | --- |
| Required destination for the `go` line | The highest Go version required by the new `go.mod` files of upgraded or added modules |
| Upper bound for changed `go` and `toolchain` versions | The lowest Go version used to build the target binaries |

When the `go` line is raised numerically, it must exactly match the required destination.
Declaration changes are handled as follows.

| Change | Handling |
| --- | --- |
| The `go` version decreases | Reject |
| The raised `go` version is below the required destination | Reject with `unexplained_dependency_diff` |
| The raised `go` version is above the required destination | Reject with `unexplained_dependency_diff` |
| The higher of `go` and `toolchain` decreases, including through removal of `toolchain` | Reject |
| A changed `go` or `toolchain` version exceeds the lowest Go version used to build the target binaries | Require manual handling with `go_line_raised_too_far` |
| A line's version changes while the Go version used to build the target binaries is unknown | Require manual handling with `go_line_raised_too_far` |
| A change meets none of the rejection or manual-handling conditions | Accept if all other checks also pass |

This hypothetical example compares the update runtime with the declaration limit when Go 1.26 is the lowest supported series.

| Value being compared | Version |
| --- | --- |
| The input `go.mod`'s `go` line, with no `toolchain` line | `1.22` |
| Go required by the target's new `go.mod` | `1.24` |
| Go runtime version used for the update | `1.26.10` |
| Go used to build the running binary | `1.22.5` |
| The updated `go.mod`'s `go` line | `1.24` |

Although the update runtime meets the `1.24` requirement, the changed `go` line exceeds the build version, `1.22.5`, so manual handling is required with `go_line_raised_too_far`.

Separately from acceptance conditions, information explaining why the `go` increase was blocked is recorded when all of these conditions hold.

- The raised `go` line equals the highest Go version declared by upgraded or added modules
- The raised `go` version exceeds the lowest Go version used to build the target binaries, or the build version is unknown

If multiple modules declare the highest required Go version, the first in module path order is selected.
`packages[].fix_hint.go_line` records the selected module and its version, the required Go version, the known build version, and the target version requested by the update.

If only the `toolchain` line caused the refusal, `fix_hint.go_line` is not recorded.
For guidance display, see [guidance when a fixed version cannot be reached](remediation-fix-hints.md#fix-hints); for PR text accompanying a `go` line increase, see [Go PRs and CI checks](remediation-pr-results.md#go-pull-requests).

### go.sum verification and completion {#go-sum-validation}

Hashes in `go.sum` are checked against `sum.golang.org` records, and missing required lines are added under these conditions.

- Check added lines and the zip and `go.mod` hashes of upgraded or added modules
- Check hashes of upgraded or added modules even when using existing lines
- If lines for an updated version are missing, KestreLynx adds them from `sum.golang.org` records
- Reject removal of original lines or changes to their hashes
- Reject conflicting values for the same module, version, and hash type

For how added lines are included in the PR body, see [Go PRs and CI checks](remediation-pr-results.md#go-pull-requests).

### Collateral module updates {#go-collateral-validation}

KestreLynx checks that modules upgraded or added alongside a target update can be explained by the requirements of the targets' new versions.
Starting from target versions verified on `proxy.golang.org`, it allows only necessary additions and upgrades reachable through their `go.mod` requirements.

| Check | Handling |
| --- | --- |
| A target exceeds its target version without explanation through another requirement path | Reject with `unexplained_dependency_diff` |
| A target version explained by requirements exceeds its target version | Check it against `retract` in the latest version's `go.mod` |
| A target version above its target version is retracted | Require manual handling with `go_release_retracted` |
| Dependency versions required by the `go.mod` of upgraded or added dependency modules | Check that the dependency versions recorded in the project's updated `go.mod` meet or exceed those requirements |
| A new version has no `go.mod` of its own and only one synthesized by the proxy | Require manual handling |
| Checking dependency requirements would read more than 2,000 module versions | Require manual handling with `go_dependencies_uncheckable` |

Each distinct module path and version counts as one entry toward the limit.
Repeated reads of the same path and version do not count again, but different versions of the same module count separately.

### Scanning and user builds {#go-scan-validation}

The original and updated `go.mod` are scanned and compared using the same Trivy, vulnerability database, and severities.
`go.sum` is excluded from scanning so that lines for old versions are not counted as dependencies.

KestreLynx checks that the target CVEs are gone and that no module, including modules changed alongside the targets, has newly detected vulnerabilities.

The scan covers versions written in `go.mod`, and assumes that user builds use Go's default `-mod=readonly`.
With `-mod=readonly`, builds use only the written versions and stop if a required module is missing or its version is too low.

For CI examples to run before merging and the contents of the PR body, see [Go PRs and CI checks](remediation-pr-results.md#go-pull-requests).
