# Go modules remediation pull request development

- **Status:** Implemented (PR creation verified in a validation repository).
- **Started:** October 29, 2026
- **Last updated:** October 30, 2026

## Purpose

Extend language package remediation PRs, previously covering npm, pnpm, pip, and uv, to Go modules.
Create PRs that update `go.mod` and `go.sum` in mapped directories from findings that Trivy detects as `gobinary` in Go binaries in running images.

## Approach

- Run the official `go` command in a worker container, as with existing language packages
- Treat worker container results as untrusted and validate them in KestreLynx

## Decisions

### Matching findings to binaries

- Only handle findings from binaries whose main module path matches the `module` in the mapped `go.mod`
  - Findings from other Go tools included in the base image are excluded from remediation plans
- If a dependency version embedded in the binary does not match `require`, require manual action

### Findings in Go itself

- No PR is created for findings in the standard library, reported as `stdlib`
  - They cannot be fixed by updating `go.mod`
  - A separate remediation plan item explains that rebuilding with the specified Go version or later resolves them

### Updates and the go directive

- Update all targets in a single `go get` invocation without running `go mod tidy`
  - The `go` directive may be raised to the version declared in an updated module's `go.mod`
- If the updated `go` directive exceeds the Go version used to build the running binary, require manual action
  - Leave the decision to raise the Go version required for the build beyond the version the user is using to the user

### When another target requires a higher version

- Omit the target for which a higher version is required by another target from the `go get` arguments and let the dependency requirement raise its version
  - Specifying each target's exact fixed version in `go get` fails when a new version of one target requires a higher version of another
    - For example, `golang.org/x/net v0.60.0` requires `golang.org/x/text v0.42.0`, so the fixed version of `x/text`, `v0.41.0`, cannot be specified at the same time
  - Validate the resulting version using the same checks as other accompanying updates

### Versions used for validation

- Compare vulnerabilities before and after the update using the versions listed in the `require` directives in `go.mod`
  - For example, in the PR used for this validation, compare `golang.org/x/net v0.20.0` and `golang.org/x/text v0.14.0` before the update with `x/net v0.60.0` and `x/text v0.42.0` after the update
  - As with npm and uv, compare module and vulnerability pairs
- Checking only the versions listed in `go.mod` is sufficient
  - With the default `-mod=readonly` setting, `go build` uses only the module versions listed in `go.mod`
  - Verified with `go1.26.0` that if a required module is missing from `go.mod` or its listed version is lower than required, the build stops with `updates to go.mod needed` without the `go` command selecting another version
  - Therefore, even if the working container returns an incomplete `go.mod`, no unchecked versions enter the build; the build simply fails
- Do not check versions found by following dependencies' `go.mod` files
  - Each module's `go.mod` also requires older dependency versions, so following them collects many old versions that the build does not use
  - For example, even updating only `x/net` from `v0.20.0` to `v0.23.0` collected 37 versions, and 88 known vulnerabilities in unused versions, including a 2019 version of `golang.org/x/crypto` and `x/text v0.3.0`, always required manual action
- This validation assumes that users run `go build` with its default settings
  - Running `go get`, `go mod tidy`, or a build with `-mod=mod` before the build causes the `go` command to select other versions, which falls outside the scope of this validation
  - The PR body states this assumption and includes `go build -mod=readonly ./... && go test -mod=readonly ./...` to run in CI

### Accompanying updates and go.sum

- Allow accompanying updates only if they can be reached by following requirements from the target fixed versions' `go.mod` files
- Check `go.sum` against records from `sum.golang.org`
  - KestreLynx adds any missing lines and documents them in the PR body

## Verification method

### Unit tests

- Verified `go.mod` parsing and matching to binaries
- Verified changes to the `go` directive and `go.sum` checks
- Verified explanations of accompanying updates and the PR body

### Integration tests

Used local Docker with Go 1.26 and 1.27 from the official `golang` images, `proxy.golang.org`, `sum.golang.org`, and Trivy.
Verified updates to a module using `golang.org/x/net v0.20.0` in five scenarios covering the following aspects.

- Updates to direct dependencies only
- Updates that also raise `golang.org/x/text`
- Updates that raise the `go` directive from `1.22` to `1.25.0`
- Updates using Go 1.26 and Go 1.27 worker images

All five scenarios became PR candidates.

### Real environment

Ran KestreLynx with local Docker against a Go application in a validation repository.
Verified the workflow from remediation planning through GitHub PR creation.

| Item | Configuration |
| --- | --- |
| Go version used for the build | Go 1.26.10 |
| Modules used | `golang.org/x/net v0.20.0` and `golang.org/x/text v0.14.0` |

## Verification results

The following results are from verification in a real environment on October 30, 2026.

### Remediation plan and worker image

| Check | Result | Significance for the implementation |
| --- | --- | --- |
| Detected findings | Eight HIGH findings in `golang.org/x/net` (fixed versions from `0.23.0` to `0.60.0`) and two findings in `golang.org/x/text` (fixed versions `0.39.0` and `0.41.0`) | Dependencies in the running binary can be treated as remediation targets |
| Target versions | `x/net v0.60.0` and `x/text v0.41.0` | A target version that resolves the target findings can be selected for each module |
| Worker image | Selected `golang1.26` (1.26.10) based on the input `go` directive and `go 1.26.0` in the `go.mod` of `x/net v0.60.0` | A worker image that meets the Go version required for the update can be selected |

### PR changes and checks after the update

| Check | Result | Significance for the implementation |
| --- | --- | --- |
| PR creation | Created a GitHub PR in the validation repository from the remediation plan | Go modules updates can be delivered as PRs |
| `go` directive in `go.mod` | `1.22` → `1.26.0` | The directive can be raised to the Go version required by the updated modules without exceeding the version used to build the running binary |
| `golang.org/x/net` | `v0.20.0` → `v0.60.0` | The update to the target version can be accepted |
| `golang.org/x/text` | `v0.14.0` → `v0.42.0` (`// indirect`) | An update beyond the target version required by another target can also be accepted after checking consistency with the requirement |
| Reason for the `x/text` update | The execution notes in the PR body explain why it was omitted from the `go get` arguments and updated to `v0.42.0` through the requirement from `x/net v0.60.0` | Users can see why the target version differs from the version in the PR |
| `go.sum` | Four lines added | Changes that include hashes for the updated versions can be included in a PR |
| Scans before and after the update | 10 resolved, 0 remaining, 0 new | Comparing the versions listed in `go.mod` can confirm that the target findings are resolved without adding new findings |
| Checks on the PR branch | `go build -mod=readonly ./...` and `go vet -mod=readonly ./...` passed, and the only versions used by the build were `x/net v0.60.0` and `x/text v0.42.0` | The checked versions were confirmed to match the versions used by the build for this application |

## Unverified areas and next steps

- Verification of `golang` images in Kubernetes worker Pods
- Verification on arm64
- Verification in the production environment and on a validation host
- Verification of merging and applying the created PR

## Update history

### October 29, 2026

- Implemented planning, updates, and PR creation, with integration tests.

### October 30, 2026

- Verified PR creation in a real environment.
- Documented handling when another target requires a higher version.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
