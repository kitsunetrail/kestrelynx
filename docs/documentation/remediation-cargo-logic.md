---
title: Rust updates
---

# Rust updates

KestreLynx proposes PRs that update only `Cargo.lock` to fix vulnerabilities found in Rust dependency packages (crates) in running images.
To apply an update to a running image, rebuild the binary with the updated `Cargo.lock` and deploy an image containing the rebuilt binary.

Updates proceed in this order.

1. Match findings from the running image to dependency files in the repository
2. Choose fixed versions in the series compatible with the running versions and check that the releases are published and have not been yanked
3. Select the Rust version to run the update
4. Run `cargo update` for each target with the selected Rust version
5. Check file differences, dependency requirements, checksums, and scan results

For details, see [Rust candidate selection](#cargo-package-selection), [Rust runtime selection](#cargo-runtime-selection), [Rust execution settings](#cargo-worker-settings), and [Rust update validation](#cargo-update-validation).
For terms used on this page, see [Terms](index.md#terms).

## Rust candidate selection {#cargo-package-selection}

Update targets are crates.io crates that Trivy detects in binaries built with cargo-auditable (`rustbinary`) or in files such as `Cargo.lock` in the image (`cargo`).

KestreLynx matches the binary’s root package against the `Cargo.toml` of a standalone package or a package in a workspace (member).

| Finding | Comparison | Handling |
| --- | --- | --- |
| `rustbinary` | The root name and version match a member, and every other embedded crate is reachable from that member through dependencies in `Cargo.lock` | Proceed to candidate selection |
| `rustbinary` | The root is identified, but its name and version match no member | Exclude the binary’s findings from the plan |
| `rustbinary` | No unique root can be identified, or the binary’s package list is missing, duplicated, or truncated | Require manual handling with `rust_binary_not_from_source` |
| `rustbinary` | An embedded crate cannot be reached from the matching member | Require manual handling with `rust_binary_not_from_source` |
| `cargo` | The repository’s `Cargo.lock` contains the name and running version from the finding | Check the crates.io crate as an update candidate |
| `cargo` or `rustbinary` | The finding is for a member itself | Require manual handling with `non_registry_source` |
| `cargo` | `Cargo.lock` has no entry matching the name and running version from the finding | Require manual handling with `not_found_in_source` |

For required files and inputs that require manual handling, see [Rust dependency files](remediation-dependency-formats.md#cargo-inputs).

### Target crate versions {#cargo-target-versions}

KestreLynx selects target crate versions from reported fixes and checks them against release information from crates.io.
Compatible versions share the major version for `1.x.y` and later, the major and minor versions for `0.x.y` where `x > 0`, and all three components for `0.0.y`.

1. For each advisory, select the lowest fixed version newer than the running version in its compatible series
2. Use the highest of those versions as the update lower bound and check whether member dependency declarations allow that version
3. From the stable releases in the same series listed on `index.crates.io`, select the lowest release at or above the lower bound that has not been withdrawn (yanked)

| Situation | Handling |
| --- | --- |
| An advisory lists fixes only in an incompatible series | Require manual handling with `cargo_fix_in_other_series` |
| In step 2, a requirement in a member’s `Cargo.toml` excludes the lower bound | Require manual handling with `range_excludes_fix` |
| In step 2, a requirement in a member’s `Cargo.toml` cannot be evaluated against the lower bound | Require manual handling with `range_not_evaluable` |
| The index lists no qualifying release, or the selected version has build metadata beginning with `+` | Require manual handling with `cargo_release_not_found` |
| `Cargo.lock` contains multiple versions of a crate with the same name as the target crates.io crate | Require manual handling with `multiple_versions` |

For fixes in incompatible series, the hint shows the lowest advisory-listed version in another series that meets the fix conditions for every target vulnerability.
If no common version can be selected and each advisory lists a fix in another series, the hint shows the lowest such fix for each advisory.

## Rust runtime selection {#cargo-runtime-selection}

KestreLynx selects a Rust runtime to update the dependency files.
From the `rust` entries in the [runtime table](remediation-reference.md#supported-runtimes), it uses the newest version with an official image verified on the execution platform.

| Check | Handling |
| --- | --- |
| No runtime version qualifies | Require manual handling with `cargo_runtime_unavailable` |
| Member `rust-version` declarations | Use the lowest declared version, including values inherited from the workspace, as the Rust version the project supports |
| A newly introduced crate version requires a newer Rust version than the project declares | Require manual handling with `cargo_rust_version_too_new` |
| The project has no declaration | Skip the comparison with the crate’s Rust version requirement |

KestreLynx supports `Cargo.lock` formats 3 and 4. It accepts a change from format 3 to 4 only when both conditions hold.

- The project’s `rust-version` is undeclared or at least 1.78
- Every `rust-toolchain` or `rust-toolchain.toml` file in the mapped directory or its ancestors specifies `stable` or a release that can be identified as 1.78 or later

A change from format 3 to 4 that fails these conditions, or any change from format 4 to 3, requires manual handling with `lockfile_format_changed`.

## Rust execution settings {#cargo-worker-settings}

Updates run in a work container (a work Pod on Kubernetes).
Cargo receives the following fixed environment variables.

| Environment variable | Value or handling |
| --- | --- |
| `CARGO_HOME` | `/home/worker/cargo-home`, an empty directory in memory-backed temporary storage for the index cache |
| `RUSTC` | Absolute path to the compiler for the selected Rust version |
| `PATH` | The selected Rust version’s command directory, followed by `/usr/bin` and `/bin` |
| `CARGO_REGISTRIES_CRATES_IO_PROTOCOL` | `sparse` |
| `CARGO_TERM_COLOR` | `never` |

- Supply empty files at the build target paths so Cargo can find the targets without receiving source contents
- Invoke Cargo from the official image by absolute path and run `cargo update --manifest-path Cargo.toml -p <name>@<running-version> --precise <target-version>` for each target in turn
- Run as a non-root user with a read-only root filesystem on Docker and Kubernetes

For shared restrictions, see [Work container restrictions](remediation-worker-logic.md#worker-restrictions). For network destinations, see [Dependency downloads](outbound-communication.md#dependency-downloads).

## Rust update validation {#cargo-update-validation}

KestreLynx accepts an update only if it passes all checks on file changes, dependency requirements, the crates.io index, and scan results.
It does not drop targets from an executed update and rerun the remainder.

### File and dependency changes

| Check | Acceptance condition |
| --- | --- |
| Changed files | Only `Cargo.lock` has changed among the inputs collected after each operation and at the end |
| Packages and versions | Member names and versions are unchanged, and each target crate is present only at its selected version |
| Crates added, removed, or changed in version | Each is a target or a crates.io crate reachable through dependencies from an old target version before the update or a new target version after it |
| Dependencies outside that scope | A reference may change only from a removed version to an in-scope successor with the same name, source, and compatible series |
| New or redirected dependencies | Each satisfies the dependent package’s version requirement in its `Cargo.toml` or the index |
| All dependencies after the update | Every crate is reachable from at least one member |
| Crates whose versions stayed the same | The source and checksum are unchanged |
| Existing series | No version is downgraded within a series |
| Addition of a lower series | No existing version can satisfy the in-scope dependent’s requirement, and the higher-series version and its dependencies are unchanged |

For each crates.io version absent before the update, KestreLynx checks publication and yank status in the index and compares the `checksum` in `Cargo.lock` with the index checksum.
It compares the Rust requirement from the index with the [project’s declared version](#cargo-runtime-selection).

### Scanning and user builds

KestreLynx scans only the original and updated `Cargo.lock` using the same Trivy, vulnerability database, and severities.

1. Check that each scan’s package list includes the name and version of every crates.io crate in the corresponding `Cargo.lock`
2. Check that the target vulnerabilities are gone and that no combination of crate name, version, and vulnerability ID is newly reported

Before merging, run `cargo build --locked && cargo test --locked` in the target workspace with the PR’s `Cargo.lock` as supplied.
With `--locked`, Cargo stops if the build would require a change to `Cargo.lock`, for example because a required dependency is missing.

For the contents of the PR body, see [Rust pull requests](remediation-pr-results.md#cargo-pull-requests).
