---
title: npm, pnpm, uv, and pip updates
---

# npm, pnpm, uv, and pip updates

This page explains how KestreLynx updates dependency files for npm, pnpm, uv, and pip, and how it validates the results.
Use the following table to find the sections relevant to your package manager.

| Manager | Sections to read |
| --- | --- |
| npm and pnpm | [Direct dependency version declarations](#direct-dependencies), [Transitive dependency update scope](#transitive-dependencies), [Node.js selection](#node-selection) and [compatibility requirements](#node-compatibility), [Tool versions and retrieval](#node-python-tools), [Temporarily removing direct dependencies](#pnpm-temporary-removal) (pnpm only), [Collateral change validation](#change-validation) |
| uv | [Direct dependency version declarations](#direct-dependencies), [Transitive dependency update scope](#transitive-dependencies), [Python selection for uv](#uv-python-selection), [Tool versions and retrieval](#node-python-tools), [Collateral change validation](#change-validation) |
| pip | [Target environment for pip validation](#pip-target-environment), [Updating pinned versions with pip](#pip-pinned-updates) |

For the terms used on this page, see [Terms](remediation.md#terms).

## Update scope {#node-python-update-scope}

This section explains which dependency version declarations npm, pnpm, and uv can change to reach the update target.
For the rules used to determine the update target, see [Fixed-version lower bounds](remediation-package-logic.md#fix-lower-bound).

### Direct dependency version declarations {#direct-dependencies}

For npm, pnpm, and uv, direct dependencies are dependencies declared by the project itself.
If a declaration in `package.json` or `pyproject.toml` excludes the update target, KestreLynx edits the version while preserving the operator, provided the notation is supported.

If the existing declaration allows the update target, KestreLynx preserves it.
If an edit is needed but the notation or location is unsupported, KestreLynx uses manual handling (`manual`, shown as “Needs a decision” in Slack).

The following hypothetical examples compare changes to the operator and version for a dependency in `package.json` with an update target of `1.2.6`.

| Declaration before | Declaration after | Decision |
| --- | --- | --- |
| `~1.0.0` | `~1.2.6` | Edit while preserving `~` because the target is excluded |
| `^1.2.5` | `^1.2.5` | Preserve the declaration because the target is allowed |

After the update, KestreLynx checks that the declarations in the dependency declaration file and lockfile agree, and that the adopted version is within the declared range.

For editable notation and locations, see [npm dependency files](remediation-dependency-formats.md#npm-inputs), [pnpm dependency files](remediation-dependency-formats.md#pnpm-inputs), and [uv dependency files](remediation-dependency-formats.md#uv-inputs).

### Transitive dependency update scope {#transitive-dependencies}

For npm, pnpm, and uv, transitive dependencies are dependencies used through other packages, and updates stay within the ranges declared by their parent packages.
The updated versions are checked against the parent packages’ declarations returned by the public registry.

Normal updates apply the following restrictions and checks.

- Do not raise the version of a parent package outside the update targets to introduce a fixed version
- Do not add `overrides` to force a fixed version
- Check that changes to targets and accompanying dependencies preserve version requirements between dependent packages and their dependencies

If the [update methods by manager](remediation-package-logic.md#manager-update-methods) do not reach the update target, KestreLynx tries [re-resolution from dependent packages](remediation-reresolution-logic.md#dependent-reresolution) for eligible targets.
It then evaluates the [conditions for a partial PR](remediation-package-logic.md#partial-pr-selection) based on the remaining targets.

## Runtime selection {#node-python-runtimes}

KestreLynx selects Node.js and Python for updating dependency files with npm, pnpm, uv, and pip, and the environments used to check dependency compatibility.

### Node.js selection {#node-selection}

For npm and pnpm, KestreLynx selects Node.js to run dependency file updates using the project’s version declarations and the manager’s requirements.
This process does not change the application’s Node.js version.

Runtime versions are selected from the list of supported versions built into KestreLynx.
The list changes with KestreLynx updates and is documented in [Supported runtimes](remediation-reference.md#supported-runtimes).

Version files are `.nvmrc` and `.node-version`; ranges come from `engines.node` and Node.js entries in `devEngines.runtime` and `engines.runtime` in `package.json`.
A Node.js series is a major version such as `22`, selected according to the declarations as follows.

| Declarations | Selection rule |
| --- | --- |
| A version file exists | Use the declared major series and select the minor and patch version from the supported-version list |
| Only ranges are declared | Select the oldest supported series satisfying all ranges and the manager’s requirements |
| No declarations | Prefer the newest series currently in LTS, then check other series from newest to oldest for a compatible combination |
| A version file and ranges exist | Check that declarations agree and that the runtime version in the declared series satisfies every range |

The following restrictions apply to selection and execution.

- Do not use a series past its end of support to run updates
- Use manual handling when declarations conflict or no runtime version satisfies the requirements
- Do not switch to another Node.js series and repeat the update after an update fails

For recognized declarations and notation, see [Node.js version declarations](remediation-dependency-formats.md#node-declarations).

### Node.js compatibility requirements {#node-compatibility}

KestreLynx uses only combinations of Node.js and npm or pnpm that satisfy the following compatibility requirements.

- The manager version satisfies the version or ranges declared by the project
- The manager’s own `engines.node` allows the Node.js version used for the update
- The Node.js requirements in the retrieved metadata are also satisfied when fetching the tool

The project’s minimum Node.js version is the lowest version satisfying all declarations in `.nvmrc`, `.node-version`, and the `engines.node`, `devEngines.runtime`, and `engines.runtime` fields of `package.json`.
When that minimum differs from the Node.js version used for the update, KestreLynx also checks added or changed dependencies’ `engines.node` against the minimum.

If a dependency excludes the minimum or its requirements cannot be interpreted, KestreLynx uses manual handling.
If Node.js is not declared, no minimum is set for this check.

For example, if `.nvmrc` declares `22` and `engines.node` declares `>=22.12`, the minimum is `22.12.0`.
Even when the update runs on Node.js `22.23.5`, the requirements of added or changed dependencies are checked against that minimum as follows.

| Dependency’s `engines.node` | Result against the minimum |
| --- | --- |
| `>=22.12` | Satisfies this compatibility check because it allows `22.12.0` |
| `>=22.13` | Requires manual handling because it excludes `22.12.0` |

This check compares version declarations; it does not run the application on the minimum Node.js version.

### Python selection for uv {#uv-python-selection}

For uv, KestreLynx selects Python for generating the lockfile using `requires-python` and the version file.
A Python series is an X.Y version such as `3.13`, selected as follows.

| Declarations | Selection rule |
| --- | --- |
| Only `requires-python` exists | Select the oldest supported series whose runtime version satisfies the range |
| A version file and `requires-python` exist | Select the file’s X.Y series and check declaration consistency and runtime compatibility |
| No `requires-python` | Use manual handling regardless of whether a version file exists |

The selected version must meet the following conditions.

- The patch version in the version file may differ from the work image’s patch version
- The actual Python version in the supported-version list must satisfy `requires-python`
- Do not relax declarations to run an update if no supported series satisfies the requirements

For recognized notation, see [Python version declarations](remediation-dependency-formats.md#python-declarations).

### Target environment for pip validation {#pip-target-environment}

The Python version that runs pip and the target environment for dependency resolution are selected separately.
Updates run on the default Python in the supported-version list, while validation targets the Python X.Y, platform, and ABI inferred from the running image.

A `requirements.txt` in the same repository, branch, and dependency directory may be shared by multiple running images.
KestreLynx checks that Python X.Y, platform, and ABI agree across the images where the target packages were detected.

In the following hypothetical example, a target package from the same `requirements.txt` is detected in two running images.

| Running image where detected | Python | Platform | ABI |
| --- | --- | --- | --- |
| Image A | `3.12` | Debian, `linux/amd64` | `cp312` |
| Image B | `3.11` | Debian, `linux/amd64` | `cp311` |

Because the Python versions and ABIs differ, the entire update for that `requirements.txt` requires manual handling.

The validation environment is determined under the following conditions.

- Infer Python X.Y from information such as package paths obtained by the scan
- Use manual handling if the Python version or platform cannot be determined
- Use manual handling if the validation environments differ between origins of the target packages
- Do not create an update PR if the target Python is past its end of support, even if the Python running the update is still supported

## Tool versions and retrieval {#node-python-tools}

Here, tools means npm, pnpm, and uv themselves, used to run updates.
For how KestreLynx retrieves tools and passes them to the work container, see [Work container execution](remediation-worker-logic.md#worker-execution).

### Tool version selection {#tool-version-selection}

KestreLynx prioritizes project declarations when selecting npm, pnpm, and uv versions, using the following rules.

| Declarations | Selection rule |
| --- | --- |
| An exact version is declared | Use it if supported and consistent with the other declarations |
| Only ranges are declared | Use the default for the selected runtime if it satisfies every range |
| No declarations | Use the default defined by KestreLynx |
| Declarations conflict or the default is outside the range | Use manual handling without automatically searching for another tool version within the range |

For pip, KestreLynx uses the version included in the official Python image used for the update.
Managers are prevented from switching to another tool version themselves.

For recognized declarations, see [Tool version declarations](remediation-dependency-formats.md#tool-declarations); for defaults, see [Supported runtimes](remediation-reference.md#supported-runtimes).

### Tool retrieval and verification {#tool-verification}

KestreLynx retrieves the selected npm, pnpm, or uv release and verifies its distribution metadata and downloaded contents before passing it to the work container.
The following checks apply during retrieval and handoff.

| Checked item | Requirement |
| --- | --- |
| Distribution metadata | Matches the requested tool and version, with a verifiable download location and hash |
| Distribution artifact | Matches the registry hash and has a supported archive structure and executable entry |
| Hash in `package.json`’s `packageManager` | The artifact covered by the declaration also matches that hash, if declared |
| Files passed to the container | Match the recorded sizes and hashes |

An example of the hash declaration notation is `"packageManager": "pnpm@11.28.5+sha512.<hex>"` (`<hex>` stands for the omitted actual hash).
The hash in a [tool version declaration](remediation-dependency-formats.md#tool-declarations) covers the tool’s distribution artifact and is separate from dependency package hashes.

KestreLynx does not ignore hash mismatches or inconsistent artifacts and execute them.
For destinations and where credentials are sent, see [Communication destinations](outbound-communication.md#outbound-communication).

### Waiting after tool publication {#tool-release-age}

For the npm, pnpm, and uv tools themselves, KestreLynx checks whether the configured waiting period has elapsed since publication under the following rules.

- Defer versions that have not reached the waiting period to a later cycle (`deferred`)
- Also defer versions whose publication time cannot be verified
- Do not substitute another tool version and run while waiting

The following comparison distinguishes waiting conditions for tools, normal updates, and re-resolution.

| What must wait | Process applying the check | Waiting condition |
| --- | --- | --- |
| npm, pnpm, and uv themselves | KestreLynx tool retrieval and reuse | `remediation.worker.tool_versions.min_release_age` in [Work containers](configuration.md#remediation-worker), default `72h` |
| Dependency packages in normal npm, uv, and pip updates | Each manager | KestreLynx does not specify an additional waiting period |
| Dependency packages in normal pnpm updates | pnpm | Follow the release-age restrictions built into the selected pnpm version |
| Package versions newly introduced by re-resolution | KestreLynx re-resolution validation | Wait 72 hours after publication ([Release waiting periods and retries](remediation-reresolution-logic.md#dependent-reresolution-waits)) |

The waiting period applied by pnpm during normal updates depends on the default in the selected pnpm version.
Changing `min_release_age` for the tool itself does not change the waiting period for dependency packages.

### Tool cache reuse {#tool-cache}

KestreLynx checks cached npm, pnpm, and uv tools’ contents and usage conditions on reuse, and manages space under the following rules.

- Read the files again, compute their hashes, and verify that they match the recorded contents
- Recheck the hash declared in `packageManager`, the publication waiting period, and Node.js requirements
- Do not execute cached contents as they are if they cannot be verified
- Defer if removing unused cache entries does not free enough space

For capacity settings, see [Work containers](configuration.md#remediation-worker); for stored contents, see [Stored files](remediation-pr-logic.md#stored-records).

## Updates and validation {#node-python-update-checks}

For npm, pnpm, uv, and pip, KestreLynx updates and validates dependency files as follows.

| Manager | Files changed | Update method | Main checks |
| --- | --- | --- | --- |
| npm | `package-lock.json`, plus `package.json` when needed | Remove target entries and regenerate the lockfile | Original input regenerates without package changes, and the updated result is consistent |
| pnpm | `pnpm-lock.yaml`, plus `package.json` when needed | Remove target entries and regenerate the lockfile without freezing it | Dependency consistency with the lockfile frozen before and after the update |
| uv | `uv.lock`, plus `pyproject.toml` when needed | Specify the update version for each package and update the lockfile | Consistency between the lockfile and project declarations before and after the update |
| pip | `requirements.txt` | Rewrite pinned versions and update existing hashes | Dry-run dependency resolution before and after the update for the running image’s environment |

For update method details, see [Update methods by manager](remediation-package-logic.md#manager-update-methods).

### Temporarily removing direct dependencies with pnpm {#pnpm-temporary-removal}

When a normal pnpm update targets only transitive dependencies, KestreLynx may temporarily remove a direct dependency entry from the working copy to resolve the lockfile again.
Unlike [re-resolution from dependent packages](remediation-reresolution-logic.md#dependent-reresolution), which can also raise dependent package versions, this operation does not allow the temporarily removed direct dependency itself to change.

After the update, the temporarily removed direct dependency is checked as follows.

- Verify that its version, declaration, and dependency relationships return to their original state
- Use manual handling if that direct dependency also changes or no direct dependency is available to trigger lockfile resolution

### Updating pinned versions with pip {#pip-pinned-updates}

For pip, KestreLynx prepares proposed changes to versions pinned with `==` in `requirements.txt`, then checks dependency resolution before and after the update.
For input requirements, see [pip dependency files](remediation-dependency-formats.md#pip-inputs).

Pinned-version updates proceed in the following order.

1. Preserve the original `requirements.txt` and prepare content with pins changed to fixed versions
2. Check dependency resolution with a dry run using the original content and obtain the pre-update pip report
3. Check post-update dependency resolution with a dry run using the rewritten content

For a target whose range allows the update target, KestreLynx does not change the file or create an update PR for that target.
This confirms that the declaration allows the update target; it does not verify that a rebuild resolves the vulnerability.

The result is presented to the user as “Rebuild,” indicating an expected resolution.

If the post-update dry run cannot resolve dependencies, KestreLynx uses the pre-update pip report and PyPI’s `requires_dist` to find dependent packages whose requirements exclude the new pinned version.
Markers, which specify the environments where a requirement applies, are evaluated for the running image’s environment, and requirements are handled as follows.

- Evaluate all applicable requirements from the same dependent package for the same target together as one range
- Exclude requirements from packages being updated because only their pre-update requirements are known

Targets with an identified blocking dependent package receive manual handling with `dependents_hold_back`; otherwise, the reason remains `post_update_check_failed`.
If the first check identifies blocking dependent packages for only some targets, KestreLynx excludes those targets and retries the remaining updates once from the original input.

The result becomes a partial PR candidate if excluded targets keep their original versions and the remaining updates pass dependency resolution, diff, and scan checks and meet the [conditions for partial PRs](remediation-package-logic.md#partial-pr-selection).
If no targets remain or the retry fails validation, the update to that `requirements.txt` does not become a PR candidate.

KestreLynx does not re-resolve from dependent packages for pip; it displays hints about the verified published versions of those dependent packages ([Overview of the hints](remediation-fix-hints.md#fix-hints)).

### Collateral change validation {#change-validation}

For npm, pnpm, uv, and pip, KestreLynx compares changes outside the intended target packages with public registry information and applies the following conditions to determine whether they are needed for the update.
It does not rely solely on the lockfile or dependency resolution results returned by the work container.

| Change | Acceptance condition or handling |
| --- | --- |
| Added, changed, or removed targets and dependencies needed for their update | Accept if dependency relationships, declared ranges, artifact references, and integrity information pass validation |
| Added, changed, or removed npm `deprecated` notes | Accept if the note matches what the npm registry returns for that package version |
| A dependency of a non-target package moves to another version | Conditionally accept only moves to the version of the same package used by an update target |
| Changes to configuration files provided for reading | Reject and use manual handling |
| Lockfile format changes or unexplained collateral changes | Reject and use manual handling |

When aligning a non-target package’s dependency version, the dependent package’s own version and other contents must remain unchanged, and declared ranges and distribution information must remain consistent.
In the following hypothetical example, focus on the versions of `shared` used by the update target `app` and the non-target package `browsers`.

```text
Before                         After
project                        project
|-- app 1.0.0                  |-- app 1.1.0          Update target
|   `-- shared 1.0.0            |   `-- shared 1.1.0   Dependency used by the target
`-- browsers 1.0.0             `-- browsers 1.0.0     Dependent package version stays unchanged
    `-- shared 1.0.0                `-- shared 1.1.0   Only the dependency version is aligned
```

Aligning `shared` to `1.1.0` is allowed if it is consistent with the range declared by `browsers` and the distribution information.
Changing `browsers` itself to `1.0.1`, or moving only its dependency to `shared 1.2.0`, is not allowed.

For dependency artifacts, KestreLynx checks references and hashes against public registry information.
This check does not unpack dependency artifacts and compare all their contents.
