---
title: Webhook remediation update record fields
---

# Webhook remediation update record fields

This page describes the fields in `language_items[].update` in the remediation plan included in the generic webhook payload.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall structure.

`language_items[].update` is included when there is a record of update processing or re-resolution through dependent packages, and omitted when no record is available.
It may be `{}` when processing stops during preparation, or contain only a record of a skipped re-resolution attempt.

Check `update_executed` and `post_update_check_executed` in [Language package fields](webhook-remediation-language-reference.md#remediation-language-fields) to see whether the update and post-update check ran in this cycle.
See [Report fields](webhook-reference.md#report-fields) for table conventions.

## Update records {#language-update-fields}

The fields in `language_items[].update` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `steps` | array of objects | Records of [executed operations](#language-update-steps). | omitted |
| `notes` | array of strings | Additional details, such as warnings during update processing. | omitted |
| `diff` | object | [Dependency diff](#language-update-diff). | omitted |
| `runtime` | object | Record of the [runtime](#language-runtime-fields) for the update. | omitted |
| `tool` | object | Record of the [tools](#language-tool-fields) for the update. | omitted |
| `deprecated_changed` | integer | Number of package name and version combinations with added, removed, or changed deprecation notes. | omitted when the count is 0 |
| `manifest_edits` | array of objects | [Direct dependency version specification changes](#language-update-manifest-edits) made before the update. | omitted |
| `chain` | object | [Results of re-resolution through dependent packages](#language-chain-fields). | omitted |
| `go` | object | [Go update records](#language-go-update). | omitted |
| `maven` | object | [Maven update records](#language-maven-update). | omitted |
| `gradle` | object | [Gradle update records](#language-gradle-update). | omitted |

The following fields have additional notes.

- `deprecated_changed`
    - The same name and version count once even when they appear in multiple lockfile entries
    - Notes removed along with their package entries are not counted

The webhook includes the count of changed deprecation notes, but not the names of affected entries.
The PR body lists those names and whether notes were added, removed, or changed.

The following example excerpts operation identifiers and exit results, the diff, and version specification changes from `language_items[].update`.

```json
{
  "steps": [
    {
      "id": "update",
      "exit_code": 0,
      "duration_ms": 0
    }
  ],
  "diff": {
    "changed": [
      "node_modules/minimist"
    ]
  },
  "manifest_edits": [
    {
      "file": "package.json",
      "section": "dependencies",
      "name": "lodash",
      "from": "^4.17.15",
      "to": "^5.0.0",
      "major_change": true
    }
  ]
}
```

### Executed operations {#language-update-steps}

The fields in each element of `language_items[].update.steps[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `id` | string | Identifier indicating which stage of update processing the operation belongs to. | — |
| `op` | string | Type of operation executed. | — |
| `scratch` | boolean | `true` when the operation runs on a copy of the working files and its changes are not carried into subsequent operations. | omitted when `false` |
| `exit_code` | integer | Operation exit code, with `0` indicating success. | `0` |
| `duration_ms` | integer | Operation execution time in milliseconds. | `0` |

The values of `id` are listed below.

| Value | Meaning |
| --- | --- |
| `baseline` | Check of the dependency files before the update. |
| `update` | Update of the dependency files. |
| `check` | Recheck of the dependency files after the update. |

The values of `op` are listed below.

| Value | Meaning |
| --- | --- |
| `npm.relock` | Regeneration of package-lock.json by npm. |
| `pnpm.frozen_check` | Consistency check by pnpm without changing the lockfile. |
| `pnpm.relock` | Regeneration of the lockfile by pnpm. |
| `uv.check` | Lockfile consistency check by uv. |
| `uv.upgrade` | Update of target packages by uv. |
| `uv.upgrade_chain` | Re-resolution including dependent packages by uv. |
| `pip.dry_run` | Dependency resolution check by pip without installation. |
| `go.get` | Update of target modules by Go. |
| `gradle.update_locks` | Lockfile update for target packages by Gradle. |

Do not treat `id` as a unique key within the array, because a stage may run again.
See [Update methods by package manager](remediation-package-logic.md#manager-update-methods) for the scope of each operation.

### Direct dependency version specification changes {#language-update-manifest-edits}

The fields in each element of `language_items[].update.manifest_edits[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `file` | string | Repository path of the file being changed. | — |
| `section` | string | Section declaring the direct dependency. | — |
| `name` | string | Name of the package whose version specification changed. | — |
| `from` | string | Version specification before the change. | — |
| `to` | string | Version specification after the change. | — |
| `major_change` | boolean | `true` when the version specification change constitutes a major-version change. | omitted when `false` |

The values of `section` are listed below.

| Value | Meaning |
| --- | --- |
| `dependencies` | Regular dependencies in package.json. |
| `devDependencies` | Development dependencies in package.json. |
| `optionalDependencies` | Optional dependencies in package.json. |
| `project.dependencies` | Project dependencies in pyproject.toml. |

The following fields have additional notes.

- `from` and `to`
    - For npm and pnpm, these represent version specifications such as `^4.17.15`
    - For uv, these represent dependency declarations that include the package name, such as `urllib3==1.26.17`
- `major_change`
    - For `0.x`, a minor-version change is treated as a major-version change

See [Direct dependency version specifications](remediation-node-python-logic.md#direct-dependencies) for the conditions under which changes are made.

### Dependency diff {#language-update-diff}

The fields in `language_items[].update.diff` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `added` | array of strings | Identifiers of added dependency entries. | omitted |
| `changed` | array of strings | Identifiers of dependency entries whose contents changed. | omitted |
| `removed` | array of strings | Identifiers of removed dependency entries. | omitted |
| `truncated` | boolean | `true` when diff lists were truncated. | omitted when `false` |
| `followed` | array of objects | [Entries with changes only to dependency versions](#language-update-followed). | omitted |

The strings in `added`, `changed`, and `removed` identify the following units.

| Manager | What is identified | Example strings |
| --- | --- | --- |
| npm | Package location in package-lock.json. | `node_modules/minimist`, `node_modules/mkdirp/node_modules/minimist` |
| pnpm | Key of an entry in pnpm-lock.yaml snapshots, normalized for comparison. | `minimist@1.2.8`, `host@1.0.0(peer@2.0.0)` |
| uv | Package name and version combination in uv.lock. | `urllib3==1.26.18` |
| pip | Package name from the installation report, lowercased with consecutive `-`, `_`, and `.` characters replaced by a single `-`. | `urllib3`, `typing-extensions` |

The following fields have additional notes.

- `added`, `changed`, and `removed`
    - For pnpm, peer dependency information related to update targets is removed from keys, so they may differ from the keys written in the lockfile
    - For pnpm and uv, identifiers include versions, so a version update may be recorded as removal of the old entry and addition of a new one
    - `changed` also includes entries whose own package version stays the same while contents such as dependencies change
- `truncated`
    - Applies to `added`, `changed`, `removed`, and `followed`, with each list limited to 100 entries when truncated
    - This 100-entry limit does not apply to `followed[].moves`
    - If an update is rejected during diff validation, lists may be recorded before truncation, so receivers must not assume a fixed maximum length of 100

This diff compares lockfiles before and after the update for npm, pnpm, and uv, and installation reports before and after the update for pip.
See the respective update records for Go, Maven, and Gradle changes.

### Entries with changes only to dependency versions {#language-update-followed}

Each element of `language_items[].update.diff.followed[]` represents one package whose dependency versions changed even though it was not an update target.
The package's own version stays the same.

The following example shows a project that uses A and B directly, with both A and B using C.
The versions before and after updating A are listed below.

| Item | Before the update | After the update |
| --- | --- | --- |
| A's version | `1.0` | `1.1` |
| B's version | `2.0` | `2.0` |
| C version used by A | `1.0` | `1.1` |
| C version used by B | `1.0` | `1.1` |

Whether each package in this example appears in `followed` and the reasons are listed below.

| Package | `followed` | Reason |
| --- | --- | --- |
| A | Not included | It is an update target |
| B | Included | Its own version stays the same, and only the C version it uses changed |
| C | Not included | Its version changed as a result of A's update |

The following is one element of `followed[]` representing B in this example.

```json
{
  "entry": "B@2.0",
  "moves": [
    {
      "name": "C",
      "from": "1.0",
      "to": "1.1"
    }
  ]
}
```

The fields in each element of `language_items[].update.diff.followed[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `entry` | string | Entry whose dependency versions changed, expressed as `package-name@version`. | — |
| `moves` | array of objects | Version changes in dependencies referenced by that entry. | — |

Before the lists are truncated, entries recorded in `followed` also appear in `changed`.
For npm, pnpm, uv, and pip, `entry` uses the `name@version` format, which differs from the identifiers in `added`, `changed`, and `removed`.

The fields in each element of `language_items[].update.diff.followed[].moves[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Name of the dependency whose referenced version changed. | — |
| `from` | string | Version referenced before the change. | — |
| `to` | string | Version referenced after the change. | — |

See [Checking related changes](remediation-node-python-logic.md#change-validation) for the conditions under which changes are allowed.

## Runtime for the update {#language-runtime-fields}

The fields in `language_items[].update.runtime` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `id` | string | Identifier of the selected runtime. | — |
| `version` | string | Node.js, Python, Go, or Gradle version included in the runtime. | — |
| `pip` | string | pip version included in the Python image. | omitted |
| `image` | string | Work image reference pinned by repository name and image index digest. | omitted |
| `platform` | string | Execution platform of the work image. | omitted |
| `digest` | string | Image manifest digest for the execution platform. | omitted |
| `support` | string | Runtime support status. | omitted |
| `eol` | string | End-of-support date in `YYYY-MM-DD` format. | omitted |
| `basis` | string | Runtime selection basis. | omitted |
| `declared` | array of objects | [Version declarations used for selection](#language-runtime-declared). | omitted |
| `excluded` | array of objects | Records of lower [series not selected](#language-runtime-excluded). | omitted |
| `engines_floor` | string | Lowest Node.js version checked for dependency compatibility. | omitted |

The formats of `id` values are listed below.

| Value format | Meaning |
| --- | --- |
| `node<major>` | Node.js series, such as `node22`. |
| `python<major>.<minor>` | Python series, such as `python3.13`. |
| `golang<major>.<minor>` | Go series, such as `golang1.26`. |
| `gradle<version>-jdk<JDK-major>` | Gradle and JDK combination, such as `gradle9.8.2-jdk17`. |

See [Supported runtimes](remediation-reference.md#supported-runtimes) for available series and Gradle/JDK combinations.

The values of `platform` are listed below.

| Value | Meaning |
| --- | --- |
| `linux/amd64` | Linux AMD64 environment. |
| `linux/arm64` | Linux ARM64 environment. |

The values of `support` are listed below.

| Value | Meaning |
| --- | --- |
| `lts` | Node.js long-term support period. |
| `maintenance` | Node.js maintenance period. |
| `security` | Python security-fix period. |
| `bugfix` | Python bug-fix period. |
| `supported` | Go support period. |

The values of `basis` are listed below.

| Value | Meaning |
| --- | --- |
| `declared_file` | Selection based on a version declaration in `.node-version`, `.nvmrc`, or `.python-version`. |
| `lowest_in_range` | Selection of the lowest series that satisfies the version ranges and execution requirements. |
| `default` | Default selection when no Node.js version is declared. |
| `go_lines` | Selection based on the versions required by go lines in the project and the target module versions. |

The following fields have additional notes.

- `image` and `digest`
    - `image` uses a reference such as `node@sha256:…`, and `digest` uses the `sha256:…` format
- `support` and `eol`
    - Omitted for Gradle runtimes
- `engines_floor`
    - Recorded when the lowest Node.js version allowed by the project's declarations differs from the Node.js version in the selected runtime

See [Runtime selection](remediation-package-logic.md#runtime-and-tool-versions) for the selection method.

### Version declarations used for selection {#language-runtime-declared}

The fields in each element of `language_items[].update.runtime.declared[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `source` | string | File name or configuration field from which the version declaration was read. | — |
| `value` | string | Value of the version declaration read. | — |

`source` contains values such as `.nvmrc`, `engines.node`, and `requires-python`.
Long `value` strings are truncated, so do not use them to reconstruct declarations or write configuration files back.

### Series not selected {#language-runtime-excluded}

The fields in each element of `language_items[].update.runtime.excluded[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `id` | string | Identifier of the runtime not selected. | — |
| `why` | string | Reason the series was not selected. | — |
| `eol` | string | End-of-support date in `YYYY-MM-DD` format. | omitted |
| `manager` | string | Name of the package manager whose execution requirements were not met. | omitted |
| `manager_version` | string | Version of the package manager whose execution requirements were not met. | omitted |
| `engines` | string | Supported Node.js version range declared by the package manager. | omitted |

The values of `why` are listed below.

| Value | Meaning |
| --- | --- |
| `end_of_life` | Support has ended or no usable work image is available. |
| `manager_engines` | Does not satisfy the package manager's supported Node.js version range. |
| `declarations` | Does not satisfy the project's runtime or tool declarations. |

The values of `manager` are listed below.

| Value | Meaning |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |

The following fields have additional notes.

- `id`
    - Uses the same format as `id` in [Runtime for the update](#language-runtime-fields), and also includes series whose support has ended, such as `node20` and `python3.10`
- `eol`
    - Recorded when `why` is `end_of_life` and the end date is known
- `manager`, `manager_version`, and `engines`
    - Recorded when `why` is `manager_engines`

## Tools for the update {#language-tool-fields}

The fields in `language_items[].update.tool` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Package manager name. | — |
| `version` | string | Selected package manager version. | — |
| `source` | string | Tool version selection basis. | — |
| `format` | string | Format of the retrieved distribution. | omitted |
| `size` | integer | Distribution size in bytes. | omitted when `0` |
| `sha256` | string | Distribution SHA-256 in hexadecimal. | — |
| `sha512` | string | Distribution SHA-512 in hexadecimal. | omitted |
| `published_at` | string | Distribution publication time in RFC 3339 format. | `"0001-01-01T00:00:00Z"` |
| `registry_digest` | string | Distribution digest reported by the registry. | omitted |
| `spec_hash` | string | Hash used to verify the distribution against the project's declaration. | omitted |

The values of `name` are listed below.

| Value | Meaning |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |
| `uv` | uv |

The values of `source` are listed below.

| Value | Meaning |
| --- | --- |
| `declared` | Exact version declared by the project. |
| `default` | Default version when the project has no tool version declaration. |
| `default_in_range` | Default version within the version ranges declared by the project. |

The values of `format` are listed below.

| Value | Meaning |
| --- | --- |
| `npm-tgz` | Compressed archive in npm format. |
| `wheel` | Distribution in Python wheel format. |

The following fields have additional notes.

- `published_at`
    - When the publication time is unset, the field is still included with the zero time
- `registry_digest`
    - Preserves the notation reported by the registry, so its string format may differ from `sha256` and `sha512`
- `spec_hash`
    - Uses the algorithm name and hash value joined by `.`, such as `sha512.<hexadecimal>`

pip, Go, and Gradle use tools included in the work image, so they do not emit this object.
Maven updates do not emit this object either.

See [Tool version selection](remediation-node-python-logic.md#tool-version-selection) for the selection method and [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) for verification.

## Results of re-resolution through dependent packages {#language-chain-fields}

In the example where `mkdirp 0.5.1` requires `minimist 0.0.8`, `blocked` contains this requirement and `tops` contains `mkdirp`, whose version is selected again.
Check `language_items[].update.chain.outcome` for the re-resolution result.

The fields in `language_items[].update.chain` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `outcome` | string | Re-resolution result. | — |
| `reason` | string | [Reason code](remediation-reason-codes.md#reason-codes) for the result. | omitted |
| `detail` | string | Additional details about the result or reason. | omitted |
| `source` | string | Re-resolution method, including skipped attempts. | — |
| `blocked` | array of objects | [Version requirements blocking updates](#language-chain-blocked) to fixed versions. | `[]` |
| `tops` | array of objects | [Direct dependencies and related changes](#language-chain-moves): direct dependencies whose versions are selected again. | `[]` |
| `moves` | array of objects | [Direct dependencies and related changes](#language-chain-moves): changes outside the update targets and direct dependencies. | omitted |
| `truncated` | boolean | `true` when the `moves` list is incomplete. | omitted when `false` |
| `usage` | object | [Processing usage](#language-chain-usage), including normal updates and reruns. | — |
| `hints` | array of objects | [Published release information for dependent packages](webhook-remediation-language-reference.md#language-fix-hint-releases) when a fixed version cannot be reached. | omitted |

The values of `outcome` are listed below.

| Value | Meaning | Example |
| --- | --- | --- |
| `adopted` | Adoption. | `mkdirp` updates to `0.5.6` and `minimist` to `1.2.8`, and the checks pass. |
| `not_fixed` | Fixed version not reached, including when resolving again for the fixed version with uv found no solution. | Selecting dependent packages again does not bring the target to a fixed version. |
| `rejected` | Rejection or a stop after repeated waits. | The update introduces another vulnerability. |
| `failed` | Processing failure. | The package manager exits with an error. |
| `not_tried` | Skipped attempt. | More than five direct dependencies need their versions selected again. |
| `deferred` | Deferral. | A newly introduced version is less than 72 hours old. |

The values of `source` are listed below.

| Value | Meaning |
| --- | --- |
| `chain_job` | Re-resolution through an additional update, including attempts skipped before execution. |
| `first_run` | Reassessment of the initial uv update result, including attempts skipped before reassessment. |

Even when `outcome` is `not_tried`, the value is `first_run` if the initial uv update produced a lockfile for reassessment, and `chain_job` otherwise.
Skipping an attempt does not cause `source` to be omitted or set to an empty string.

The following fields have additional notes.

- `reason`
    - When resolving again for the fixed version with uv finds no solution, `outcome` is `not_fixed` and `reason` is `no_resolution`
- `hints`
    - Checked for npm, pnpm, and uv when `outcome` is `not_fixed`, `rejected`, or `not_tried`
    - Included when the dependent package blocking the update is known and information about its published releases is available to provide guidance
- `truncated`
    - `moves` contains at most 100 entries, and this flag is `true` when entries beyond that limit are omitted
    - Also `true` when the underlying `update.diff` was truncated
    - For pnpm, `moves` is omitted and this flag is set to `true` when diff identifiers cannot be matched to dependency relationships
    - Does not indicate omissions from `blocked`, `tops`, or `hints`
- `tops`
    - At most five direct dependencies can have their versions selected again; if the limit is exceeded, re-resolution is skipped rather than run with a truncated list
- `blocked`
    - Not truncated based on the number of output entries

`update.chain` also includes skipped attempts, so its presence alone does not establish that re-resolution ran or that its result was adopted.
Check `update_executed`, `post_update_check_executed`, and `retry_after` in [Language package fields](webhook-remediation-language-reference.md#remediation-language-fields) for execution status and the date and time when the release waiting period ends.

During a waiting period, some cycles include `retry_after` without `update.chain`.
See [Release waiting periods and retries](remediation-reresolution-logic.md#dependent-reresolution-waits) for waiting and stopping conditions.

### Version requirements blocking updates {#language-chain-blocked}

The fields in each element of `language_items[].update.chain.blocked[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package whose update is blocked. | — |
| `version` | string | Current version of the package whose update is blocked. | — |
| `parent` | string | Name of the dependent package whose version requirement blocks the update. | — |
| `parent_version` | string | Current version of that dependent package. | — |
| `range` | string | Version or version range the dependent package requires for the target package. | — |
| `proof` | string | Evidence that the version requirement prevents an update to a fixed version. | — |
| `via` | array of strings | Names of the project's direct dependencies that lead to that dependent package. | omitted |

The values of `proof` are listed below.

| Value | Meaning |
| --- | --- |
| `exact` | Pinned to a specific version older than the fixed version. |
| `upper_bound` | The required range's upper bound excludes fixed versions. |

When `parent` itself is a direct dependency of the project, `via` contains its name.

### Direct dependencies and related changes {#language-chain-moves}

Elements of `language_items[].update.chain.tops[]` and `language_items[].update.chain.moves[]` have the same structure, with the fields listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Name of the package whose change is recorded. | — |
| `from` | string | Version before the change. | omitted |
| `to` | string | Version after the change. | omitted |
| `kind` | string | Role of the changed entry or type of change. | — |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `top` | Direct dependency in `tops` whose version is selected again. |
| `ancestor` | Change to a dependent package leading to the target package, recorded in `moves`. |
| `followed` | Change to an entry other than a dependent package, recorded in `moves`. |
| `added` | Addition of an entry, recorded in `moves`. |
| `removed` | Removal of an entry, recorded in `moves`. |

The following fields have additional notes.

- `name`
    - In `moves`, the identifier in the lockfile is used when the package name is unavailable
- `from` and `to`
    - In `tops`, the values are equal when the version is unchanged, and `to` is omitted when the resulting version is unknown, such as when an attempt is skipped before re-resolution
    - In `moves`, `from` is omitted when no version exists before an addition, and `to` is omitted when no version exists after a removal

### Processing usage of updates and re-resolution {#language-chain-usage}

The fields in `language_items[].update.chain.usage` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `containers` | integer | Number of work containers. | `0` |
| `lookups` | integer | Number of lookups to registries such as npm and PyPI. | `0` |
| `bytes` | integer | Bytes received from registries. | `0` |
| `elapsed_ms` | integer | Milliseconds elapsed from the start of processing the item to the time the usage was recorded. | `0` |

Usage includes the normal update, re-resolution through dependent packages, and any required reruns in that cycle.
See [Re-resolution support and limits](remediation-reresolution-logic.md#dependent-reresolution-limits) for processing limits.

## Go update records {#language-go-update}

The fields in `language_items[].update.go` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `collateral` | array of objects | Dependency modules outside the update targets whose versions were raised or that were added. | omitted |
| `go_before` | string | Version in the go line of go.mod before the update. | omitted |
| `go_after` | string | Version in the go line of go.mod after the update. | omitted |
| `toolchain_before` | string | Value in the toolchain line of go.mod before the update. | omitted |
| `toolchain_after` | string | Value in the toolchain line of go.mod after the update. | omitted |
| `sum_added` | array of strings | Lines added to complete go.sum using information from the checksum database. | omitted |

The following fields have additional notes.

- `go_before` and `go_after`
    - Represent versions such as `1.25.0`, and are recorded even when the version is unchanged
- `toolchain_before` and `toolchain_after`
    - Represent declared values such as `go1.25.3`, and are omitted when the corresponding line is absent
- `sum_added`
    - Each string uses the `module-path version h1:hash` format, with `/go.mod` appended to the version for a go.mod checksum
    - Represents lines added because they were missing from the update result, rather than all lines added by the Go command

The fields in each element of `language_items[].update.go.collateral[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | Dependency module path. | — |
| `from` | string | Dependency module version before the update. | omitted when the module was added |
| `to` | string | Dependency module version after the update. | — |

See [Go update validation](remediation-go-logic.md#go-update-validation) for adoption conditions.

## Maven update records {#language-maven-update}

The fields in `language_items[].update.maven` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `edits` | array of objects | Version specification changes in pom.xml. | omitted |
| `moves` | array of objects | Packages outside the update targets whose resolved versions changed. | omitted |

The fields in each element of `language_items[].update.maven.edits[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `file` | string | Repository path of the pom.xml being changed. | — |
| `kind` | string | Method used to change the version specification. | — |
| `package` | string | Name of the package targeted by the change, in `groupId:artifactId` format. | omitted |
| `property` | string | Name of the changed property. | omitted |
| `from` | string | Version specification before the change. | omitted |
| `to` | string | Version specification after the change. | — |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `version` | Change to a version written directly in a dependency declaration. |
| `property` | Change to a property defined by the project. |
| `property_override` | Project-level override of a property inherited from a parent. |
| `managed_pin` | Addition of a version specification to dependencyManagement. |

The fields in each element of `language_items[].update.maven.moves[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Package name in `groupId:artifactId` format. | — |
| `from` | array of strings | Sorted, deduplicated list of versions resolved before the update. | omitted |
| `to` | array of strings | Sorted, deduplicated list of versions resolved after the update. | omitted |

The versions in `moves` are those resolved by scans of the dependency files before and after the update.
`from` is omitted for added packages, and `to` is omitted for packages that are no longer present.

See [Version sources and edits](remediation-maven-logic.md#maven-version-sources) for the change methods and [Maven update validation](remediation-maven-logic.md#maven-update-validation) for adoption conditions.

## Gradle update records {#language-gradle-update}

The fields in `language_items[].update.gradle` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `edits` | array of objects | Version specification changes within the project. | omitted |
| `moves` | array of objects | Packages outside the update targets whose lockfile versions changed or that were added. | omitted |
| `companions` | array of objects | Records of packages changed because they share a version specification in a property or version catalog. | omitted |
| `bom` | string | Identifier of the Spring Boot BOM associated with the properties being changed, in `groupId:artifactId:version` format. | omitted |

The fields in each element of `language_items[].update.gradle.edits[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `file` | string | Repository path of the file being changed. | — |
| `kind` | string | Method used to change the version specification. | — |
| `package` | string | Name of the package targeted by the change, in `groupId:artifactId` format. | omitted |
| `property` | string | Name of the changed property or version key in the version catalog. | omitted |
| `from` | string | Version specification before the change. | omitted |
| `to` | string | Version specification after the change. | — |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `catalog_version` | Change to a version in the version catalog's `[versions]` section. |
| `catalog_library` | Change to a version written directly in a library definition in the version catalog. |
| `declaration` | Change to a version written directly in a dependency declaration in the build script. |
| `property` | Change to a property defined in gradle.properties or the build script. |
| `property_override` | Override of a Spring Boot BOM property in gradle.properties. |
| `constraint` | Addition of a dependency constraint to the build script. |

The fields in each element of `language_items[].update.gradle.moves[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Package name in `groupId:artifactId` format. | — |
| `from` | array of strings | Sorted, deduplicated list of versions locked before the update. | omitted when the package was added |
| `to` | array of strings | Sorted, deduplicated list of versions locked after the update. | — |

`moves` records changes or additions.
Updates that remove packages from the lockfile are not adopted, so `to` in each generated element contains versions after the update.

The fields in each element of `language_items[].update.gradle.companions[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `key` | string | Property name or version catalog version key through which the version is shared. | — |
| `value` | string | Shared version after the change. | — |
| `packages` | array of strings | Names of packages sharing that version specification, in `groupId:artifactId` format. | — |

The following fields have additional notes.

- `packages`
    - For each change, packages sharing the version specification are listed, excluding the package targeted by that change itself
    - When multiple update targets share a version specification, an update target itself may be included as a package affected by a change for another target

`companions` records packages confirmed to exist on Maven Central at the shared version after the change.
See [Version declarations and edits](remediation-gradle-logic.md#gradle-version-sources) for the change methods and [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation) for adoption conditions.
