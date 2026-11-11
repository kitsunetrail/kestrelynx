---
title: Webhook remediation language package fields
---

# Webhook remediation language package fields

This page describes language package items, per-package results, and hints when a package cannot reach its fix in the webhook's `remediation` object.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall structure.

## Language package fields {#remediation-language-fields}

The language package fields in `remediation` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `language_summary` | object | [Language package item counts by category](webhook-remediation-reference.md#remediation-summary-keys) | omitted when there are no language items |
| `language_items` | array of objects | Language package remediation plan items | omitted |

`language_summary` counts items in `language_items[]`, not packages.
The keys are `pr_candidate`, `dependency_update_candidate`, `rebuild_expected`, `manual`, `not_comparable`, `deferred`, and `failed`, with `0` included for categories that have no matching items.

Each element of `language_items[]` groups findings from workloads mapped to the same repository, base branch, and directory by package manager.
Before the manager is identified, items are separated by ecosystem, and findings whose running image could not be confirmed and the Go standard library may appear as separate items.

Use `key` to identify an item.
Do not combine items with different `key` values, even when they share a directory or package name.

The following example extracts the summary and the main fields of one item.

```json
{
  "language_summary": {
    "deferred": 1,
    "dependency_update_candidate": 1,
    "failed": 0,
    "manual": 1,
    "not_comparable": 0,
    "pr_candidate": 0,
    "rebuild_expected": 1
  },
  "language_items": [
    {
      "key": "deps:ex/app@main:backend",
      "category": "dependency_update_candidate",
      "reason": "update_candidate_in_source",
      "manager": "npm",
      "workloads": [
        "compose/shop/api"
      ],
      "update_executed": false,
      "post_update_check_executed": false,
      "package_count": 4
    }
  ]
}
```

The main fields of an item whose update and checks ran look like this.

```json
{
  "key": "lang-key",
  "category": "pr_candidate",
  "reason": "update_verified",
  "update_executed": true,
  "post_update_check_executed": true
}
```

The fields in each element of `language_items[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `key` | string | Key identifying the item within the plan | — |
| `category` | string | Item-wide category from [Plan category values](remediation-reference.md#category-values) | — |
| `reason` | string | Code explaining the category, as defined in [Reason codes](remediation-reference.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the category or reason | omitted |
| `manager` | string | Package manager that handles the dependency files | omitted when not identified |
| `priority` | string | Highest target vulnerability priority from [Priorities](webhook-reference.md#priority-values) | omitted |
| `workloads` | array of strings | Workload keys mapped to this dependency file directory | `null` or `[]` |
| `source` | object | [Source of dependency files](#language-source-fields) | — |
| `runtime_eol` | object | [End-of-life runtime](#language-runtime-eol-fields) requiring manual handling | omitted when none applies |
| `update_executed` | boolean | Whether the dependency update operation ran to completion during processing of the latest remediation plan | `false` |
| `post_update_check_executed` | boolean | Whether the update result was received and inspected during processing of the latest remediation plan | `false` |
| `retry_after` | string | Date and time when the release waiting period ends and a retry becomes possible, in RFC 3339 format | omitted |
| `package_count` | integer | Total package count before list truncation | `0` |
| `packages` | array of objects | [Package results](#language-package-fields) | omitted |
| `packages_truncated` | boolean | `true` when part of `packages` was omitted because of the count limit | omitted |
| `update` | object | [Update records](webhook-remediation-update-reference.md#language-update-fields) | omitted when no record is available |
| `source_check` | object | Dependency file results from [Checks before and after the update](webhook-remediation-check-reference.md#language-source-check-fields) | omitted when no record is available |
| `artifacts` | array of objects | Information about [Updated files](webhook-remediation-check-reference.md#language-artifact-fields) | omitted |
| `pull_request` | object | [PR processing results](#language-pull-request-fields) for this item | omitted when there is no matching processing result |

The values of `manager` are listed below.

| Value | Meaning |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |
| `uv` | uv |
| `pip` | pip |
| `go` | Go modules |
| `maven` | Maven |
| `gradle` | Gradle |

The following fields have additional notes.

- `workloads`
    - Normal plans output the configured workload keys as a sorted, deduplicated list
    - See [Image name updates](webhook-diff-reference.md#reference-change-fields) for workload key formats
    - Outputs `null` when the list is unset, or `[]` when it is held as an empty list
    - `null` and `[]` do not distinguish unknown targets from no targets
- `post_update_check_executed`
    - Also `true` when checks fail; use `source_check.passed` to determine whether checks passed
- `retry_after`
    - While waiting, an item may contain only this timestamp without `update.chain`
    - See [Release waiting periods and retries](remediation-reference.md#dependent-reresolution-waits) for waiting and retry conditions
- `packages`
    - Includes packages with reason `global_node_modules` even when they are not displayed under “Needs a decision” in Slack or email

### Source of dependency files {#language-source-fields}

The fields in `language_items[].source` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `repository` | string | Repository from which dependency files are read, in `owner/name` format | — |
| `base_branch` | string | Base branch from which dependency files are read | — |
| `directory` | string | Dependency file directory within the repository, with `.` representing the root | — |
| `commit_sha` | string | Commit SHA recorded as the source | omitted |
| `files` | array of objects | List of [Retrieved files](#language-source-file-fields) | omitted |
| `absent` | array of strings | Repository paths of files that were looked for when checking inputs but did not exist | omitted |
| `origin` | string | Origin of the source configuration | `""` |
| `confidence` | string | Basis for mapping the running image to the source | `""` |

The values of `origin` are listed below.

| Value | Meaning |
| --- | --- |
| `config` | Source specified in user configuration |

The values of `confidence` are listed below.

| Value | Meaning |
| --- | --- |
| `asserted` | Mapping explicitly stated by the user |

Matching package names and versions in the dependency files and running packages does not confirm that the running image was built from those files.
See [Source verification](remediation-logic.md#source-verification) for the scope of verification.

`absent` also includes files whose later addition would change the input conditions.
An example is `pnpm-workspace.yaml` when it did not exist at the time of the check.

#### Retrieved files {#language-source-file-fields}

The fields in each element of `language_items[].source.files[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | File path within the repository | — |
| `blob_sha` | string | Git blob SHA identifying the retrieved file content | — |
| `repository` | string | Repository from which the file was read | omitted when the source repository and branch both match the parent `source` |
| `base_branch` | string | Branch from which the file was read | omitted when the source repository and branch both match the parent `source` |

The same file information structure is also used for Dockerfile sources.
When `repository` and `base_branch` are omitted, use the values in the parent `source`.

The following is an example of `source` including its file list.

```json
{
  "repository": "ex/app",
  "base_branch": "main",
  "directory": "backend",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "files": [
    {
      "path": "backend/package.json",
      "blob_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    {
      "path": "backend/package-lock.json",
      "blob_sha": "cccccccccccccccccccccccccccccccccccccccc"
    }
  ],
  "origin": "config",
  "confidence": "asserted"
}
```

### End-of-life runtime {#language-runtime-eol-fields}

The fields in `language_items[].runtime_eol` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `id` | string | Runtime identifier such as `node22` or `python3.8` | — |
| `name` | string | Display name such as `Node.js 22` or `Python 3.8` | — |
| `eol` | string | End-of-support date in `YYYY-MM-DD` format | omitted when unknown |

This information is included when the item's `reason` is `runtime_eol`.
See [Runtime selection](remediation-logic.md#runtime-and-tool-versions) for how runtimes are selected.

### PR processing results {#language-pull-request-fields}

The fields in `language_items[].pull_request` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `status` | string | Status of the matching PR processing result, as defined in [PR status values](remediation-reference.md#pr-status-values) | — |
| `reason` | string | Code for the PR processing result, as defined in [Reason codes](remediation-reference.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the PR processing result | omitted |
| `number` | integer | GitHub PR number | omitted |
| `url` | string | GitHub PR URL | omitted |
| `state` | string | State of the PR itself, as defined in [PR status values](remediation-reference.md#pr-status-values) | omitted |
| `target_key` | string | Key identifying the update target within the repository | omitted |
| `update_key` | string | Key identifying the update proposed for the target | omitted |
| `attempt_key` | string | Key identifying an update attempt, including the base commit and the file content to change | omitted |

This contains information from the element of `pull_requests[]` whose `kind` is `language` and whose `item_key` matches this language item's `key`.
Processing results that did not create a PR are also included, so the presence of `pull_request` does not guarantee that `number` or `url` is available.

See [Matching existing PRs](remediation-logic.md#existing-pr-matching) for matching by identifier keys.

## Package results {#language-package-fields}

Each element of `language_items[].packages[]` represents an ecosystem, package name, and running version combination.
For Python, packages with the same normalized matching name are grouped together.

Even for the same combination, project packages and packages in a global `node_modules` are separate elements.
Receivers must not use this combination as a unique key to merge elements.

The following example extracts the main fields of a package.

```json
{
  "name": "express",
  "ecosystem": "node-pkg",
  "installed": "4.18.2",
  "selection_lower_bound": "4.19.2",
  "relation": "direct",
  "action": "update",
  "reason": "update_candidate_in_source",
  "occurrence_count": 1,
  "cve_count": 1,
  "kev_count": 1,
  "origin_count": 1
}
```

The fields in each element of `language_items[].packages[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Package name reported by the running image scan | — |
| `normalized` | string | Python package name normalized for matching | omitted for non-Python packages |
| `ecosystem` | string | Package type reported by the running image scan | — |
| `installed` | string | Package version detected in the running image | — |
| `selection_lower_bound` | string | Fixed-version lower bound from which update candidate selection starts | omitted |
| `adopted_version` | string | Lowest target package version in the updated dependency files | omitted |
| `relation` | string | Dependency relationship from the project's perspective | omitted when undetermined |
| `action` | string | Per-package action from [Package action values](remediation-reference.md#action-values) | omitted |
| `reason` | string | Code for the package action, as defined in [Reason codes](remediation-reference.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the action or reason | omitted |
| `left_out` | boolean | `true` when excluded from the planned update | omitted |
| `through` | array of strings | Names of dependent packages updated along with the target to reach a fixed version | omitted |
| `maven_bom` | object | [BOM guidance](#language-maven-bom) for reaching the target version | omitted when no applicable guidance is available |
| `fix_hint` | object | [Hints when a package cannot reach its fix](#language-fix-hint) | omitted when no applicable hints are available |
| `occurrence_count` | integer | Number of occurrences in dependency files before list truncation | `0` |
| `occurrences` | array of objects | Dependency file occurrences described in [Occurrences, vulnerabilities, and finding origins](#language-package-lists) | omitted |
| `occurrences_truncated` | boolean | `true` when part of `occurrences` was omitted because of the count limit | omitted |
| `cve_count` | integer | Number of target vulnerabilities before list truncation | `0` |
| `kev_count` | integer | Number of target vulnerabilities listed in CISA KEV | omitted when zero |
| `cves` | array of objects | List of [Target vulnerabilities](#language-package-cve-fields) | omitted |
| `cves_truncated` | boolean | `true` when part of `cves` was omitted because of the count limit | omitted |
| `origin_count` | integer | Number of finding origins before list truncation | `0` |
| `origins` | array of objects | [Finding origins in running images](#language-package-origin-fields) from which the package result was derived | omitted |
| `origins_truncated` | boolean | `true` when part of `origins` was omitted because of the count limit | omitted |

The values of `ecosystem` are listed below.

| Value | Meaning |
| --- | --- |
| `node-pkg` | Node.js packages |
| `python-pkg` | Python packages |
| `gobinary` | Modules or the standard library included in Go binaries |
| `jar` | Packages included in Java archives |

The values of `relation` are listed below.

| Value | Meaning |
| --- | --- |
| `direct` | Dependency required directly by the project |
| `transitive` | Dependency required through another package |
| `mixed` | Includes both direct and transitive dependency occurrences |

`normalized` is the name converted to lowercase, with consecutive `-`, `_`, and `.` characters collapsed to a single `-`.
For example, `Foo_Bar..Baz` becomes `foo-bar-baz`, and the field is included even when its value is identical to the original name.

The list count limits are listed below.

| List | Limit | Count before truncation |
| --- | --- | --- |
| `language_items[].packages` | 100 per item | `package_count` |
| `language_items[].packages[].occurrences` | 20 per package | `occurrence_count` |
| `language_items[].packages[].cves` | 50 per package | `cve_count` |
| `language_items[].packages[].origins` | 50 per package | `origin_count` |

`cve_count` counts unique vulnerability IDs within the package, and `kev_count` is also counted before list truncation.
`origin_count` counts unique combinations of finding origins, including image, package, vulnerability, detection location, and workload, so the same vulnerability ID can contribute multiple entries.

See [Update targets and adopted versions](remediation-results.md#target-and-adopted-version) for the distinction between `selection_lower_bound` and `adopted_version`.
An `action` of `update` does not necessarily mean that an update or checks ran.

In the example where updating `mkdirp` brings `minimist` to a fixed version, `through` for `minimist` is `["mkdirp"]`.
If direct dependency versions stay unchanged, it lists the updated intermediate dependent package closest to the project.

The following fields have additional notes.

- `through`
    - The common list determined for the entire re-resolution is assigned to each package whose update was blocked
    - It is not restricted to each package's dependency paths and may include dependents of other targets

`through` may also be supplemented from information in an existing PR matching the item.
Check `update_executed` and `post_update_check_executed` to determine whether the update and checks ran during processing of the latest remediation plan.

`left_out` and the `action`, `reason`, and `detail` describing that exclusion may also be supplemented from the matching PR.
See [Partial PRs](remediation-results.md#partial-pull-requests) for how to interpret partial PRs.

### Occurrences, vulnerabilities, and finding origins {#language-package-lists}

The fields in each element of `language_items[].packages[].occurrences[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | String identifying an entry or declaration location in dependency files | omitted |
| `version` | string | Target package version read from the dependency files before the update | omitted |
| `direct` | boolean | Whether this occurrence is a direct dependency of the project | `false` |
| `unpinned` | boolean | `true` for a requirement that is not pinned to a single version | omitted |
| `constraint` | string | Version requirement | omitted |
| `marker` | string | Environment marker attached to a Python dependency declaration | omitted |
| `extras` | array of strings | Names of extras specified in the Python dependency declaration | omitted |
| `matched` | boolean | `true` when the dependency file declaration was matched to the running package | omitted |
| `manual_reason` | string | Code explaining why this occurrence cannot be updated automatically, as defined in [Reason codes](remediation-reference.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the occurrence or the reason for manual handling | omitted |

The following fields have additional notes.

- `path`
    - For npm, a path within the lockfile such as `node_modules/express`
    - For pnpm, an identifier for a package or dependency declaration within the lockfile
    - For uv, the package name and version in `name==version` format
    - For pip and Go, a filename and line number relative to `source.directory`, such as `requirements.txt:3` or `go.mod:5`
    - For Maven, a `pom.xml` path, and for Gradle, a `gradle.lockfile` path, relative to the repository root
- `version`
    - Retains the version from the dependency files before the update; use `installed` for the running image version and `adopted_version` for the version adopted after the update
    - Omitted for unpinned requirements or declarations whose version cannot be read from the dependency files alone
- `matched`
    - Maven can also match declarations whose versions are confirmed during update processing, so `version` may be absent even when this is `true`

#### Target vulnerabilities {#language-package-cve-fields}

The fields in each element of `language_items[].packages[].cves[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `vuln_id` | string | Target vulnerability ID | — |
| `severity` | string | Target vulnerability severity | omitted |
| `fixed_vers` | array of strings | Sorted, deduplicated list of fixed versions reported by vulnerability information | omitted |
| `priority` | string | Target vulnerability priority from [Priorities](webhook-reference.md#priority-values) | omitted |
| `kev` | boolean | `true` when listed in CISA KEV | omitted |

The values of `severity` are listed below.

| Value | Meaning |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| `UNKNOWN` | Unknown |

#### Finding origins in running images {#language-package-origin-fields}

The fields in each element of `language_items[].packages[].origins[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `entity` | string | Identifier of the image content where the finding was detected | — |
| `ecosystem` | string | Package type at the finding origin | omitted |
| `class` | string | Package classification at the finding origin | omitted |
| `name` | string | Package name reported at the finding origin | — |
| `version` | string | Package version reported at the finding origin | — |
| `vuln_id` | string | ID of the detected vulnerability | — |
| `target` | string | Scan target name or path reported by the scanner | omitted |
| `pkg_path` | string | Package location within the image reported by the scanner | omitted |
| `workload` | string | Workload key corresponding to this finding, in the format described in [Image name updates](webhook-diff-reference.md#reference-change-fields) | — |

`entity` is a string containing the digest kind and value, such as `config:sha256:…`, with a platform such as `@linux/amd64` appended when known.
It is `unconfirmed` when a valid digest is unavailable.

The values of `ecosystem` are the same as in [Package results](#language-package-fields).
For Python, `name` retains its spelling before normalization, so finding origins for the same package may contain different spellings.

The values of `class` are listed below.

| Value | Meaning |
| --- | --- |
| `lang` | Language package |
| `os` | OS package |

Finding origins for the language packages covered on this page normally have `lang`.
`origins` records detections in running images, while `language_items[].source_check` contains the dependency file check results before and after the update.

The following example extracts occurrences, vulnerabilities, and finding origins for the same package.

```json
{
  "occurrences": [
    {
      "path": "node_modules/express",
      "version": "4.18.2",
      "direct": true,
      "matched": true
    }
  ],
  "cves": [
    {
      "vuln_id": "CVE-2032-0001",
      "severity": "HIGH",
      "fixed_vers": [
        "4.19.2"
      ],
      "kev": true
    }
  ],
  "origins": [
    {
      "entity": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "ecosystem": "node-pkg",
      "class": "lang",
      "name": "express",
      "version": "4.18.2",
      "vuln_id": "CVE-2032-0001",
      "target": "Node.js",
      "pkg_path": "app/node_modules/express/package.json",
      "workload": "compose/shop/api"
    }
  ]
}
```

### BOM guidance {#language-maven-bom}

The fields in `language_items[].packages[].maven_bom` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `bom` | string | BOM name in `groupId:artifactId` format | — |
| `property` | string | Name of the property specifying the BOM version | omitted |
| `from` | string | BOM version imported by the project | — |
| `to` | string | BOM version confirmed to manage the target package at or above its target version | — |
| `manages` | string | Target package version managed by the BOM at `to` | — |

This information is included only when the package's `reason` is `maven_bom_series_unreached` and guidance was retrieved.

The following fields have additional notes.

- `to`
    - A stable release in the same major version as `from` and a later minor version than `from`
    - The lowest BOM version among those confirmed to manage the package named by `language_items[].packages[].name` at or above `selection_lower_bound`
    - Because lookups are capped, this does not necessarily reflect a search of all published BOM releases
- `manages`
    - The version set for the target package by that BOM, not the BOM's own version

See [Version sources and edits](remediation-logic.md#maven-version-sources) for Maven version management.

### Hints when a package cannot reach its fix {#language-fix-hint}

The fields in `language_items[].packages[].fix_hint` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `held_by` | array of objects | [Dependents requiring the target](#language-fix-holder-fields) that block its update or require it | omitted |
| `releases` | array of objects | [Published release information for dependents](#language-fix-hint-releases) or POMs deciding the version | omitted |
| `go_line` | object | [Go version required for the update](#language-go-line-fields) and the module requiring it | omitted |
| `fix` | object | Information about a [Fixed release in another major version](#language-fix-release-fields) | omitted |
| `direct` | boolean | `true` when the project's own direct requirement for the target package was confirmed | omitted |
| `decided_by` | object | External [POM deciding the target version](#language-fix-decider-fields) | omitted |
| `configuration` | string | Gradle configuration where the target remained below its target version | omitted |

The `reason` values eligible for `fix_hint` are `dependents_hold_back`, `go_line_raised_too_far`, `go_runtime_unavailable`, `fix_in_other_major_version`, `maven_version_source_unsupported`, `gradle_version_source_unsupported`, `maven_release_not_found`, `maven_fix_in_other_major`, and `target_not_updated` for Maven and Gradle.
Even for an eligible reason, `fix_hint` or its child fields are omitted when the information cannot be retrieved.

See [Reason codes](remediation-reference.md#reason-codes) for the meanings of reasons and [Hints when a package cannot reach its fix](remediation-results.md#fix-hints) for interpreting the hints.

The following fields have additional notes.

- `direct`
    - For Go hints about another major version, `true` when the project's `go.mod` requires the target without `// indirect`
    - For Maven `target_not_updated`, `true` when there are no dependents to list in `held_by` and the project's own module declares the target directly
    - For Gradle `target_not_updated`, `true` when there are no dependents to list in `held_by` and the target configuration declares the target directly
- `configuration`
    - Included for Gradle `target_not_updated`, and omitted when neither a dependent nor a direct declaration can be confirmed

#### Dependents requiring the target {#language-fix-holder-fields}

The fields in each element of `language_items[].packages[].fix_hint.held_by[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `parent` | string | Name of the dependent requiring the target package | — |
| `parent_version` | string | Checked version of the dependent | — |
| `range` | string | Version requirement the dependent specifies for the target package | `""` |

The interpretation of `range` depends on the manager.

| Manager and reason | Meaning |
| --- | --- |
| `dependents_hold_back` for pip | Combined range of active requirements that excludes the version the update tried to pin |
| `fix_in_other_major_version` for Go | Target module version required by the dependent's `go.mod` |
| `target_not_updated` for Maven | Target package version brought in by the dependent after the update |
| `target_not_updated` for Gradle | Target package version requested by the dependent in the dependency tree |

For Maven and Gradle, `parent` uses `groupId:artifactId` format.
`held_by` contains at most five entries for Maven and Gradle; this five-entry limit does not apply to pip or Go.

#### Go version required for the update {#language-go-line-fields}

The fields in `language_items[].packages[].fix_hint.go_line` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `module` | string | Path of the module whose `go.mod` declares the required Go version | — |
| `version` | string | Module version containing that declaration | — |
| `go` | string | Version declared by the `go` line in that `go.mod` | — |
| `built_with` | string | Go version used to build the running binaries and used for the comparison | omitted |
| `to` | string | Target package version requested by the update | omitted |

The following fields have additional notes.

- `built_with`
    - Included for `go_line_raised_too_far` when the build-time version is known
    - Omitted when the build-time version is unknown or for `go_runtime_unavailable`
- `to`
    - The update target version, which may differ from the `version` of the module declaring the required Go version

#### Fixed release in another major version {#language-fix-release-fields}

The fields in `language_items[].packages[].fix_hint.fix` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `version` | string | Lowest version that meets the hint's conditions and fixes all target vulnerabilities | — |

The interpretation of `version` depends on the package's `reason`.

| Reason | Meaning |
| --- | --- |
| `fix_in_other_major_version` for Go | Fixed version in another major version reported by vulnerability information |
| `maven_fix_in_other_major` for Maven and Gradle | Stable fixed release in a different major version from the running version, reported by vulnerability information |
| `maven_release_not_found` for Maven and Gradle | Stable fixed release published on Maven Central at or above the target version and in a different major version from the running version |

For Maven and Gradle `maven_release_not_found`, the version must have the same variant as the running version.
For `maven_fix_in_other_major`, the version may have the same variant as the running version or no variant.

See [Target versions and Maven Central releases](remediation-logic.md#maven-target-versions) for version variants and selection conditions.

#### POM deciding the target version {#language-fix-decider-fields}

The fields in `language_items[].packages[].fix_hint.decided_by` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Kind of POM deciding the target version | — |
| `name` | string | POM name in `groupId:artifactId` format | — |
| `version` | string | POM version currently used | — |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `parent_pom` | Parent POM |
| `bom` | Imported BOM |
| `spring_boot` | BOM used by the Spring Boot plugin in Gradle |

When `kind` is `spring_boot`, `name` is `org.springframework.boot:spring-boot-dependencies` and `version` is the Spring Boot plugin's version.

### Published release information for dependents {#language-fix-hint-releases}

`language_items[].packages[].fix_hint.releases[]` contains checked information about published releases of dependents requiring the target package or POMs deciding its version.
`language_items[].update.chain.hints[]` also uses the structure defined in this section.

The fields in each element of `language_items[].packages[].fix_hint.releases[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the target package being checked for an update to a fixed version | — |
| `parent` | string | Name of the checked dependent or POM deciding the version | — |
| `parent_version` | string | Current version of the dependent or POM used as the basis for the check | — |
| `via` | array of strings | Names of the project's direct dependencies leading to that dependent | omitted |
| `direct` | boolean | Value indicating how the dependent is treated as a direct dependency | omitted |
| `spec` | string | Version range the project specifies for the direct dependency | omitted |
| `in_spec` | object | [Checked release](#language-hint-release-fields) within the specified range or the same major and minor version | omitted when unavailable |
| `latest` | object | [Checked release](#language-hint-release-fields) identified as the newest | omitted when unavailable or when it is the same version as `in_spec` |

The following fields have additional notes.

- `parent` and `parent_version`
    - For Maven and Gradle, the name and version of the dependent bringing in the target or the POM identified by `decided_by`
- `via`
    - Identifies direct dependencies leading to the dependent, but does not identify which version of a direct dependency would bring in the published release shown in the hint
- `direct`
    - For npm, pnpm, and uv, `true` when `parent` is a direct dependency of the project
    - For Maven and Gradle, published release information always has `true`, so this value does not indicate whether it is a direct dependency of the project
    - Omitted from published release information for pip and Go
- `spec`
    - The range specified in `package.json` for npm and pnpm, or `pyproject.toml` for uv
    - Omitted when the dependent is not direct, or when it is direct but no version range is specified
    - Omitted from published release information for Maven, Gradle, pip, and Go

The versions represented by `in_spec` and `latest` depend on the manager.

| Manager | `in_spec` | `latest` |
| --- | --- | --- |
| npm, pnpm, uv | Newest stable release within the range specified for the direct dependency | Newest published stable release |
| pip | Not included | Newest published stable release |
| Go | Not included | Version checked through the module proxy's `@latest` |
| Maven, Gradle | Newest stable release in the same major and minor version as `parent_version` | Newest stable release of the dependent or POM |

For npm, pnpm, and uv, `in_spec` is included only when `direct` is `true`, and the absence of `spec` is treated as no version restriction.
For Maven and Gradle, `in_spec` may contain the same version as the currently used `parent_version`.

#### Checked release {#language-hint-release-fields}

The fields in `language_items[].packages[].fix_hint.releases[].in_spec` are listed below and are also used by `latest` in the same element and by `in_spec` and `latest` in `language_items[].update.chain.hints[]`.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `version` | string | Checked release of the dependent or POM | — |
| `range` | string | Range or version that release specifies for the target package | omitted |
| `fixes` | boolean | Whether the release's declaration was confirmed to allow or set a fixed version | `false` |
| `dropped` | boolean | `true` when the release was confirmed to have no requirement or version setting for the target | omitted |

The interpretation of `range` and `fixes` is listed below.

| Manager | `range` | `fixes` |
| --- | --- | --- |
| npm, pnpm, uv, pip | Version range specified for the target package | `true` when the range includes a published stable release that fixes all target vulnerabilities |
| Go | Target module version required by `go.mod` | Always `false` for hints about another major version |
| Maven, Gradle | Version set for the target package | `true` when it is at or above the target version and fixes all target vulnerabilities |

The following fields have additional notes.

- `range`
    - Omitted when the range string is empty, including requirements with no version restriction
- `fixes`
    - A check of the published release's declaration, not a guarantee that updating to it will resolve the vulnerabilities or work correctly
    - Go checks requirements for the same module path, so `false` alone does not mean the dependent's published release as a whole is vulnerable
- `dropped`
    - For npm, pnpm, uv, pip, and Go, `true` when the release does not declare the target as a direct dependency
    - For Maven and Gradle dependents, `true` when the POM does not declare the target in `dependencies`
    - For Maven and Gradle POMs deciding the version, `true` when the POM sets no target version
    - The target package may still be brought in through another dependency path

The absence of published release information does not mean that no release capable of fixing the package exists.
See [Hints when a package cannot reach its fix](remediation-results.md#fix-hints) for interpreting the information and for lookup limits.
