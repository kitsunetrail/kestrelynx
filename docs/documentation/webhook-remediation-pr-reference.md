---
title: Webhook remediation PR processing fields
---

# Webhook remediation PR processing fields

This page describes PR processing results, language package update details, PR operation events, and problems that stop writes in webhook remediation plans.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall structure.

When PR creation is enabled and a remediation plan exists, `pull_request_summary` and `pull_requests` are emitted if there are processing targets, `operations` if there are undelivered operation events, and `problems` if there are problems that stop writes.
`operations` and `problems` can also be emitted when `pull_requests` is absent.

Field names in each table are relative to the object named before the table.
The notation in “When there is no value” follows [Report fields](webhook-reference.md#report-fields).

## PR processing fields {#remediation-pr-fields}

`remediation` has the following fields for PR processing.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `pull_request_summary` | object | [PR processing item counts by status](webhook-remediation-reference.md#remediation-summary-keys) | omitted when there are no processing targets |
| `pull_requests` | array of objects | PR processing results for each update target | omitted when there are no processing targets |
| `operations` | array of objects | Undelivered PR operation events described in [PR operation event fields](#remediation-operation-fields) | omitted |
| `problems` | array of objects | Problems that stop PR writes, as described in [Write-blocking problem fields](#remediation-problem-fields) | omitted |

See [Item counts](webhook-remediation-reference.md#remediation-summary-keys) for how to read the keys and counts in `pull_request_summary` and how zero counts are handled.

See [PR status values](remediation-reason-codes.md#pr-status-values) for status definitions.

### Matching update targets to PRs {#pr-unit-fields}

Each element of `pull_requests[]` is the processing result for targets updated together in the same repository and base branch.
How targets are grouped depends on `kind`.

An element contains information about the PR created or the PR corresponding to the same update.
An element is emitted even when a PR could not be created, so the number of elements does not equal the number of PRs created.

Use `repo` and `number` together to identify a PR.

`pull_requests[]` has the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Update target type, as described in [Update target kinds](#pr-unit-kinds) | omitted when updating Compose tags |
| `key` | string | Value identifying one element of `pull_requests[]` | — |
| `repo` | string | `owner/name` of the repository to update | — |
| `base_branch` | string | Branch into which the PR is to be merged | — |
| `path` | string | Path within the repository of the file representing the update target | — |
| `services` | array of strings | List of service names or workloads to update | `[]` |
| `workloads` | array of strings | Target workload keys, as described in [Image name updates](webhook-diff-reference.md#reference-change-fields) | omitted |
| `also_running` | array of objects | Information about [Services](webhook-remediation-reference.md#remediation-services) running the same image but not included in the update | omitted |
| `current_ref` | string | Image name before the update | `""` |
| `candidate_tag` | string | Tag of the update candidate image | omitted |
| `candidate_digest` | string | Manifest or image index digest of the update candidate image | omitted |
| `status` | string | PR processing status from [PR status values](remediation-reason-codes.md#pr-status-values) | — |
| `reason` | string | Reason for the PR processing result from [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `detail` | string | Explanatory text supplementing the PR processing result | omitted |
| `number` | integer | Number of the associated PR | omitted when `0` |
| `url` | string | URL of the associated PR | omitted |
| `state` | string | Recorded state of the associated PR from [PR status values](remediation-reason-codes.md#pr-status-values) | omitted |
| `user_modified` | boolean | Whether changes differing from the creation record were found in the PR | omitted when `false` |
| `target_key` | string | Value identifying the combination of file and locations to edit | omitted |
| `update_key` | string | Value identifying the update contents for the same edit target | omitted |
| `attempt_key` | string | Value identifying the update contents and inputs to the commit to be created | omitted |
| `fix_target_count` | integer | Number of fix targets before truncation | `0` |
| `fix_targets` | array of objects | [Fix targets](#pr-fix-target-fields) resolved by this update | omitted |
| `fix_targets_truncated` | boolean | Whether the fix target list was truncated to 100 entries | omitted when `false` |
| `replaced_by` | integer | Number of the newer PR that replaced this PR | omitted when `0` |
| `replacing` | array of objects | Progress of [PR replacement](#pr-replacing-fields) for each older PR this PR replaces | omitted |
| `replaced` | array of integers | Numbers of older PRs whose replacement by this PR is complete | omitted |
| `item_key` | string | `key` of the associated element in `language_items[]` | omitted |
| `language` | object | [Language package update details](#pr-language-fields) | omitted |

The following fields have additional notes.

- `key`
    - An identifier determined before querying GitHub, separate from the PR number
    - Use it to match the same processing target across notifications, without assuming it matches `items[].key` or `dockerfile_items[].key`
- `item_key`
    - Match against `language_items[].key` when `kind` is `language`
- `target_key`
    - Identifies the update kind, repository, base branch, file, and edit locations, and stays the same for the same edit target even if the versions before and after the update change
    - Match `pull_requests[].target_key` across notifications to associate proposals for the same edit target
- `update_key`
    - Distinguishes the previous reference and candidate tag and digest for image updates, or adopted versions and dependency file changes for language package updates
    - For Kubernetes manifest updates, also distinguishes the combination of containers specified by `workload` in [Source mappings](configuration.md#remediation-mappings)
    - For Kustomize and Helm values updates, also distinguishes the combination of containers specified by `workload` and `affects` in the configuration
    - Match `pull_requests[].update_key` across notifications to associate proposals for the same update
- `attempt_key`
    - Changes when the base commit or file contents before or after the edit change, even for the same update
    - Stays the same when processing resumes from the same inputs, so do not use it to count executions
    - Match against `operations[].attempt_key` to group operations related to creating that PR
- `target_key`, `update_key`, `attempt_key`
    - Values are 64-character hexadecimal strings representing SHA-256 hashes; compare the received strings as they are
    - If processing stops partway through, keys that have not yet been determined are omitted
- `also_running`
    - For Compose, includes services without a mapping
    - For Kubernetes manifest updates, includes containers not specified by `workload` in the configuration
    - For Kustomize and Helm values updates, includes containers not specified by `workload` or `affects` in the configuration
- `user_modified`
    - `true` when the PR head commit, base, head repository, or similar information differs from the creation record
- `replaced_by`, `replacing`, `replaced`
    - PR numbers belong to the repository in this element's `repo`
    - `replacing` and `replaced` are not truncated by entry count when emitted in the webhook

### Update target kinds {#pr-unit-kinds}

`kind` uses the following values.

| Value | Meaning |
| --- | --- |
| omitted | Compose tag update, grouping services in the same file that use the same image reference |
| `kubernetes` | Kubernetes manifest tag update, grouping containers in the same file that use the same image reference |
| `kustomize` | Updates one Kustomize `images` entry |
| `helm_values` | Updates one configured key in Helm values |
| `dockerfile` | Updates one `FROM` in a Dockerfile |
| `language` | Updates packages together for one dependency file directory |

The values of `path` and `services` for each `kind` are as follows.

| `kind` | File identified by `path` | Values in `services` |
| --- | --- | --- |
| omitted (Compose) | Compose file | Service names in the Compose file being edited |
| `kubernetes` | Kubernetes manifest | Workload keys as described in [Image name updates](webhook-diff-reference.md#reference-change-fields) |
| `kustomize` | kustomization file | Workload keys as described in [Image name updates](webhook-diff-reference.md#reference-change-fields) |
| `helm_values` | values file | Workload keys as described in [Image name updates](webhook-diff-reference.md#reference-change-fields) |
| `dockerfile` | Dockerfile | Names extracted from each workload key, with duplicates removed |
| `language` | Dependency file representing the update target | Names extracted from each workload key, with duplicates removed |

When `kind` is `language`, `path` identifies the following dependency file.

| Package manager | Dependency file |
| --- | --- |
| npm | `package-lock.json` |
| pnpm | `pnpm-lock.yaml` |
| uv | `uv.lock` |
| pip | `requirements.txt` |
| Go | `go.mod` |
| Maven | Root `pom.xml` |
| Gradle | `gradle.lockfile` |

Language package PRs may also change dependency files other than `path`.

For `dockerfile` and `language`, the following names are extracted from workload keys.

| Target | Name extracted |
| --- | --- |
| Compose | Service name |
| Kubernetes | Workload name |
| Docker container with an unknown workload | Container name |
| Kubernetes container with an unknown workload | Pod name |

The following fields have additional notes.

- `current_ref`
    - For Compose, `kubernetes`, `kustomize`, and `helm_values`, the running image reference used by the update targets
    - For `dockerfile`, the base image reference specified in the target `FROM`
    - `""` for `language`
- `candidate_tag`, `candidate_digest`
    - Omitted for `language`

### Fix targets {#pr-fix-target-fields}

Each element of `pull_requests[].fix_targets[]` represents a vulnerability resolved in a package at a particular location.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `location` | string | Edit location or location within a dependency file to which the fix target belongs | — |
| `vuln_id` | string | ID of the vulnerability resolved | — |
| `package` | string | Name of the package to fix | — |
| `ecosystem` | string | Type of the package to fix, as described in [Packages](webhook-reference.md#package-fields) | omitted |

The following fields have additional notes.

- `location`
    - For Compose, `services.<service>.image`
    - For `kubernetes`, `<Kind>/<namespace>/<name>/<container>`, where `Kind` and `name` identify the mapped object in the file and `namespace` is the workload namespace
    - For `kustomize`, `images[<name>].newTag`
    - For `helm_values`, the configured `helm_values.key`
    - For `dockerfile`, `stages[<number>]` using a zero-based stage number, with `:<name>` appended in lowercase if the stage has a name
    - For `language`, the matched package location within a dependency file, or the path of the dependency file to update if no location is available
- `package`
    - For language packages, this may be the normalized name used for matching against dependency files

The list contains at most 100 entries.
Check `pull_requests[].fix_target_count` for the full count; `pull_requests[].fix_targets_truncated` is `true` when there are more than 100 entries.

The count distinguishes locations and packages rather than grouping only by vulnerability ID.
Base image updates also count targets separately when the sets of layers containing the findings differ.

Layer information is not emitted in this array.
Programs receiving the webhook must not remove elements as duplicates merely because their visible fields are identical.

### PR replacement {#pr-replacing-fields}

Each element of `pull_requests[].replacing[]` represents the progress of replacing an older PR with this PR.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `old_number` | integer | Number of the older PR to replace | — |
| `state` | string | State of the process for replacing the older PR | — |

`state` uses the following values.

| Value | Meaning |
| --- | --- |
| `pending` | Replacement has been decided, but no operation has been sent yet |
| `commented` | The older PR has a comment announcing the replacement |
| `closed` | The close operation has been sent, but its result has not been confirmed |
| `done` | The older PR has been recorded as replaced |
| `abandoned` | Replacement conditions are no longer met, and the process has been abandoned |

A `replacing[].state` of `closed` does not necessarily mean that closure has been confirmed.
`replaced[]` contains the numbers for which the replacement process is `done` and the older PR's state has also been confirmed as `replaced`.

See [Replacing older PRs](remediation-pr-logic.md#pr-replacement) for replacement conditions.

### PR processing examples {#pr-unit-examples}

The following example shows the summary and PR processing result excerpted from the output after creating a base image update PR.

```json
{
  "remediation": {
    "pull_request_summary": {
      "pr_created": 1
    },
    "pull_requests": [
      {
        "kind": "dockerfile",
        "key": "dockerfile|ex/app|main|docker/Dockerfile|stages[0]:runtime",
        "repo": "ex/app",
        "base_branch": "main",
        "path": "docker/Dockerfile",
        "services": ["app"],
        "workloads": ["compose/shop/app"],
        "current_ref": "python:3.12.3-slim",
        "candidate_tag": "3.12.5-slim",
        "status": "pr_created",
        "number": 7,
        "url": "https://github.com/ex/app/pull/7",
        "state": "open",
        "fix_target_count": 2,
        "fix_targets": [
          {
            "location": "stages[0]:runtime",
            "vuln_id": "CVE-2031-0001",
            "package": "libc"
          },
          {
            "location": "stages[0]:runtime",
            "vuln_id": "CVE-2031-0002",
            "package": "libc"
          }
        ]
      }
    ]
  }
}
```

The following example shows fields describing the target, excerpted from one element of `pull_requests[]` for a language package update.

```json
{
  "kind": "language",
  "key": "language|ex/app|main|package-lock.json",
  "repo": "ex/app",
  "base_branch": "main",
  "path": "package-lock.json",
  "services": ["api", "web"],
  "workloads": ["compose/shop/api", "compose/shop/web"],
  "current_ref": ""
}
```

## Language package update details {#pr-language-fields}

`pull_requests[].language` describes the packages updated by the PR and the changes to dependency files.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `manager` | string | Package manager that handles the dependency files | — |
| `root` | string | Directory of the dependency files within the repository | — |
| `packages` | array of objects | [Packages to update](#pr-language-package-fields) | `[]` |
| `manifest_edits` | array of objects | [Version specification changes in dependency files](#pr-language-edit-fields) | omitted |
| `chain` | array of objects | [Direct dependencies updated along with the targets](#pr-language-chain-fields) for re-resolution | omitted |
| `remaining` | array of objects | [Packages excluded from the PR update](#pr-language-remaining-fields) | omitted |

`manager` uses the following values.

| Value | Meaning |
| --- | --- |
| `npm` | npm |
| `pnpm` | pnpm |
| `uv` | uv |
| `pip` | pip |
| `go` | Go modules |
| `maven` | Maven |
| `gradle` | Gradle |

`root` is `.` when it refers to the repository root.
See [Supported input formats](remediation-reference.md#supported-inputs) for supported dependency file formats.

### Packages to update {#pr-language-package-fields}

Each element of `pull_requests[].language.packages[]` represents one package updated by the PR.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Name of the package to update | — |
| `ecosystem` | string | Type of the package to update, as described in [Packages](webhook-reference.md#package-fields) | — |
| `relation` | string | Dependency relationship classification from the project's perspective | omitted |
| `from` | string | Running version of the package to update | — |
| `to` | string | Update version adopted by the PR | — |
| `major` | boolean | Whether the change from `from` to `to` is a major version change | omitted when `false` |
| `through` | array of strings | Names of direct dependencies updated along with this package to enable its update | omitted |

`relation` uses the following values.

| Value | Meaning |
| --- | --- |
| `direct` | Dependency required directly by the project |
| `transitive` | Dependency reached through another package |
| `mixed` | A mixture of direct dependencies and dependencies reached through other packages |

The following fields have additional notes.

- `from`
    - In a cycle matched to an existing PR, the running version confirmed in that cycle's plan
- `major`
    - Also `true` for minor version changes in `0.x`
    - Also omitted when versions cannot be parsed and compared, so do not judge the safety of a change from omission alone
- `through`
    - Check the entry with the same name in `pull_requests[].language.chain[]` for the versions before and after the update

### Version specification changes in dependency files {#pr-language-edit-fields}

Each element of `pull_requests[].language.manifest_edits[]` represents a change to one version specification in a dependency file.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `file` | string | Path within the repository of the file whose version specification is rewritten | — |
| `section` | string | Dependency declaration section containing the version specification | — |
| `name` | string | Name of the package whose version specification is rewritten | — |
| `from` | string | Version specification before the change | — |
| `to` | string | Version specification after the change | — |
| `major` | boolean | Whether the new version specification no longer allows the major version allowed by the old specification | omitted when `false` |

`section` contains a section within a dependency file, such as `dependencies` or `project.dependencies`.
`from` and `to` are version specifications such as `^4.17.15`; check `pull_requests[].language.packages[].to` for the version actually adopted.

### Direct dependencies updated along with the targets {#pr-language-chain-fields}

Each element of `pull_requests[].language.chain[]` represents one direct dependency updated to enable an update to a target package.

The following diagram shows the dependencies between the project and packages A, B, and C.

```text
Project
└── A            Updated from 1.0.0 to 1.1.0
    └── B        Requires version 0.5.0 of C
        └── C    Package to update
```

The field containing the name of each package is as follows.

| Package | Field containing its name |
| --- | --- |
| A | `name` |
| B | `held_by` |
| C | `held` |

The following element of `chain[]` represents the update of A.

```json
{
  "name": "A",
  "from": "1.0.0",
  "to": "1.1.0",
  "held": "C",
  "held_range": "0.5.0",
  "held_by": "B"
}
```

`pull_requests[].language.chain[]` has the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Name of the direct dependency updated along with the targets | — |
| `from` | string | Version of the direct dependency before the change | `""` |
| `to` | string | Version of the direct dependency after the change | `""` |
| `held` | string | Name of the package subject to a requirement for an older version | omitted |
| `held_range` | string | Version specification that blocked the update | omitted |
| `held_by` | string | Name of the package between the direct dependency and `held` that required an older version | omitted |

`held_by` is omitted when the direct dependency itself requires the older version.
See [Re-resolution check conditions](remediation-reresolution-logic.md#dependent-reresolution-rules) for re-resolution conditions.

### Packages excluded from the PR update {#pr-language-remaining-fields}

Each element of `pull_requests[].language.remaining[]` represents one package planned for update but excluded from the PR update.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Name of the package excluded from the PR update | — |
| `ecosystem` | string | Type of the excluded package, as described in [Packages](webhook-reference.md#package-fields) | — |
| `relation` | string | Dependency relationship classification from the project's perspective, as described in [Packages to update](#pr-language-package-fields) | omitted |
| `from` | string | Running version of the excluded package | — |
| `target` | string | Planned lower bound for the update version | `""` |
| `reason` | string | Reason for exclusion from the update from [Reason codes](remediation-reason-codes.md#reason-codes) | — |
| `detail` | string | Explanatory text supplementing the exclusion reason | omitted |
| `maven_bom` | object | [BOM information for excluded packages](#pr-language-bom-fields) identifying a version that reaches the update lower bound | omitted |

In a cycle matched to an existing PR, exclusion information is supplemented from `pull_requests[].language.remaining[]`.
The destination is the element of `language_items[].packages[]` with the same name and package type.

Packages with the reason `global_node_modules` are excluded from this supplementation.
Supplementation occurs even when `language_items[].update_executed` and `language_items[].post_update_check_executed` are `false`.

The destination fields and their values are as follows.

| Field | Value supplied |
| --- | --- |
| `language_items[].packages[].left_out` | `true` |
| `language_items[].packages[].action` | `"manual"` |
| `language_items[].packages[].reason` | Exclusion reason |
| `language_items[].packages[].detail` | Explanatory text, when available |
| `language_items[].packages[].maven_bom` | Applicable BOM information, when available |

See [Partial PRs](remediation-update-results.md#partial-pull-requests) for interpreting partial updates.

### BOM information for excluded packages {#pr-language-bom-fields}

`pull_requests[].language.remaining[].maven_bom` describes a candidate BOM version that manages the excluded package at or above the update lower bound.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `bom` | string | `groupId:artifactId` of the BOM | — |
| `property` | string | Name of the property specifying the BOM version | omitted |
| `from` | string | BOM version imported by the project | — |
| `to` | string | Candidate BOM version that manages the target package at or above the update lower bound | — |
| `manages` | string | Version of the target package managed by the BOM at `to` | — |

This object is emitted when `pull_requests[].language.remaining[].reason` is `maven_bom_series_unreached` and BOM candidate information is available.
Use `from` and `to` for BOM versions and `manages` for the target package version.

See [Version sources and edits](remediation-maven-logic.md#maven-version-sources) and [Version declarations and edits](remediation-gradle-logic.md#gradle-version-sources) for the meaning of the candidate.

### Language package update example {#pr-language-example}

The following example shows `pull_requests[].language` for a PR that updates the npm packages lodash and minimist.
Check `packages` for the versions before and after the update, and `manifest_edits` for the change to the lodash version specification in `package.json`.

```json
{
  "manager": "npm",
  "root": ".",
  "packages": [
    {
      "name": "lodash",
      "ecosystem": "node-pkg",
      "relation": "direct",
      "from": "4.17.15",
      "to": "4.17.21"
    },
    {
      "name": "minimist",
      "ecosystem": "node-pkg",
      "relation": "transitive",
      "from": "1.2.5",
      "to": "1.2.6"
    }
  ],
  "manifest_edits": [
    {
      "file": "package.json",
      "section": "dependencies",
      "name": "lodash",
      "from": "4.17.15",
      "to": "4.17.21"
    }
  ]
}
```

### Partial PR example {#remediation-json-example}

A [partial PR](remediation-update-results.md#partial-pull-requests) updates only some of the packages that were intended to be updated together.

The following example extracts only the main fields from a payload containing a partial PR.
Check where the successfully updated package and the package excluded from the update are recorded.

- The successfully updated `example-a` is recorded only in `language_items[].packages[]` in this example
- The excluded `example-b` is recorded in `language_items[].packages[]` with `left_out: true` and also in `pull_requests[].language.remaining[]`

```json
{
  "remediation": {
    "language_items": [
      {
        "category": "pr_candidate",
        "update_executed": true,
        "post_update_check_executed": true,
        "packages": [
          {
            "name": "example-a",
            "ecosystem": "node-pkg",
            "installed": "1.0.0",
            "adopted_version": "1.0.1",
            "action": "update",
            "reason": "update_verified"
          },
          {
            "name": "example-b",
            "ecosystem": "node-pkg",
            "installed": "2.0.0",
            "selection_lower_bound": "2.0.1",
            "action": "manual",
            "reason": "target_not_updated",
            "left_out": true
          }
        ]
      }
    ],
    "pull_requests": [
      {
        "kind": "language",
        "language": {
          "remaining": [
            {
              "name": "example-b",
              "ecosystem": "node-pkg",
              "from": "2.0.0",
              "target": "2.0.1",
              "reason": "target_not_updated"
            }
          ]
        }
      }
    ]
  }
}
```

See [Partial PR conditions](remediation-package-logic.md#partial-pr-selection) for adoption conditions.

## PR operation event fields {#remediation-operation-fields}

`operations[]` emits PR operation events that have not yet been recorded as delivered, in ascending sequence number order.
The record before sending an operation, its result, and any result confirmed later are separate events for that operation.

PR processing records are saved in `prs.json` under `remediation.storage_dir`.
See [Stored files](remediation-pr-logic.md#stored-records) for what is saved.

`operations[]` has the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `seq` | integer | Event sequence number that increases within the same `prs.json` | — |
| `id` | string | Identifier linking the phases of the same operation | — |
| `at` | string | Time the event was recorded, in UTC RFC 3339 format | — |
| `phase` | string | Value indicating which phase of the operation the event records | — |
| `kind` | string | Kind of write operation on GitHub | — |
| `repo` | string | `owner/name` of the repository targeted by the operation | — |
| `attempt_key` | string | Value identifying the contents of the related PR creation attempt | omitted |
| `number` | integer | Number of the PR targeted by the operation | omitted when `0` |
| `result` | string | Operation result | omitted |
| `error` | string | Explanatory text supplementing an error or the confirmation of an outcome | omitted |

`phase` uses the following values.

| Value | Meaning |
| --- | --- |
| `intent` | The intention to perform the operation was recorded before sending it |
| `result` | The result obtained after sending the operation was recorded |
| `settled` | An operation with an unknown outcome was checked in a later cycle, and its handling was settled |

`kind` uses the following values.

| Value | Meaning |
| --- | --- |
| `create_blob` | Creates Git file contents |
| `create_tree` | Creates a Git file tree |
| `create_commit` | Creates a commit |
| `create_ref` | Creates a branch for a PR |
| `create_pull` | Creates a PR |
| `create_comment` | Creates a comment on a PR announcing its replacement |
| `close_pull` | Closes the PR being replaced |

`result` uses the following values.

| Value | Meaning |
| --- | --- |
| `ok` | The operation was confirmed to have succeeded |
| `failed` | The operation was confirmed to have failed or the intended change was confirmed not to have taken effect |
| `unknown` | Whether the operation succeeded cannot be determined |

The following fields have additional notes.

- `seq`
    - Increases across all PR processing that uses the same `prs.json`, rather than separately for each repository
    - The same event has the same value when redelivered
- `id`
    - Uses the form `op-<sequence number>`, with the sequence number of the first event
    - Shared by `intent`, `result`, and `settled` for the same operation, while each event has a different `seq`
- `attempt_key`
    - Can be matched against `pull_requests[].attempt_key`, with one value corresponding to the `id` values of multiple operations
    - Because undelivered events from earlier cycles are also included, a matching entry may not exist in that notification's `pull_requests[]`
- `number`
    - The target PR number for comment creation and closure; it may be omitted from PR creation events even after success
- `phase`
    - `intent` alone does not confirm that the operation was sent to GitHub
    - Even with `settled`, `result` stays `unknown` when processing restarts without using Git file contents, trees, or commits whose creation could not be confirmed
- `error`
    - Explanatory text rather than a fixed code; for `settled`, it may contain confirmation details even when `result` is `ok`

Programs receiving the webhook should deduplicate events using `seq` within the same `prs.json` from the same sender.
Deduplicating by `id` or `attempt_key` alone would discard results and later confirmation events for the same operation.

If `prs.json` is deleted or the storage directory is changed to one without `prs.json`, `seq` starts at 1.
As a result, previously used `seq` and `id` values are used again.

The webhook contains no value that uniquely identifies the sender or identifies recreation of `prs.json`.
Neither `environment.kind` nor `environment.name` is guaranteed to be unique.

Received data alone cannot reliably distinguish events from multiple senders or events before and after recreation of `prs.json`.
The following operational measures are available.

- Use a separate receiving URL for each sender
- When recreating `prs.json`, switch the deduplication records used by the program receiving the webhook

See [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) for delivery and redelivery behavior.

## Write-blocking problem fields {#remediation-problem-fields}

`problems[]` represents problems that stop PR writes.
A problem is included in each cycle's plan while it persists, with one entry per combination of `code`, `repo`, and `target` in the same plan.

`problems[]` has the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `code` | string | Classification of the problem that stops writes | — |
| `repo` | string | `owner/name` of the repository with the problem | omitted when the problem concerns all repositories |
| `target` | string | Display string identifying the file and target locations with the problem | omitted when the problem is not limited to a target |
| `reason` | string | Specific cause of the problem from [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `detail` | string | Explanatory text supplementing the problem | omitted |

`code` uses the following values.

| Value | Meaning |
| --- | --- |
| `write_blocked` | Writes stopped because of a mismatch between records and GitHub state, a processing setup failure, or a similar problem |
| `storage_failed` | Writes stopped because the remediation plan or PR processing records could not be saved |
| `storage_full` | New writes stopped because space could not be made available for operation events |
| `records_unverified` | Writes stopped because PR records could not be verified |

`code` is the broad problem classification, and `reason` is its cause.
For example, when `code` is `write_blocked`, `reason` distinguishes causes such as `branch_not_ours` and `attempt_unsettled`.

The following fields have additional notes.

- `repo`
    - When present, match against `pull_requests[].repo`
- `target`
    - Uses the format `<file path> (<target location>, <target location>)`, with only one location inside the parentheses when there is one target location
    - Compare the file path with `pull_requests[].path` and the target locations for Compose, Kubernetes, Kustomize, Helm values, and Dockerfile updates with `pull_requests[].fix_targets[].location`
    - For language package updates, the target location is the dependency file directory and corresponds to `pull_requests[].language.root`
    - Not a matching key that equals `pull_requests[].key` or `pull_requests[].target_key`
    - Because `fix_targets` may be omitted or truncated and processing targets may change, the corresponding element of `pull_requests[]` may not be identifiable from that notification alone
    - If `repo` is present and `target` is absent, the problem concerns the entire repository

See [Stopping writes](remediation-pr-logic.md#write-stops) for stop conditions.
