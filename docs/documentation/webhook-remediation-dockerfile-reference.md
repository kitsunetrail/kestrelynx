---
title: Webhook remediation base image fields
---

# Webhook remediation base image fields

This page describes the fields for base image remediation plans, results for each running image, and rebuild estimates in `remediation` in the generic webhook payload.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall remediation plan structure.

See [Report fields](webhook-reference.md#report-fields) for table conventions.
The JSON examples are excerpts from the output.

## Base image fields {#remediation-dockerfile-fields}

The base image fields in `remediation` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `dockerfile_summary` | object | [Base image item counts by category](webhook-remediation-reference.md#remediation-summary-keys) | omitted when there are no items |
| `dockerfile_items` | array of objects | Remediation plan items for Dockerfile base images | omitted when there are no items |

`dockerfile_summary` counts `dockerfile_items[]` by `category`.
The keys are `pr_candidate`, `pull_again`, `manual`, `not_comparable`, `deferred`, `no_candidate`, `excluded`, and `failed`, and keys with zero counts are also emitted when items exist.

See [Plan category values](remediation-reason-codes.md#category-values) for the meaning of each category.

```json
{
  "dockerfile_summary": {
    "deferred": 0,
    "excluded": 0,
    "failed": 0,
    "manual": 1,
    "no_candidate": 1,
    "not_comparable": 1,
    "pr_candidate": 1,
    "pull_again": 0
  }
}
```

### Item grouping and fields {#dockerfile-item-fields}

`dockerfile_items[]` contains one item for each `FROM` line to rewrite when updating a base image.
The repository, branch, and Dockerfile path identify the file, and the stage within that file identifies the `FROM` line to rewrite.

Items are grouped or separated as follows.

- Multiple build targets or workloads built from the same `FROM` line are grouped into one item
- Different `FROM` lines form separate items even when they use the same base image name

If the Dockerfile cannot be retrieved or parsed and the `FROM` instruction cannot be identified, the failure is recorded at the level of the file, build target, or other information available.
Use `key` to identify items on the receiving side, and do not merge them by base image name alone.

The following is an excerpt from an item with a base image update candidate.

```json
{
  "key": "dockerfile:ex/app@main:docker/Dockerfile#stages[0]:runtime",
  "kind": "dockerfile",
  "fix_class": "base_image",
  "verification": "base_image_comparison",
  "final_image_verified": false,
  "category": "pr_candidate",
  "reason": "adopted",
  "priority": "act_now",
  "workloads": [
    "compose/shop/app"
  ],
  "base_ref": "python:3.12.3-slim",
  "base_kind": "pinned"
}
```

Each element of `dockerfile_items[]` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `key` | string | Key identifying the item within the remediation plan | — |
| `kind` | string | Type of remediation target | — |
| `fix_class` | string | Type of fix | — |
| `verification` | string | Target of verification | — |
| `final_image_verified` | boolean | Whether the final image after rebuilding has been verified | `false` |
| `category` | string | Item-wide category from [Plan category values](remediation-reason-codes.md#category-values) | — |
| `reason` | string | Code explaining the category, as defined in [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the category or reason | omitted |
| `priority` | string | Highest priority among fixable findings in the target workloads' running images, as defined in [Priorities](webhook-reference.md#priority-values) | omitted |
| `workloads` | array of strings | List of target workload keys, as defined in [Image name updates](webhook-diff-reference.md#reference-change-fields) | `[]` |
| `source` | object | [Source information](#dockerfile-source-fields) identifying the Dockerfile and the `FROM` line to rewrite | — |
| `base_ref` | string | Current base image reference as written in `FROM` | omitted |
| `base_kind` | string | Classification of the current base image tag | omitted |
| `candidate` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the candidate base | omitted |
| `counts` | object | [Counts](#dockerfile-count-fields) aggregated from comparisons for each running image | — |
| `rebuild_runtimes` | array of objects | Item-wide [Runtime rebuild estimates](#dockerfile-rebuild-runtimes) | omitted |
| `rebuild_check` | object | Item-wide [Check against the current base](#dockerfile-rebuild-check) | omitted |
| `entities` | array of objects | [Results for each running image](#dockerfile-entity-fields) | omitted |
| `pull_request` | object | [PR processing results](#dockerfile-pull-request-fields) associated with the item | omitted |
| `newer_series` | object | [Newer series check results](webhook-remediation-reference.md#remediation-newer-series) aggregated across all running images | omitted |
| `awaiting_deploy` | object | Information about a [Merged PR awaiting deployment](#dockerfile-awaiting-deploy-fields) whose changes have not reached the running images | omitted |

`dockerfile_items[].kind` has the following value.

| Value | Meaning |
| --- | --- |
| `dockerfile` | Item for a Dockerfile change |

`dockerfile_items[].fix_class` has the following value.

| Value | Meaning |
| --- | --- |
| `base_image` | Base image update |

`dockerfile_items[].verification` has the following value.

| Value | Meaning |
| --- | --- |
| `base_image_comparison` | Comparison of the current and candidate base images |

`dockerfile_items[].base_kind` has the following values.

| Value | Meaning |
| --- | --- |
| `pinned` | Fixed tag identifying a single release, such as `1.25.3` |
| `floating` | Floating tag, such as `1.25` or `latest` |
| `excluded` | Reference excluded from candidate searches |

The following fields have additional notes.

- `priority`
    - Only findings whose fix status is `fixed` and that have fixed version information are included
- `final_image_verified`
    - Always `false` because the final image is neither built nor scanned
    - See [Verification scope by target](remediation-logic.md#verification-scope) for the scope of verification
- `candidate`
    - Copies the first `candidate_base` found in the order of `dockerfile_items[].entities[]`
    - The presence of candidate information does not necessarily mean `category` is `pr_candidate`
    - When the item-wide `category` is `pr_candidate`, the `tag` and `top_digest` of every `entities[].candidate_base` match `candidate`
    - `platform`, `config_digest`, and `manifest_digest` can differ by platform, so see `dockerfile_items[].entities[].candidate_base` for individual values
- `newer_series`
    - Item-wide `dockerfile_items[].newer_series.candidates[]` entries do not include `comparison` or `scans`
    - Individual comparisons and scan records are included in `dockerfile_items[].entities[].newer_series`

### Source information {#dockerfile-source-fields}

`dockerfile_items[].source` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `repository` | string | Repository containing the Dockerfile, in `owner/repository` format | — |
| `base_branch` | string | Base branch from which the Dockerfile is read | — |
| `commit_sha` | string | Commit SHA confirmed on the base branch of the Dockerfile repository | omitted |
| `path` | string | Dockerfile path relative to the repository root | `""` |
| `targets` | array of strings | List of build target stage names specified by the target workloads | omitted |
| `origin` | string | Source of the information used to locate the Dockerfile | omitted |
| `compose_path` | string | Repository-relative path of the Compose file used to locate the Dockerfile | omitted |
| `files` | array of objects | List of [Source files](#dockerfile-source-file-fields) read | omitted |
| `stage` | integer | Zero-based index of the stage containing the `FROM` line to rewrite | omitted when not identified |
| `platform` | string | Static `--platform` value specified in the `FROM` line to rewrite | omitted |
| `stage_name` | string | `AS` name of the stage containing the `FROM` line to rewrite | omitted |
| `line` | integer | One-based starting line number of the `FROM` line to rewrite | omitted when not identified |

`dockerfile_items[].source.origin` has the following values.

| Value | Meaning |
| --- | --- |
| `mapping` | Located through a configuration mapping |
| `compose_build` | Located through Compose `build` |
| `mapping_and_compose_build` | Uses a configuration mapping and Compose `build` |

The following fields have additional notes.

- `targets`
    - The list is deduplicated and sorted, and an element of `""` means no build target is specified and the last stage is used
    - The build target stage can differ from the `stage` that references its base image
- `stage`
    - `0`, which identifies the first stage, is also emitted

#### Source files {#dockerfile-source-file-fields}

Each element of `dockerfile_items[].source.files[]` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | Path relative to the root of the repository containing the file | — |
| `blob_sha` | string | Git blob SHA of the file read | — |
| `repository` | string | Repository name when the file's source differs from the item's source | omitted |
| `base_branch` | string | Base branch when the file's source differs from the item's source | omitted |

Files whose `repository` and `base_branch` are omitted belong to the repository and base branch in `dockerfile_items[].source`.

The following is an example of source information for rewriting the `FROM` line in the first stage of a Dockerfile.

```json
{
  "repository": "ex/app",
  "base_branch": "main",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "path": "docker/Dockerfile",
  "targets": [
    "runtime"
  ],
  "origin": "mapping",
  "files": [
    {
      "path": "docker/Dockerfile",
      "blob_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "stage": 0,
  "stage_name": "runtime",
  "line": 3
}
```

### Target and comparison counts {#dockerfile-count-fields}

`dockerfile_items[].counts` aggregates the targets and comparison results in `dockerfile_items[].entities[]`.
The same combination of CVE ID, package name, ecosystem, and package class counts once, even when it appears in multiple running images.

`dockerfile_items[].counts` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `targets` | integer | Number of fix targets after deduplication across all running images | `0` |
| `resolved` | integer | Number of targets resolved in every running image that has the target | `0` |
| `remaining` | integer | Number of targets remaining in any running image that has the target | `0` |
| `introduced` | integer | Number of newly detected findings in the candidate base image after deduplication | `0` |

The following fields have additional notes.

- `targets`
    - The same combination of CVE ID, package name, ecosystem, and class counts once, even when there are multiple package versions or locations
    - This is not a simple sum of `entities[].targets`
- `resolved` and `remaining`
    - Running images without a target do not affect its aggregation
    - Targets that were not compared or could not be determined may count as neither resolved nor remaining, so the sum can be less than `targets`
- `introduced`
    - Deduplicates by the same combination of CVE ID, package name, ecosystem, and class used for fix targets
    - Also counts new findings in packages not included in the fix targets

The following is an example of counts for an item without target comparison results.

```json
{
  "targets": 0,
  "resolved": 0,
  "remaining": 0,
  "introduced": 0
}
```

### Merged PR awaiting deployment {#dockerfile-awaiting-deploy-fields}

`dockerfile_items[].awaiting_deploy` describes a merged base image update PR whose changes have not yet reached the running images.

The main conditions for emitting this information are as follows.

- A base image update PR created by KestreLynx has been merged
- Every running image in the item matches one of the running images present when that PR was created

Deploying an image built from the Dockerfile after the merge applies the update.
In this case, `dockerfile_items[].reason` is `base_update_not_deployed`.

`dockerfile_items[].awaiting_deploy` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `number` | integer | Merged PR number | — |
| `url` | string | Merged PR URL | omitted |
| `from` | string | Base image name referenced by `FROM` before the PR, from which the running images were built | — |
| `to` | string | Tag set in `FROM` by the PR | — |

See [Rebuild guidance](remediation-update-results.md#rebuild-guidance) for how to interpret results awaiting deployment.

### PR processing results {#dockerfile-pull-request-fields}

`dockerfile_items[].pull_request` describes the PR processing result for the item's base image update.

It is emitted when PR processing for the item's update is available.
It also includes processing results such as manual handling or deferral where no PR was created.

`dockerfile_items[].pull_request` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `status` | string | PR processing status from [PR status values](remediation-reason-codes.md#pr-status-values) | — |
| `reason` | string | Code explaining the PR processing result, as defined in [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `number` | integer | Associated PR number | omitted |
| `url` | string | Associated PR URL | omitted |
| `state` | string | Associated PR record state from [PR status values](remediation-reason-codes.md#pr-status-values) | omitted |

The following is an example of a result after creating a PR.

```json
{
  "status": "pr_created",
  "number": 7,
  "url": "https://github.com/ex/app/pull/7",
  "state": "open"
}
```

## Results for each running image {#dockerfile-entity-fields}

Each element of `dockerfile_items[].entities[]` contains the results for one image running in the workloads targeted by the item.
Results are separated because workloads can run different images even when those images were built from the same `FROM` line.

The combination of `running_image.ref` and `running_image.content` distinguishes the images.
The rules for separating and grouping elements are as follows.

- When multiple workloads use the same image, there is one element, with information about each workload listed in that element's `services[]`
- When `running_image.content` uses a registry digest, the same image name and digest produce separate elements if the platforms differ
    - `running_image.content` identifies the content and, in this case, also includes the platform
- When the content cannot be identified, `running_image.content` is `unconfirmed`, and unconfirmed images with the same `running_image.ref` are grouped into one element
    - In this case, the same `ref` does not confirm that the content is the same

Each element of `dockerfile_items[].entities[]` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `services` | array of objects | Information about [Services](webhook-remediation-reference.md#remediation-services) using the running image | omitted |
| `running_image` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the running image in which findings were detected | — |
| `current_base` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the base currently referenced by the `FROM` tag | omitted |
| `candidate_base` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the candidate base | omitted |
| `layer_confirmation` | object | [Layer matching results](#dockerfile-layer-confirmation-fields) for the running image and current base | — |
| `findings_by_layer` | object | [Finding counts by layer](#dockerfile-layer-count-fields) for the running image | — |
| `category` | string | Category for the running image from [Plan category values](remediation-reason-codes.md#category-values) | — |
| `reason` | string | Code explaining the category, as defined in [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of the category or reason | omitted |
| `targets` | integer | Number of fix targets belonging to the base | `0` |
| `kev_targets` | integer | Number of fix targets listed in CISA KEV | omitted when the count is zero |
| `comparison` | object | [Comparison results](webhook-remediation-reference.md#remediation-comparison) for the fix targets between the current and candidate bases | omitted |
| `rebuild_runtimes` | array of objects | [Runtime rebuild estimates](#dockerfile-rebuild-runtimes) for the running image | omitted |
| `rebuild_check` | object | [Check against the current base](#dockerfile-rebuild-check) for the running image | omitted |
| `scans` | array of objects | [Scan records](webhook-remediation-reference.md#remediation-scan-records) for the current and candidate bases | omitted |
| `newer_series` | object | [Newer series check results](webhook-remediation-reference.md#remediation-newer-series) for the running image | omitted |

The following fields have additional notes.

- `targets` and `kev_targets`
    - Counts are deduplicated by the combination of CVE ID, package name, ecosystem, and class
    - `targets` is also `0` when fix target selection has not been reached
- `comparison`
    - `verdicts[]` contains assessments limited to the running image's fix targets
    - This is not a comparison of the final image after rebuilding
- `scans`
    - The current base has `role: baseline`, and the candidate base has `role: candidate`
    - Only available records are emitted

The following is an excerpt from the results for a running image.

```json
{
  "running_image": {
    "ref": "shop-app:1",
    "content": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "config_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "platform": "linux/amd64",
    "digest_kind_unverified": true
  },
  "layer_confirmation": {
    "status": "confirmed",
    "base_layers": 2,
    "image_layers": 3
  },
  "findings_by_layer": {
    "base": 3,
    "upper": 1,
    "unknown": 1
  },
  "category": "pr_candidate",
  "reason": "adopted",
  "targets": 3,
  "kev_targets": 1
}
```

### Layer matching results {#dockerfile-layer-confirmation-fields}

`dockerfile_items[].entities[].layer_confirmation` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `status` | string | Layer matching status | — |
| `base_layers` | integer | Number of base layers that match the beginning of the running image | omitted when a match cannot be confirmed |
| `image_layers` | integer | Number of layers obtained from the running image | omitted when the count is zero |
| `detail` | string | Additional explanation of the matching status | omitted |

`dockerfile_items[].entities[].layer_confirmation.status` has the following values.

| Value | Meaning |
| --- | --- |
| `confirmed` | The current base's layer sequence matches the beginning of the running image |
| `mismatch` | The layer information was compared and does not match the beginning of the running image |
| `unusable` | Layer information is insufficient or unusable, preventing matching |
| `not_checked` | Layer matching has not been reached |

See [Base layer matching](remediation-base-image-logic.md#base-layer-matching) for the scope and conditions of matching.

### Finding counts by layer {#dockerfile-layer-count-fields}

`dockerfile_items[].entities[].findings_by_layer` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `base` | integer | Number of findings classified as belonging to the current base | `0` |
| `upper` | integer | Number of findings classified as belonging to layers above the base | `0` |
| `unknown` | integer | Number of findings that could not be classified as belonging to either the base or later layers | `0` |

Each occurrence of a finding is counted, so these are not counts of deduplicated CVE IDs.
Findings not selected as fix targets are also included.

All three counts are `0` when classification has not been reached, so all-zero counts do not necessarily mean there are no findings.
When reading the results, also check `dockerfile_items[].entities[].category`, `reason`, and `layer_confirmation.status`.

## Runtime rebuild estimates {#dockerfile-rebuild-runtimes}

`rebuild_runtimes[]` describes how the CVEs currently detected in the running image would change if it inherited the runtime version in the current base.
It appears in two places: results for each running image and item-wide aggregates.

The inclusion conditions are as follows.

- `dockerfile_items[].entities[].rebuild_runtimes`
    - Included when the corresponding `dockerfile_items[].entities[].reason` is `floating_base_unconfirmed` and the running image's runtime findings could be checked against the version in the current base
    - Omitted when no runtimes could be checked
- `dockerfile_items[].rebuild_runtimes`
    - Aggregates individual results when `dockerfile_items[].entities[]` has at least one element and every `dockerfile_items[].entities[].reason` is `floating_base_unconfirmed`
    - Omitted when the aggregate is empty
    - When running images with other reasons are mixed in, the item-wide result is omitted while individual records for qualifying running images are retained

Each element of `dockerfile_items[].rebuild_runtimes[]` has the following fields, and `dockerfile_items[].entities[].rebuild_runtimes[]` uses the same structure.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Runtime name | — |
| `installed` | string | Runtime version in the running image | — |
| `base_version` | string | Runtime version in the current base | — |
| `disappearing` | array of strings | CVE IDs expected to disappear if the version in the current base is inherited | omitted |
| `remaining` | array of strings | CVE IDs that remain in the version in the current base | omitted |

`dockerfile_items[].rebuild_runtimes[].package` has the following values.

| Value | Meaning |
| --- | --- |
| `Node.js` | Node.js runtime itself |
| `Python runtime` | Python runtime itself |

The following fields have additional notes.

- `disappearing` and `remaining`
    - Includes only CVEs currently detected in the running image, excluding CVEs newly introduced by the version in the current base
    - CVE IDs are deduplicated and sorted
    - Item-wide aggregation groups records with the same `package`, `installed`, and `base_version`
    - An ID in `remaining` in any grouped record is excluded from the item-wide `disappearing` list

These results are estimates based on runtime versions, not verification of the final image.
See [Base layer matching](remediation-base-image-logic.md#base-layer-matching) and [Rebuild guidance](remediation-update-results.md#rebuild-guidance) for conditions and limitations.

## Check against the current base {#dockerfile-rebuild-check}

`rebuild_check` contains the results of matching the running image against the current base by package location and CVE.
The final image is not built, and `dockerfile_items[].final_image_verified` remains `false`.

The findings used in the check are as follows.

| Image | Findings used in the check |
| --- | --- |
| Running image | Findings within the compared severity range whose fix status is `fixed` and that have fixed version information |
| Current base | All findings within the compared severity range, including those without fixed versions (to check whether a CVE remains) |

See [Base layer matching](remediation-base-image-logic.md#base-layer-matching) for location matching and conditions that leave findings undetermined.

The inclusion conditions are as follows.

- `dockerfile_items[].entities[].rebuild_check`
    - Included when the corresponding `dockerfile_items[].entities[].reason` is `floating_base_unconfirmed` and a check result is available
    - Also records cases where comparison was not possible, with `status: not_checked`
- `dockerfile_items[].rebuild_check`
    - Aggregates individual results when `dockerfile_items[].entities[]` has at least one element and every `dockerfile_items[].entities[].reason` is `floating_base_unconfirmed`
    - When running images with other reasons are mixed in, the item-wide result is omitted while individual records are retained

The webhook emits results even when `status` is `checked` and no findings are expected to disappear, with nothing displayed in Slack or email.

`dockerfile_items[].rebuild_check` has the following fields, and `dockerfile_items[].entities[].rebuild_check` uses the same structure.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `status` | string | Status of the check | — |
| `reason` | string | Code explaining why comparison was not possible, as defined in [Reason codes](remediation-reason-codes.md#reason-codes) | omitted |
| `detail` | string | Additional explanation of why comparison was not possible | omitted |
| `gone` | array of objects | [Package records](#dockerfile-rebuild-package-fields) for which the base has a different version at the same location without the target CVE | omitted |
| `remaining` | array of objects | [Package records](#dockerfile-rebuild-package-fields) whose target CVE is also present at the same location in the base | omitted |
| `not_in_base` | array of objects | [Package records](#dockerfile-rebuild-package-fields) for OS packages or packages in a global `node_modules` absent from the same location in the base | omitted |
| `other_not_in_base` | integer | Number of packages outside the scope of `not_in_base` that are absent from the same location in the base, such as application dependencies | omitted when the count is zero |
| `only_in_base` | array of objects | [Package records](#dockerfile-rebuild-package-fields) with corresponding fixable findings present only in the current base | omitted |
| `undetermined` | integer | Number of findings that could not be determined | omitted when the count is zero |
| `running_scan` | object | Running image record in the [Scan records](webhook-remediation-reference.md#remediation-scan-records) format | omitted |
| `base_scan` | object | Current base record in the [Scan records](webhook-remediation-reference.md#remediation-scan-records) format | omitted |

`dockerfile_items[].rebuild_check.status` has the following values.

| Value | Meaning |
| --- | --- |
| `checked` | All targeted findings were determined |
| `partial` | The check was performed, but some findings could not be determined |
| `not_checked` | No comparison was made |

The following fields have additional notes.

- `not_in_base`
    - Cannot distinguish packages removed from the base from packages added by Dockerfile instructions
- `other_not_in_base`
    - Counts for each running image are deduplicated by the combination of package class, name, version, and path
- `only_in_base`
    - Contains base findings whose fix status is `fixed` and that have fixed version information, with no corresponding finding at the same location in the running image
    - Includes findings that Dockerfile instructions may remove
- `undetermined`
    - Findings for language runtimes themselves are handled by `rebuild_runtimes`, and targets that cannot be confirmed in those records count toward `undetermined`
- `running_scan` and `base_scan`
    - Recorded in results for each running image and not included in item-wide aggregates
    - Both records have `role` set to `baseline`, so use the field names to distinguish their targets

### Package records {#dockerfile-rebuild-package-fields}

Each element of `gone[]`, `remaining[]`, `not_in_base[]`, or `only_in_base[]` groups a package version at one location with the CVEs belonging to that result.
When outcomes differ by CVE, the same package appears in multiple arrays.

Each element of `dockerfile_items[].rebuild_check.gone[]` has the following fields, with the same structure used by `remaining[]`, `not_in_base[]`, `only_in_base[]`, and the `rebuild_check` for each running image.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Package name | — |
| `version` | string | Package version covered by the record | `""` |
| `class` | string | Package class | — |
| `path` | string | String identifying the package location in the scan result | omitted |
| `owner` | string | Name of the package under which this package is located in a global `node_modules` | omitted |
| `base_version` | string | Version at the same location in the current base corresponding to the `gone` record | omitted |
| `vuln_ids` | array of strings | List of CVE IDs belonging to this record's result | — |

`dockerfile_items[].rebuild_check.gone[].class` has the following values.

| Value | Meaning |
| --- | --- |
| `os` | OS package |
| `lang` | Language package |

The following fields have additional notes.

- `version`
    - The running image's version in `gone[]`, `remaining[]`, and `not_in_base[]`
    - The current base's version in `only_in_base[]`
- `path`
    - Uses the package's own path when available, otherwise a string identifying the scan target where it was detected
    - Omitted for OS packages
    - The emitted string is the value at detection time, not a path with the version removed for location matching
- `owner`
    - For example, `npm` for a dependency at `usr/local/lib/node_modules/npm/node_modules/undici/package.json`
- `base_version`
    - Set only in `gone[]`
- `vuln_ids`
    - Contains one or more IDs, deduplicated and sorted

### Item-wide aggregation {#dockerfile-rebuild-check-reading}

This section describes the rules for aggregating each running image's `rebuild_check` into `dockerfile_items[].rebuild_check`.

The item-wide `status` is determined by the following conditions.

| Item-wide `status` | Condition |
| --- | --- |
| `not_checked` | At least one running image has not been compared (its result is `not_checked` or missing) |
| `partial` | Every running image has been compared and at least one result is `partial` |
| `checked` | Every running image has a `checked` result |

The aggregation rules for each field are as follows.

| Field | Aggregation |
| --- | --- |
| `gone` | Includes a finding only if it disappears in every running image that has it |
| `gone`, `remaining`, `not_in_base`, and `only_in_base` | Records with the same package class, name, version, path, and `base_version` are grouped into one record, with CVE IDs deduplicated |
| `undetermined` | Sum of the counts for each running image |
| `other_not_in_base` | Maximum of the counts for each running image |

The following notes also apply to item-wide aggregation.

- When the item-wide result is `not_checked`, package lists from checked running images are retained in individual results but excluded from the item-wide result
- When current base versions differ by platform, separate records are kept for each `base_version`

See [Rebuild guidance](remediation-update-results.md#rebuild-guidance) for limitations of the estimates, including the effects of Dockerfile instructions.
