---
title: Webhook remediation overview and shared objects
---

# Webhook remediation overview and shared objects

This page describes the overall structure of a remediation plan.

It also describes the fields of objects shared by published image, base image, and PR processing items.
These are image information, comparison results, scan records, newer series check results, and services.

When remediation planning is enabled, `remediation` is included in both full and diff payloads.
See [Webhook base fields](webhook-reference.md#top-level) for the overall report structure.

| Content | Page |
| --- | --- |
| Published image items (`summary`, `items`) | [Webhook remediation published image fields](webhook-remediation-image-reference.md) |
| Base image items (`dockerfile_summary`, `dockerfile_items`) | [Webhook remediation base image fields](webhook-remediation-dockerfile-reference.md) |
| Language package items (`language_summary`, `language_items`) | [Webhook remediation language package fields](webhook-remediation-language-reference.md) |
| Language package update records (`language_items[].update`) | [Webhook remediation update record fields](webhook-remediation-update-reference.md) |
| Checks before and after language package updates (`language_items[].source_check`, `artifacts`) | [Webhook remediation update check fields](webhook-remediation-check-reference.md) |
| PR processing (`pull_request_summary`, `pull_requests`, `operations`, `problems`) | [Webhook remediation PR processing fields](webhook-remediation-pr-reference.md) |

## Remediation plan overview {#remediation-overview}

The direct children of `remediation` contain the plan status, comparison conditions, work counts, and results for each target type.
The following structure includes fields that may be omitted.

```text
remediation
├── schema_version
├── status
├── unavailable_reason
├── not_saved
├── generated_at
├── conditions                    Comparison scan conditions
├── limits                        Work count limits
├── usage                         Actual work counts
├── summary                       Published image count summary
├── items[]                       Array of published image items
├── dockerfile_summary            Base image count summary
├── dockerfile_items[]            Array of base image items
├── language_summary              Language package count summary
├── language_items[]              Array of language package items
├── pull_request_summary          PR processing count summary
├── pull_requests[]               Array of PR processing items
├── operations[]                  PR operation records
└── problems[]                    Problems that stop PR writes
```

Each target type has a count summary paired with an array of items.
Only published images use the names `summary` and `items` without a prefix.

The following is the `remediation` output when a plan was generated successfully but no items required remediation.
Even with no remediation targets, the plan generation time, work limits and counts, published image summary, and empty `items` array are emitted.

```json
{
  "remediation": {
    "schema_version": 1,
    "status": "ok",
    "generated_at": "2026-10-09T03:00:00Z",
    "conditions": {
      "trivy_version": "0.71.2",
      "trivy_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "vulnerability_db_updated_at": "2026-10-09T00:00:00Z",
      "vulnerability_db_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "java_db_updated_at": "2026-10-08T12:00:00Z",
      "java_db_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
      "severities": [
        "CRITICAL",
        "HIGH"
      ],
      "analysis_settings": "image;scanners=default;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;env=sanitized;workdir=isolated"
    },
    "limits": {
      "max_candidate_scans": 10,
      "max_baseline_rescans": 10,
      "max_tag_pages": 20
    },
    "usage": {
      "candidate_scans": 0,
      "baseline_rescans": 0,
      "tag_pages": 0,
      "registry_requests": 0
    },
    "summary": {
      "deferred": 0,
      "excluded": 0,
      "failed": 0,
      "manual": 0,
      "no_candidate": 0,
      "not_comparable": 0,
      "pr_candidate": 0,
      "pull_again": 0
    },
    "items": []
  }
}
```

Even when no plan could be generated, `remediation` and an empty `items` array are emitted.

```json
{
  "remediation": {
    "schema_version": 1,
    "status": "unavailable",
    "unavailable_reason": "databases_not_prepared",
    "items": []
  }
}
```

## Common remediation plan fields {#remediation-fields}

See [Report fields](webhook-reference.md#report-fields) for how to read the tables.
See [Plan category values](remediation-reference.md#category-values) for each item's `category` and [Reason codes](remediation-reference.md#reason-codes) for `reason`.

`remediation` has the following direct-child fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `schema_version` | integer | Version of the remediation plan JSON format, currently `1` | — |
| `status` | string | Status indicating whether a plan could be generated | — |
| `unavailable_reason` | string | Reason a plan could not be generated | omitted when a plan was generated |
| `not_saved` | boolean | `true` when the generated plan could not be saved | omitted when `false` |
| `generated_at` | string | Plan generation time in RFC 3339 format | omitted when there is no plan |
| `conditions` | object | [Comparison scan conditions](#remediation-conditions) | omitted when condition information is unavailable |
| `limits` | object | [Planning limits](#remediation-limits) | omitted when there is no plan |
| `usage` | object | [Planning work counts](#remediation-usage) | omitted when there is no plan |
| `summary` | object | Published image item counts by category, described in [Webhook remediation published image fields](webhook-remediation-image-reference.md) | omitted when there is no plan |
| `items` | array of objects | Published image items, described in [Webhook remediation published image fields](webhook-remediation-image-reference.md) | `[]` |
| `language_summary` | object | Language package item counts by category, described in [Webhook remediation language package fields](webhook-remediation-language-reference.md) | omitted when there are no corresponding items |
| `language_items` | array of objects | Language package items, described in [Webhook remediation language package fields](webhook-remediation-language-reference.md) | omitted when empty |
| `dockerfile_summary` | object | Base image item counts by category, described in [Webhook remediation base image fields](webhook-remediation-dockerfile-reference.md) | omitted when there are no corresponding items |
| `dockerfile_items` | array of objects | Base image items, described in [Webhook remediation base image fields](webhook-remediation-dockerfile-reference.md) | omitted when empty |
| `pull_request_summary` | object | PR processing item counts by status, described in [Webhook remediation PR processing fields](webhook-remediation-pr-reference.md) | omitted when there are no corresponding items |
| `pull_requests` | array of objects | PR processing items, described in [Webhook remediation PR processing fields](webhook-remediation-pr-reference.md) | omitted when empty |
| `operations` | array of objects | PR operation records, described in [Webhook remediation PR processing fields](webhook-remediation-pr-reference.md) | omitted when empty |
| `problems` | array of objects | Problems that stop PR writes, described in [Webhook remediation PR processing fields](webhook-remediation-pr-reference.md) | omitted when empty |

The values of `status` are as follows.

| Value | Meaning |
| --- | --- |
| `ok` | A plan was generated |
| `unavailable` | A plan could not be generated |

`ok` does not mean that every individual candidate check or PR processing operation succeeded.
Check the arrays for each target type for individual item results.

The values of `unavailable_reason` are as follows.

| Value | Meaning |
| --- | --- |
| `databases_not_prepared` | The scan databases could not be prepared, preventing generation of a plan that compares scans under equal conditions |
| `planner_not_built` | The processing needed to generate a plan could not be set up |

### Item counts {#remediation-summary-keys}

This section explains the contents of `summary`, `dockerfile_summary`, `language_summary`, and `pull_request_summary`.

The following example shows `summary`, which counts published image items by category.

```json
{
  "summary": {
    "deferred": 0,
    "excluded": 0,
    "failed": 0,
    "manual": 1,
    "no_candidate": 0,
    "not_comparable": 0,
    "pr_candidate": 2,
    "pull_again": 1
  }
}
```

The key `pr_candidate` is a category name, and its value `2` means that two items in `items[]` have `category` set to `pr_candidate`.
Likewise, there is one `manual` item and one `pull_again` item.

An item counts as `1` even if it contains multiple vulnerabilities or packages.

The four fields differ as follows.

| Field | What is counted | Keys | Keys with zero counts | When the field itself is omitted |
| --- | --- | --- | --- | --- |
| `summary` | Items in `items[]` | Category names from `category` (8 values) | `0` emitted | No plan |
| `dockerfile_summary` | Items in `dockerfile_items[]` | Category names from `category` (8 values) | `0` emitted | `dockerfile_items[]` is empty |
| `language_summary` | Items in `language_items[]` | Category names from `category` (7 values) | `0` emitted | `language_items[]` is empty |
| `pull_request_summary` | Items in `pull_requests[]` | [PR status values](remediation-reference.md#pr-status-values) from `status` | omitted | `pull_requests[]` is empty |

When a plan exists, all eight `summary` keys are emitted with `0` even if `items[]` is empty.
`dockerfile_summary` does not count `dockerfile_items[].entities[]` individually.

`summary` and `dockerfile_summary` use eight keys: `pull_again`, `pr_candidate`, `manual`, `not_comparable`, `deferred`, `no_candidate`, `excluded`, and `failed`.
`language_summary` uses seven keys: `pr_candidate`, `dependency_update_candidate`, `rebuild_expected`, `manual`, `not_comparable`, `deferred`, and `failed`.

### Comparison scan conditions {#remediation-conditions}

`conditions` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `trivy_version` | string | Trivy version used for comparison scans | `""` |
| `trivy_sha256` | string | SHA-256 of the Trivy executable | omitted |
| `vulnerability_db_updated_at` | string | Vulnerability database update time in RFC 3339 format | omitted |
| `vulnerability_db_sha256` | string | SHA-256 of the vulnerability database file | omitted |
| `java_db_updated_at` | string | Java database update time in RFC 3339 format | omitted |
| `java_db_sha256` | string | SHA-256 of the Java database file | omitted |
| `severities` | array of strings | Severities covered by comparison scans | omitted when empty |
| `analysis_settings` | string | String identifying the analysis settings for comparison scans | omitted |

The following fields have additional notes.

- `conditions`
    - Emitted when `trivy_version` is not empty
    - Emitted even when `trivy_version` is empty if the update time corresponding to `vulnerability_db_updated_at` and a nonzero vulnerability database format version, which is not emitted in the JSON, are recorded
    - The object itself is omitted when `trivy_version` is empty and either the update time is missing or the format version is `0`
    - Java database or severity information alone does not cause the object to be emitted
- `trivy_version`
    - Emitted as an empty string inside `conditions` when only vulnerability database information is known
- `trivy_sha256`, `vulnerability_db_sha256`, `java_db_sha256`
    - SHA-256 is represented in hexadecimal without the `sha256:` prefix
- `severities`
    - The usual values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`
- `analysis_settings`
    - A string identifying analysis options, configuration files, and other settings, rather than a value consisting only of a hash

See [Scan comparison conditions](remediation-logic.md#comparison-conditions) for details of the comparison conditions.
The following example extracts the version, update times, and severities from the conditions.

```json
{
  "trivy_version": "0.71.2",
  "vulnerability_db_updated_at": "2026-10-09T03:00:00Z",
  "java_db_updated_at": "2026-10-09T03:00:00Z",
  "severities": [
    "CRITICAL",
    "HIGH"
  ]
}
```

### Planning limits {#remediation-limits}

`limits` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `max_candidate_scans` | integer | Maximum number of candidate image scans in one planning pass | `0` |
| `max_baseline_rescans` | integer | Maximum number of baseline rescans in one planning pass | `0` |
| `max_tag_pages` | integer | Maximum number of tag-list retrieval requests for one repository | `0` |

A limit of `0` means that the work cannot be performed.
`max_tag_pages` counts both tag-list page retrievals and requests that search successive tags in the same series.

```json
{
  "max_candidate_scans": 10,
  "max_baseline_rescans": 10,
  "max_tag_pages": 20
}
```

### Planning work counts {#remediation-usage}

`usage` has the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `candidate_scans` | integer | Number of candidate image scans performed | `0` |
| `baseline_rescans` | integer | Number of baseline rescans performed | `0` |
| `tag_pages` | integer | Total number of tag-list retrieval requests | `0` |
| `registry_requests` | integer | Number of registry requests consumed during planning | `0` |

`tag_pages` totals requests across repositories, so it can exceed the per-repository limit `limits.max_tag_pages`.

```json
{
  "candidate_scans": 2,
  "baseline_rescans": 0,
  "tag_pages": 0,
  "registry_requests": 7
}
```

## Shared objects {#remediation-common-objects}

The following objects use a shared structure within published image items (`items[]`), base image items (`dockerfile_items[]`), and PR processing (`pull_requests[]`).
Their structures are documented in this section, which the pages for each item type reference.

| Object | Content | Appears in |
| --- | --- | --- |
| [Image information](#remediation-image-state) | Image names, digests, and other identifying information | Published images, base images |
| [Comparison results](#remediation-comparison) | Resolved, remaining, and newly detected findings | Published images, base images |
| [Scan records](#remediation-scan-records) | Scan targets, roles, and verification results | Published images, base images |
| [Newer series check results](#remediation-newer-series) | Newer series candidates and their check results | Published images, base images |
| [Services](#remediation-services) | Information about services and workloads using the image | Published images, base images, PR processing |

### Image information {#remediation-image-state}

Image information is emitted in the following fields.

- `items[].current`, `items[].candidate`
- `items[].newer_series.candidates[].candidate`
- `dockerfile_items[].candidate`
- `dockerfile_items[].entities[].running_image`, `current_base`, `candidate_base`
- `dockerfile_items[].newer_series.candidates[].candidate`
- `dockerfile_items[].entities[].newer_series.candidates[].candidate`

`items[].current` and other image information objects have the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `ref` | string | Image name including any tag or digest specification | `""` |
| `tag` | string | Image tag | omitted |
| `content` | string | String identifying the running image's content, including the digest kind | omitted |
| `config_digest` | string | Digest identifying the image configuration | omitted |
| `manifest_digest` | string | Digest identifying the image manifest for the target platform | omitted |
| `top_digest` | string | Digest identifying the image index or manifest that the tag or other reference points to | omitted |
| `platform` | string | Platform in `OS/architecture` format, such as `linux/amd64` | omitted |
| `digest_kind_unverified` | boolean | `true` when the running image's digest kind has not been verified | omitted when `false` |

The following fields have additional notes.

- `content`
    - Emitted only in `items[].current` and `dockerfile_items[].entities[].running_image`
    - The format is `config:sha256:<64 lowercase hexadecimal digits>` or `registry:sha256:<64 lowercase hexadecimal digits>@<OS>/<architecture>`
    - Set to `unconfirmed` when a valid digest could not be obtained
- `config_digest`, `manifest_digest`, `top_digest`
    - The format is `sha256:<64 lowercase hexadecimal digits>`
    - Does not include the `config:` or `registry:` prefix or the platform found in `content`
- `top_digest`
    - For an image containing multiple platforms, identifies the image index that lists them
    - Equals `manifest_digest` when the reference points to a single image manifest
- `digest_kind_unverified`
    - When `true`, neither the `config:` notation in `content` nor `config_digest` alone confirms that the value is an image configuration digest
    - The value obtained from the container runtime may instead be a manifest or image index digest

The following is information about the current base image.

```json
{
  "ref": "python:3.12.3-slim",
  "tag": "3.12.3-slim",
  "config_digest": "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
  "manifest_digest": "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
  "top_digest": "sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
  "platform": "linux/amd64"
}
```

### Comparison results {#remediation-comparison}

Comparison results are used in `items[].comparison`, `dockerfile_items[].entities[].comparison`, and each running image's `newer_series.candidates[].comparison`.
See [Scan comparison conditions](remediation-logic.md#comparison-conditions) for comparison conditions and [Resolved findings in comparisons](remediation-results.md#verification-results) for interpreting results.

The following example extracts the main fields from a comparison result that resolves one target finding.

```json
{
  "comparable": true,
  "decision": "adopt",
  "targets": 1,
  "resolved": 1,
  "remaining": 0,
  "unknown": 0,
  "undetected": 0,
  "introduced": 0,
  "verdicts": [
    {
      "vuln_id": "CVE-2031-0000",
      "package": "libc",
      "severity": "HIGH",
      "outcome": "resolved",
      "disposition": "version_changed"
    }
  ]
}
```

`items[].comparison` and other comparison result objects have the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `comparable` | boolean | `true` when the results can be compared | `false` |
| `reason` | string | [Reason codes](remediation-reference.md#reason-codes) value explaining why comparison is not possible | omitted |
| `scope` | string | English text describing the comparison scope, such as the severities evaluated | omitted |
| `decision` | string | Candidate adoption decision based on the comparison results | omitted |
| `targets` | integer | Number of target findings evaluated | `0` |
| `resolved` | integer | Number of resolved findings | `0` |
| `remaining` | integer | Number of findings remaining in the candidate | `0` |
| `unknown` | integer | Number of target findings that could not be judged | `0` |
| `undetected` | integer | Number of target findings not detected in the baseline | `0` |
| `introduced` | integer | Number of findings newly detected in the candidate | `0` |
| `verdicts` | array of objects | Individual verdicts for baseline findings | omitted when empty |
| `verdicts_truncated` | boolean | `true` when some `verdicts` entries were omitted because of the count limit | omitted when `false` |
| `introduced_findings` | array of objects | Individual verdicts for findings newly detected in the candidate | omitted when empty |
| `introduced_findings_truncated` | boolean | `true` when some `introduced_findings` entries were omitted because of the count limit | omitted when `false` |

The following fields have additional notes.

- `scope`
    - This is descriptive text rather than a fixed code, so use `comparable`, `reason`, and `decision` to identify the status
- `resolved`, `remaining`, `unknown`, `undetected`
    - Comparisons with a `decision` count only findings targeted by the adoption decision, excluding other findings included in `verdicts[]`
    - For a newer series candidate, the counts match that candidate's `counts`
    - In comparisons with neither a `decision` nor candidate `counts`, `resolved` and `remaining` are counted from the results before the `verdicts[]` count limit is applied, while `unknown` and `undetected` are `0`
    - When `comparable` is `false`, a count of `0` does not mean that there are no targets or that they have been resolved
- `verdicts`
    - Ordinary published image comparisons may include findings outside the adoption decision's targets
    - Base image comparisons and newer series candidate comparisons include only target findings
- `verdicts`, `introduced_findings`
    - Each list contains at most 50 entries, with the corresponding `*_truncated` set to `true` if the limit is exceeded
    - Count fields are not reduced when list entries are omitted, so do not derive total counts from array lengths

The values of `decision` are as follows.

| Value | Meaning |
| --- | --- |
| `adopt` | Adopted as a candidate that resolves all targets |
| `adopt_partial` | Adopted as a candidate that resolves some targets |
| `not_resolving` | No targets are resolved |
| `introduced` | New findings are present |
| `new_kev` | Newly detected vulnerabilities include a KEV-listed vulnerability |
| `analysis_incomplete` | Analysis is insufficient to judge the targets |
| `targets_not_detected` | Targets were not detected in the baseline, so resolution cannot be judged |
| `not_comparable` | Comparison is not possible |

`items[].comparison.verdicts[]` has the following fields in each element.
The elements of `verdicts[]` and `introduced_findings[]` in each `comparison` use the same structure.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `vuln_id` | string | Vulnerability ID | — |
| `package` | string | Name of the package being evaluated | — |
| `ecosystem` | string | Package type | omitted |
| `severity` | string | Vulnerability severity | omitted |
| `outcome` | string | Comparison outcome for the finding | — |
| `disposition` | string | How the package associated with a resolved finding changed in the candidate | omitted |
| `reason` | string | [Reason codes](remediation-reference.md#reason-codes) value explaining why an individual finding could not be judged | omitted |
| `before_versions` | array of strings | Package versions recorded in the baseline | omitted when empty |
| `after_versions` | array of strings | Package versions at locations where the vulnerability was detected in the candidate | omitted when empty |

The following fields have additional notes.

- `ecosystem`
    - Identifies the package type in the scan results, such as `alpine`, `debian`, `node-pkg`, or `python-pkg`
- `severity`
    - The usual values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`
- `before_versions`, `after_versions`
    - Duplicate versions are removed and the values are sorted lexicographically
    - These fields do not list every installed location of the package
- `after_versions`
    - Omitted when `outcome` is `resolved`, and does not indicate the package version installed after the fix

The values of `outcome` are as follows.

| Value | Meaning |
| --- | --- |
| `resolved` | A finding present in the baseline is absent from the candidate within the evaluated scope |
| `remaining` | The finding is also present in the candidate |
| `introduced` | The finding was absent from the baseline and newly detected in the candidate |
| `unknown` | Whether the finding is resolved or remains cannot be judged |

The values of `disposition` are as follows.

| Value | Meaning |
| --- | --- |
| `package_removed` | The package is absent from the candidate |
| `version_changed` | The candidate contains only versions different from those in the baseline |
| `same_version` | The candidate contains a version present in the baseline, but the finding is no longer detected |

### Scan records {#remediation-scan-records}

Scan records are used in `scans[]` for published images and base images, and in `scans[]` for newer series candidates.
The base image fields `rebuild_check.running_scan` and `rebuild_check.base_scan` use the same structure.

The following example shows records where the baseline and candidate content was confirmed and database verification after each scan succeeded.

```json
[
  {
    "role": "baseline",
    "ref": "python:3.12.3-slim",
    "requested": "registry:sha256:1111111111111111111111111111111111111111111111111111111111111111@linux/amd64",
    "confirmed": "registry:sha256:1111111111111111111111111111111111111111111111111111111111111111@linux/amd64",
    "db": "verified",
    "scanned_at": "2026-10-09T02:59:00Z"
  },
  {
    "role": "candidate",
    "ref": "python:3.12.5-slim",
    "requested": "registry:sha256:2222222222222222222222222222222222222222222222222222222222222222@linux/amd64",
    "confirmed": "registry:sha256:2222222222222222222222222222222222222222222222222222222222222222@linux/amd64",
    "db": "verified",
    "scanned_at": "2026-10-09T02:59:30Z"
  }
]
```

`items[].scans[]` and other scan record arrays have the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `role` | string | Role of the scan in the comparison | — |
| `ref` | string | Name of the scanned image | `""` |
| `requested` | string | Identity string of the image the scan was asked to confirm | `""` |
| `confirmed` | string | Identity string of the image confirmed by the scan | `""` |
| `db` | string | Result of database verification after the scan | `""` |
| `scanned_at` | string | Scan time in RFC 3339 format | omitted when no record is available |
| `failure` | string | Text describing the scan failure | omitted |

The values of `role` are as follows.

| Value | Meaning |
| --- | --- |
| `baseline` | Baseline scan |
| `candidate` | Scan of the candidate being compared |

The values of `db` are as follows.

| Value | Meaning |
| --- | --- |
| `verified` | The databases after the scan matched the prepared databases |
| `changed` | The databases after the scan differed from the prepared databases |
| `check_failed` | The databases could not be checked |
| `supplied_by_caller` | Used a scan supplied during planning and the conditions supplied with it |
| `not_checked` | The databases were not checked because the scan failed |

The following fields have additional notes.

- `requested`, `confirmed`
    - Use the same identity string with a digest kind as `content` in [Image information](#remediation-image-state)
    - Normal scan processing emits `unconfirmed` when the target could not be identified
    - If no string is set in the record, an empty string is emitted rather than omitting the key
- `db`
    - See [Comparison scan conditions](#remediation-conditions) for database update times and hashes
- `scanned_at`
    - Present for scans performed during planning, and omitted when a supplied scan was used as is

Scan IDs are not emitted in the webhook.

### Newer series check results {#remediation-newer-series}

Newer series check results are used in `items[].newer_series`, `dockerfile_items[].newer_series`, and `dockerfile_items[].entities[].newer_series`.
See [Newer series check](remediation-logic.md#newer-series-check) for candidate selection and [Newer series status values](remediation-reference.md#newer-series-status-values) for the meanings of statuses.

The following example extracts a newer series candidate and its counts.

```json
{
  "status": "resolves",
  "shown": "2.0.1",
  "candidates": [
    {
      "tag": "2.0.1",
      "change": "major",
      "status": "resolves",
      "counts": {
        "targets": 2,
        "resolved": 2,
        "remaining": 0,
        "unknown": 0,
        "undetected": 0,
        "introduced": 0,
        "introduced_kev": 0
      }
    }
  ]
}
```

`items[].newer_series` and other newer series check result objects have the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `status` | string | Status of the newer series check result | — |
| `shown` | string | Candidate tag shown as the item's check result | omitted |
| `reason` | string | [Reason codes](remediation-reference.md#reason-codes) value explaining why the check could not be completed or another outcome | omitted |
| `detail` | string | Additional explanation of the reason | omitted |
| `candidates` | array of objects | Results in the order candidates were checked | omitted when empty |

See [Newer series status values](remediation-reference.md#newer-series-status-values) for the values of `status`.
`shown` is omitted when no candidate resolves any target findings.

`items[].newer_series.candidates[]` and other newer series candidate arrays have the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `tag` | string | Candidate tag to check | — |
| `change` | string | Kind of series change relative to the current tag | — |
| `status` | string | Status of the candidate check result | — |
| `reason` | string | [Reason codes](remediation-reference.md#reason-codes) value explaining the candidate's result | omitted |
| `detail` | string | Additional explanation of the reason | omitted |
| `candidate` | object | Candidate [Image information](#remediation-image-state) | omitted when information is unavailable |
| `counts` | object | Counts of target resolution outcomes and newly detected findings | omitted when counts cannot be calculated |
| `comparison` | object | Candidate [Comparison results](#remediation-comparison) | omitted when no result is available |
| `scans` | array of objects | [Scan records](#remediation-scan-records) used for the comparison | omitted when empty |

A candidate's `status` uses [Newer series status values](remediation-reference.md#newer-series-status-values), excluding `no_newer_series`.

The values of `change` are as follows.

| Value | Meaning |
| --- | --- |
| `minor` | A newer minor series within the same major version |
| `major` | A newer major series |

`items[].newer_series.candidates[].counts` and other newer series count objects have the following fields.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `targets` | integer | Number of target findings evaluated | `0` |
| `resolved` | integer | Number of resolved target findings | `0` |
| `remaining` | integer | Number of target findings remaining in the candidate | `0` |
| `unknown` | integer | Number of target findings that could not be judged | `0` |
| `undetected` | integer | Number of target findings not detected in the baseline | `0` |
| `introduced` | integer | Number of findings newly detected in the candidate | `0` |
| `introduced_kev` | integer | Number of KEV-listed vulnerability IDs among newly detected findings | `0` |

The following fields have additional notes.

- `comparison`
    - For candidates in `items[].newer_series` and `dockerfile_items[].entities[].newer_series`, `verdicts[]` contains only target findings
    - `decision` is omitted for newer series candidates
    - `verdicts[]` and `introduced_findings[]` are each limited to 50 entries
- `counts`
    - If candidate retrieval fails or processing stops before comparison, for example, the object itself is omitted rather than setting every field to `0`
    - `introduced_kev` counts distinct vulnerability IDs
- `dockerfile_items[].newer_series`
    - Represents the result across all running images belonging to the base image item
    - `candidates[]` does not include `comparison` or `scans`
    - A candidate's `candidate` object contains the `ref`, `tag`, and `top_digest` that were obtained
    - The candidate's `counts` is omitted if any running image is unchecked or the same candidate tag points to different content across running images
    - Findings are deduplicated by vulnerability ID and package pair, and counted as `resolved` only when resolved in every running image that has the finding

If a newer series candidate tag points to the same content as the current image, no scan is performed for that candidate.
For published image candidates and base image candidates for individual running images, `status` is `not_resolving` and `reason` is `same_content`.

In that case, `comparison` has `comparable` set to `true` and each target's `outcome` set to `remaining`.
In both `counts` and `comparison`, `remaining` equals `targets`, while the resolved, unknown, undetected, and introduced counts are `0`.

`scope` contains `the candidate is the content already in use; nothing was scanned`.

Changes only to timestamps or `detail` in newer series results do not by themselves cause webhook redelivery.
The emitted JSON still includes `detail` and `scans[].scanned_at` according to the conditions in the tables above.

See [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) for details.

### Services {#remediation-services}

Service information is used in `items[].services[]`, `dockerfile_items[].entities[].services[]`, and `pull_requests[].also_running[]`.

`items[].services[]` and other service arrays have the following fields in each element.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `project` | string | Docker Compose project name | omitted |
| `service` | string | Docker Compose service name | omitted |
| `container` | string | Docker container name | omitted |
| `workload` | string | Kubernetes workload key | omitted |

The following fields have additional notes.

- `project`, `service`, `container`
    - Docker Compose emits the project name, service name, and container name
    - For Docker containers that do not belong to Compose, `container` is emitted
- `workload`
    - Kubernetes emits only this field, omitting `project`, `service`, and `container`
    - Replicas of the same workload are not split into separate service information entries by Pod name
    - See [Image name updates](webhook-diff-reference.md#reference-change-fields) for the string format

The following is service information for Docker Compose.

```json
{
  "project": "shop",
  "service": "web",
  "container": "shop-web-1"
}
```
