---
title: Webhook diff fields
---

# Webhook diff fields

This page describes the fields in `diff` in the generic webhook payload.
See [Payload overview](webhook-reference.md#payload-overview) for the overall payload structure and [Report fields](webhook-reference.md#report-fields) for table conventions and values shared by several fields.

`diff` is included only in diff mode and describes changes between saved history and the latest scan, grouped by type.

The following `diff` example includes a priority escalation, a fix becoming available, and a package resolution.

```json
{
  "new": [
    {
      "image": "web:1.0",
      "package": "openssl",
      "kind": "escalated",
      "critical": 1,
      "high": 1,
      "priority": "act_now",
      "reason": "CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign",
      "ecosystems": [""]
    },
    {
      "image": "web:1.0",
      "package": "dpkg",
      "kind": "now_fixable",
      "critical": 0,
      "high": 1,
      "priority": "low",
      "ecosystems": [""]
    }
  ],
  "resolved": [
    {
      "image": "web:1.0",
      "package": "old-pkg"
    }
  ],
  "replaced": [],
  "new_eosl": [],
  "resolved_eosl": [],
  "oldest_open_days": 20,
  "new_eol_packages": [],
  "resolved_eol_packages": []
}
```

See [Change and history decisions](diff-logic.md#comparison-baseline) for the conditions used to identify changes.

## Diff object {#diff-fields}

The fields in `diff` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `new` | array of objects | [Ordinary package changes](#new-fields). | `[]` |
| `resolved` | array of objects | [Package resolutions](#resolved-fields). | `[]` |
| `replaced` | array of objects | [Image digest changes](#image-replacement-fields). | `[]` |
| `reference_changes` | array of objects | [Image name updates](#reference-change-fields). | omitted when none apply |
| `new_eosl` | array of strings | [Images whose base OS is newly recorded as EOL](#eol-base-fields). | `[]` |
| `resolved_eosl` | array of strings | [Images whose base OS is no longer recorded as EOL](#eol-base-fields). | `[]` |
| `new_eol_packages` | array of objects | [EOL package changes](#eol-change-fields). | `[]` |
| `resolved_eol_packages` | array of objects | [EOL package clearances](#eol-resolved-fields). | `[]` |
| `oldest_open_days` | integer | [Oldest unresolved age](#oldest-open-days). | `0` |

## Ordinary package changes {#new-fields}

`diff.new[]` describes changes to [ordinary findings](scan-logic.md#eol-package).
Each element represents an image name and package name combination, combining multiple [package groups](scan-logic.md#package-grouping) when present.

Counts from `critical` through `unknown` describe the package in the latest scan and sum the combined package groups.
They are not limited to newly added CVEs.

The fields in each element of `diff.new[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name. | — |
| `package` | string | Package name. | — |
| `kind` | string | Type of change. | — |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystem types of the package groups. | — |
| `runtime_usage` | string | [Usage](webhook-reference.md#usage-values) across the combined package groups. | omitted when runtime usage is disabled |
| `muted` | boolean | Indicates that all combined package groups are [muted](runtime-usage.md#muting-findings-without-a-fix). | omitted unless all combined groups are muted |
| `new_cve_count` | integer | Number of added CVEs. | omitted when `kind` is not `new_cves` |
| `new_cve_ids` | array of strings | Sorted list of added CVE IDs. | omitted when `kind` is not `new_cves` |
| `critical` | integer | CRITICAL count. | `0` |
| `high` | integer | HIGH count. | `0` |
| `medium` | integer | MEDIUM count. | omitted when the count is 0 |
| `low` | integer | LOW count. | omitted when the count is 0 |
| `unknown` | integer | UNKNOWN count, including unrecognized severities. | omitted when the count is 0 |
| `priority` | string | Highest [priority](webhook-reference.md#priority-values) among the combined package groups. | omitted when triage is disabled |
| `reason` | string | Evidence for a priority escalation or the reason notifications resumed. | omitted when `kind` is neither `escalated` nor `unmuted` |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `new` | A finding for a combination absent from saved history. |
| `escalated` | The priority of a known package increased. |
| `new_cves` | CVEs were added to a known package. |
| `now_fixable` | A fix became available for a package that had no fix. |
| `unmuted` | The package no longer meets the [muting conditions](runtime-usage.md#muting-findings-without-a-fix), so notifications resumed. |

The following fields have additional notes.

- `ecosystems`
    - Includes `""` for unrecognized types
- `runtime_usage`
    - When the combined package groups have different assessments, the first assessment present in the order `in_use`, `unavailable`, `not_observed` is used
- `new_cve_ids`
    - Its length matches `new_cve_count`
- `reason`
    - Explanatory text in English regardless of the notification language setting, not a fixed value
    - An example for `escalated` is `CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign`
    - An example for `unmuted` is `now in use`

The following example describes a package with one added CVE and two HIGH findings in the latest scan.

```json
{
  "image": "api:2.0",
  "package": "libxml2",
  "kind": "new_cves",
  "new_cve_count": 1,
  "new_cve_ids": ["CVE-2031-0007"],
  "critical": 0,
  "high": 2,
  "priority": "act_now",
  "ecosystems": [""]
}
```

See [Ordinary package changes](diff-logic.md#normal-changes) for the order used when several changes apply.

## Package resolutions {#resolved-fields}

`diff.resolved[]` identifies image name and package name combinations whose ordinary findings disappeared and were judged resolved.
It excludes ordinary findings that moved to EOL findings.

The fields in each element of `diff.resolved[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name. | — |
| `package` | string | Name of the resolved package. | — |

See [Package EOL](scan-logic.md#eol-package) for the distinction between ordinary findings and EOL findings.
See [Resolution decisions](diff-logic.md#resolved-findings) for what resolution means.

## Image digest changes {#image-replacement-fields}

`diff.replaced[]` is populated when the running image's content changes under the same image name.
The fields in each element are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `ref` | string | Image name. | — |
| `prev_content_ids` | array of strings | Sorted content identifiers verified in saved history. | — |
| `content_ids` | array of strings | Sorted content identifiers verified at the latest scan. | — |

The following fields have additional notes.

- `prev_content_ids` and `content_ids`
    - Elements identify the image's content (config digest) and have the same format as an image's [`content_id`](webhook-reference.md#image-identity)
    - Each array contains at least one element

See [Image digest changes](diff-logic.md#image-content-changes) for the conditions used to identify a change.

## Image name updates {#reference-change-fields}

`diff.reference_changes[]` is populated when the same workload moves to an image with another tag or digest in the same repository and carries its findings history over.
The fields in each element are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `repository` | string | Repository from the new image name with its tag and digest removed. | — |
| `previous_ref` | string | Previous image name, including its tag or digest. | — |
| `ref` | string | New image name, including its tag or digest. | — |
| `workloads` | array of strings | Sorted workload keys shared by the previous and new image names. | — |

The following fields have additional notes.

- `repository`
    - Preserves any registry port specified in the image name
- `workloads`
    - Contains at least one element

Workload key formats are listed below.

| Target | Workload key format |
| --- | --- |
| Compose | `compose/<project>/<service>` |
| Kubernetes | `<kind>/<namespace>/<name>/<container>` |
| Docker container with no known workload | `container/<name>` |
| Kubernetes container with no known workload | `container/<namespace>/<pod>/<container>` |

The components of these formats have the following meanings.

- `<project>` is the Compose project name
- `<service>` is the Compose service name
- `<kind>` matches `containers[].workload.kind`
- `<namespace>` is the namespace
- `<name>`
    - The workload name in the Kubernetes format
    - The value of `containers[].name` in the format for a Docker container with no known workload
- `<pod>` is the Pod name
- `<container>` is the container name within the Pod

The following example shows an image name update for the Compose service `shop/web` that carried its findings history over.

```json
{
  "repository": "ghcr.io/acme/web",
  "previous_ref": "ghcr.io/acme/web:sha-aaaa",
  "ref": "ghcr.io/acme/web:sha-bbbb",
  "workloads": ["compose/shop/web"]
}
```

See [Image name updates](diff-logic.md#reference-changes) for conditions for carrying history over.

## Base OS EOL changes {#eol-base-fields}

`diff.new_eosl` and `diff.resolved_eosl` are arrays of image names whose base OS EOL records changed.
The elements of these arrays are described below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `diff.new_eosl[]` | string | Image name whose base OS is newly recorded as EOL. | — |
| `diff.resolved_eosl[]` | string | Image name whose base OS is no longer recorded as EOL. | — |

## EOL package changes {#eol-change-fields}

`diff.new_eol_packages[]` lists packages with newly detected or changed [EOL findings](scan-logic.md#eol-package).
Each element represents an image name and package name combination.

When an image's base OS is EOL, Slack does not display that image's EOL packages individually in its EOL section, but the webhook includes them.

Counts from `critical` through `unknown` describe the package's [EOL findings](scan-logic.md#eol-package) in the latest scan.
Counts are summed when multiple package groups apply.

The fields in each element of `diff.new_eol_packages[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name. | — |
| `package` | string | Package name. | — |
| `kind` | string | Type of EOL change. | — |
| `ecosystems` | array of strings | Sorted, deduplicated ecosystem types of the package groups. | — |
| `runtime_usage` | string | [Usage](webhook-reference.md#usage-values) across the combined package groups. | omitted when runtime usage is disabled |
| `new_cve_ids` | array of strings | Sorted list of added EOL CVE IDs. | omitted when `kind` is not `eol_new_cves` |
| `critical` | integer | CRITICAL count. | `0` |
| `high` | integer | HIGH count. | `0` |
| `medium` | integer | MEDIUM count. | omitted when the count is 0 |
| `low` | integer | LOW count. | omitted when the count is 0 |
| `unknown` | integer | UNKNOWN count, including unrecognized severities. | omitted when the count is 0 |
| `priority` | string | Highest [priority](webhook-reference.md#priority-values) among the combined package groups. | omitted when triage is disabled |
| `reason` | string | Explanatory text giving evidence for a priority escalation. | omitted when `kind` is not `eol_escalated` |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `eol_new` | Newly detected EOL findings. |
| `eol_new_cves` | CVEs were added to a known EOL package. |
| `eol_escalated` | An EOL package's priority increased to `act_now`. |

The following fields have additional notes.

- `ecosystems`
    - Includes `""` for unrecognized types
- `runtime_usage`
    - Uses the same selection rule as [ordinary package changes](#new-fields)
- `new_cve_ids`
    - Use its length for the added count because no `new_cve_count` field is output
- `reason`
    - Explanatory text in English regardless of the notification language setting, not a fixed value

The following example shows one CVE added to an EOL package.

```json
{
  "image": "legacy:1",
  "package": "zlib",
  "kind": "eol_new_cves",
  "new_cve_ids": ["CVE-2033-0007"],
  "critical": 1,
  "high": 1,
  "priority": "act_now",
  "ecosystems": [""]
}
```

See [EOL package changes](diff-logic.md#eol-package-changes) for the conditions used to identify changes.

## EOL package clearances {#eol-resolved-fields}

`diff.resolved_eol_packages[]` identifies image name and package name combinations whose [EOL findings](scan-logic.md#eol-package) disappeared.
The fields in each element are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name. | — |
| `package` | string | Name of the package whose EOL findings disappeared. | — |
| `still_open` | boolean | Whether ordinary findings remain. | `false` |

When `still_open` is `true`, [ordinary findings](scan-logic.md#eol-package) remain for the same package under the same image name.

The following example shows EOL findings that disappeared while ordinary findings remain.

```json
{
  "image": "app:2.1",
  "package": "sqlite-libs",
  "still_open": true
}
```

## Oldest unresolved age {#oldest-open-days}

`diff.oldest_open_days` is the number of days from the earliest first-seen date among eligible records to `generated_at`.
Fractional days are rounded down, and the value is `0` when no records qualify.

The records compared and the dates used are listed below.
See [Priority values](webhook-reference.md#priority-values) for the meaning of `act_now`.

| Target | Condition | Date compared |
| --- | --- | --- |
| [Ordinary findings](scan-logic.md#eol-package) | Includes `low`, [muted findings](runtime-usage.md#muting-findings-without-a-fix), and [retained records](diff-logic.md#retained-findings). | Date the ordinary findings were first detected. |
| Base OS EOL | The base OS is recorded as EOL. | Date the base OS was first detected as EOL. |
| [EOL findings](scan-logic.md#eol-package) | The image's base OS is not EOL. | Date the package was first detected as EOL. |
| EOL findings | The image's base OS is EOL and the package's priority is `act_now`. | Date the package was first detected as EOL. |
| EOL findings | The image's base OS is EOL and the package's priority is not `act_now`. | Exclude the package's first-seen-as-EOL date from the comparison and use the base OS's first-seen-as-EOL date. |

The scope differs from the age shown in Slack when triage is enabled.
See [Unresolved age](slack-display.md#unresolved-age) for the Slack definition.
