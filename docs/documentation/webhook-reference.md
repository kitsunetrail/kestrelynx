---
title: Webhook base fields
---

# Webhook base fields

## Payload scope {#generic-webhook}

The generic webhook sends current scan results as JSON.
In `diff` mode, it also includes changes found by comparing stored history with the latest scan.

The payload also includes items that Slack does not display individually.

- [Package groups](scan-logic.md#package-grouping) with priority `low`
- [Muted](runtime-usage.md#muting-findings-without-a-fix) package groups
- EOL packages even when the image's base OS is EOL
- Containers and workloads using the image

The webhook can be used alongside Slack, but does not convert the payload into Discord- or Teams-specific message formats.

Delivery works as follows.

| Item | Behavior |
| --- | --- |
| HTTP method | `POST` |
| Content-Type | `application/json` |
| Authentication | A Basic authentication `Authorization` header is added when the destination URL contains a user name, with or without a password, and no signature is added |
| Response handling | HTTP status `2xx` means success; other statuses mean failure |
| Response timeout | 15 seconds |
| Retry after failure | No immediate retry; subsequent attempts follow [Scan notification redelivery](notification-conditions.md#scan-redelivery) |

See the following pages for configuration, notification conditions, and field details.

| Contents | Page |
| --- | --- |
| Destinations | [Configuration](configuration.md) |
| Delivery timing | [Notification conditions](notification-conditions.md#notification-conditions) |
| Fields in `diff` | [Webhook diff fields](webhook-diff-reference.md) |
| Fields in the top-level `runtime` and `findings[].runtime` | [Webhook runtime fields](webhook-runtime-reference.md) |
| Fields in `remediation` | [Webhook remediation overview and shared objects](webhook-remediation-reference.md) |

## Payload overview {#payload-overview}

The payload contains information about the report as a whole and findings for each image.
The following tree shows the main nested objects, including fields that may be omitted.

```text
Payload
├── generated_at
├── environment
├── summary
├── eosl_images[]
├── actionable[], watch[], wont_fix[], eol_packages[]   Image
│   ├── containers[]                                   Container
│   │   └── workload
│   └── findings[]                                     Package group
│       ├── vulns[]                                    Vulnerability
│       │   └── refs[]
│       └── runtime
│           └── containers[]
│               ├── process
│               └── instances[]
├── scan_errors[]
├── runtime_unchecked[]
├── diff
├── runtime
└── remediation
```

`actionable`, `watch`, `wont_fix`, and `eol_packages` are image arrays whose elements share the same structure.
The same image can appear in more than one array.

The following `diff` mode payload contains one package group for `web:1.0` and a scan failure for `broken:1`.

```json
{
  "generated_at": "2026-06-24T09:00:00Z",
  "environment": {
    "kind": "docker"
  },
  "summary": {
    "images_total": 2,
    "images_affected": 1,
    "priority_counts": {
      "act_now": 1,
      "low": 0,
      "watch": 0
    },
    "intel": {
      "degraded": false,
      "kev_ok": true,
      "epss_ok": true,
      "stale_days": 0
    }
  },
  "eosl_images": null,
  "actionable": [
    {
      "image": "web:1.0",
      "severity_counts": {
        "CRITICAL": 1,
        "HIGH": 0
      },
      "findings": [
        {
          "package": "openssl",
          "installed": "3.0.7",
          "fixed": "3.0.11",
          "status": "fixed",
          "severity_counts": {
            "CRITICAL": 1,
            "HIGH": 0
          },
          "upgrade_risk": "distro_update",
          "priority": "act_now",
          "vuln_ids": [
            "CVE-2031-0001"
          ],
          "vulns": [
            {
              "id": "CVE-2031-0001",
              "severity": "CRITICAL",
              "url": "https://avd.example/CVE-2031-0001",
              "title": "openssl: buffer overread",
              "kev": true,
              "ransomware": true,
              "epss": 0.94321,
              "priority": "act_now",
              "refs": [
                {
                  "kind": "vendor",
                  "label": "vendor advisory",
                  "url": "https://vendor.example/advisory/1"
                }
              ]
            }
          ],
          "class": "os",
          "ecosystem": ""
        }
      ],
      "containers": [],
      "content_id": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "registry_digests": [],
      "identity_resolved": true,
      "scan_target_kind": "content_id"
    }
  ],
  "watch": [],
  "wont_fix": [],
  "eol_packages": [],
  "scan_errors": [
    {
      "image": "broken:1",
      "error": "pull failed",
      "cause": "unclassified"
    }
  ],
  "diff": {
    "new": [
      {
        "image": "web:1.0",
        "package": "openssl",
        "kind": "escalated",
        "critical": 1,
        "high": 0,
        "priority": "act_now",
        "reason": "CVE-2031-0001 CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign",
        "ecosystems": [
          ""
        ]
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
}
```

## Report fields {#report-fields}

Field names in each table are relative to the object named before the table.
`a.b` means `b` inside `a`, and `a[]` means each element of array `a`.

Read the entries in “When there is no value” as follows.

| Notation | Meaning |
| --- | --- |
| omitted | The key is absent when the value is missing, nothing applies, or the value cannot be obtained |
| omitted when … | The key is absent when the stated condition applies |
| `[]`, `null`, `""`, `0`, `false` | The indicated value is emitted |
| — | A value is always present when the object described by the table exists |

### Values used by several fields {#common-values}

This section describes priorities, fix statuses, severity counts, and usage values shared by several fields.

#### Priorities {#priority-values}

Vulnerabilities and [package groups](scan-logic.md#package-grouping) use the following priority values.

| Value | Meaning |
| --- | --- |
| `act_now` | Take action now |
| `watch` | Continue monitoring without immediate urgency |
| `low` | Address in batches as a low priority |

See [Exploitation-based triage](scan-logic.md#triage) for the assessment rules.

#### Fix statuses {#status-values}

[Package groups](scan-logic.md#package-grouping) use the following [fix status](scan-logic.md#status) values.

| Value | Meaning |
| --- | --- |
| `fixed` | A fix is available |
| `affected` | Affected, with no fix available |
| `will_not_fix` | No fix is currently planned for the target platform |
| `end_of_life` | Outside the supported scope |

`affected` also includes Trivy statuses such as `fix_deferred`, `under_investigation`, and `unknown`.

#### Severity counts {#severity-count-fields}

The following fields describe `severity_counts` in images and package groups.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `CRITICAL` | integer | Number of CVEs with severity `CRITICAL` | `0` |
| `HIGH` | integer | Number of CVEs with severity `HIGH` | `0` |
| `MEDIUM` | integer | Number of CVEs with severity `MEDIUM` | omitted when the count is 0 |
| `LOW` | integer | Number of CVEs with severity `LOW` | omitted when the count is 0 |
| `UNKNOWN` | integer | Number of CVEs with unknown or unrecognized severity | omitted when the count is 0 |

The following fields have additional notes.

- `MEDIUM`, `LOW`, and `UNKNOWN`
    - Severities selected by `scan.severity` are included in detection
    - The default `[HIGH, CRITICAL]` excludes these severities from detection
    - The received JSON alone cannot distinguish an excluded severity from a zero count

#### Usage {#usage-values}

The following values describe [runtime usage](runtime-usage.md).

| Value | Meaning |
| --- | --- |
| `in_use` | Use was confirmed according to the assessment rules |
| `not_observed` | Use was not confirmed during the observation period |
| `unavailable` | Insufficient evidence to assess usage |

`not_observed` does not mean that the package is unused.

### Top level {#top-level}

The top level contains report information, findings, scan failures, changes, and related data.

`actionable`, `watch`, `wont_fix`, and `eol_packages` organize findings by [fix status](scan-logic.md#status).
`watch` contains results grouped under fix status `affected`, separate from the `watch` [priority](#priority-values).

Findings with status `not_affected` are excluded from all four arrays.

The top-level fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `generated_at` | string | Time the report was assembled, in RFC 3339 format | — |
| `environment` | object | [Environment](#environment) | — |
| `summary` | object | [Summary](#summary) | — |
| `eosl_images` | array of strings or `null` | Names of images whose base OS is EOL | `null` |
| `actionable` | array of objects | [Images](#images) with package groups whose fix status is `fixed` | `[]` |
| `watch` | array of objects | Images with package groups whose fix status is `affected` | `[]` |
| `wont_fix` | array of objects | Images with package groups whose fix status is `will_not_fix` | `[]` |
| `eol_packages` | array of objects | Images with package groups whose fix status is `end_of_life` | `[]` |
| `scan_errors` | array of objects | List of [scan failures](#scan-errors) | `[]` |
| `runtime_unchecked` | array of objects | List of [unchecked language runtimes](#runtime-unchecked) | omitted |
| `diff` | object | [Changes](webhook-diff-reference.md) | omitted in `full` mode |
| `runtime` | object | [Sensor information and usage counts](webhook-runtime-reference.md) | omitted when runtime usage is disabled |
| `remediation` | object | [Remediation plans and PR processing results](webhook-remediation-reference.md#remediation-fields) | omitted when remediation planning is disabled |

See [Payload overview](#payload-overview) for a complete JSON example.

### Environment {#environment}

`environment` identifies the runtime environment that was scanned.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Runtime environment type | — |
| `name` | string | Environment name specified by `environment.name` in [Configuration](configuration.md) | omitted when unset |

`kind` uses the following values.

| Value | Meaning |
| --- | --- |
| `docker` | Docker Engine host |
| `kubernetes` | Kubernetes cluster |

### Summary {#summary}

`summary` describes the counts of scanned targets and affected images, counts by priority, and threat intelligence availability.

The fields in `summary` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `images_total` | integer | Number of scanned targets, counting different digests of the same image name separately and including failed scans | `0` |
| `images_affected` | integer | Number of image names present in any of the four finding arrays or whose base OS is EOL | `0` |
| `priority_counts` | object | [Package-group](scan-logic.md#package-grouping) counts by [priority](#priority-values) | omitted when triage is disabled |
| `priority_counts.act_now` | integer | Count with priority `act_now` | `0` |
| `priority_counts.watch` | integer | Count with priority `watch` | `0` |
| `priority_counts.low` | integer | Count with priority `low` | `0` |
| `intel` | object | KEV and EPSS availability and data age | omitted when triage is disabled |
| `intel.degraded` | boolean | Whether neither KEV nor EPSS is available | `false` |
| `intel.kev_ok` | boolean | Whether KEV is available | `false` |
| `intel.epss_ok` | boolean | Whether EPSS is available | `false` |
| `intel.stale_days` | integer | Age in days of the oldest cached dataset in use after a refresh failure, or `0` when using current data | `0` |

`priority_counts` is calculated as follows.

- The counting unit is a [package group](scan-logic.md#package-grouping)
- EOL packages are counted only when their priority is `act_now`
- Because only some EOL packages qualify, the three counts do not necessarily sum to the number of package groups in the four arrays
- [Muted](runtime-usage.md#muting-findings-without-a-fix) package groups are also counted

The following `summary` example has triage enabled.

```json
{
  "images_total": 3,
  "images_affected": 2,
  "priority_counts": {
    "act_now": 3,
    "low": 4,
    "watch": 1
  },
  "intel": {
    "degraded": false,
    "kev_ok": true,
    "epss_ok": true,
    "stale_days": 0
  }
}
```

### Unchecked language runtimes {#runtime-unchecked}

`runtime_unchecked` lists targets where the Node.js or Python runtime itself was found but could not be checked because advisory data was unavailable.
Each combination of image name and runtime is included only once.

The fields in `runtime_unchecked[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name whose runtime was not checked | — |
| `package` | string | Package name of the runtime that was not checked | — |

`package` uses the following values.

| Value | Meaning |
| --- | --- |
| `Node.js` | The Node.js runtime itself |
| `Python runtime` | The Python runtime itself |

See [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable) for notification and history handling.

### Scan failures {#scan-errors}

`scan_errors` identifies targets whose scans failed and the associated errors.
The fields in `scan_errors[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name whose scan failed | — |
| `error` | string | Error text returned by Trivy or another component | — |
| `cause` | string | Cause of the scan failure | — |
| `registry` | string | Registry host from which the image is fetched | omitted |

`cause` uses the following values.

| Value | Meaning |
| --- | --- |
| `local_registry` | Images in the local registry cannot be fetched by KestreLynx |
| `registry_auth` | No valid login for the registry, so the images cannot be fetched |
| `image_not_found` | The images cannot be found in the registry |
| `registry_rate_limited` | The registry's request limit prevents the images from being fetched |
| `registry_unreachable` | The registry cannot be reached, so the images cannot be fetched |
| `vulnerability_db` | The vulnerability database cannot be retrieved |
| `image_mismatch` | The image scanned does not match the one running |
| `unclassified` | The cause cannot be classified |

The text in `error` does not come from a fixed set of values.

See [Images that could not be scanned](slack-warnings-display.md#scan-failure-causes) for the displays and conditions corresponding to `cause` values.

See [Handling scan failures](scan-logic.md#scan-failures) for how results are handled after a failure.

## Image fields {#images}

Each element of `actionable`, `watch`, `wont_fix`, or `eol_packages` corresponds to an image name paired with a value identifying the running image's contents, and contains the [package groups](#findings) belonging to the array's [fix status](scan-logic.md#status).

When a registry digest identifies the image, the platform is also included, so the same image name and digest produce separate elements for different platforms.

Images without a value identifying their contents are also included when they have applicable package groups, grouped into one element per image name in each array.

If an image has package groups with different fix statuses, elements with the same `image` appear in multiple arrays.

The following example shows one image element in `actionable`.

```json
{
  "image": "api:2.0",
  "severity_counts": {
    "CRITICAL": 0,
    "HIGH": 1
  },
  "findings": [
    {
      "package": "setuptools",
      "installed": "53.0.0",
      "fixed": "78.1.1",
      "status": "fixed",
      "severity_counts": {
        "CRITICAL": 0,
        "HIGH": 1
      },
      "upgrade_risk": "caution",
      "priority": "low",
      "vuln_ids": [
        "CVE-2031-0008"
      ],
      "vulns": [
        {
          "id": "CVE-2031-0008",
          "severity": "HIGH",
          "kev": false,
          "epss": null,
          "priority": "low"
        }
      ],
      "class": "lang",
      "ecosystem": "python-pkg"
    }
  ],
  "containers": [],
  "content_id": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "registry_digests": [],
  "identity_resolved": true,
  "scan_target_kind": "content_id"
}
```

### Image elements {#image-identity}

The fields of an image element are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `image` | string | Image name. | — |
| `severity_counts` | object | Sum of CVE counts from each package group in this element, [grouped by severity](#severity-count-fields). | — |
| `findings` | array of objects | [Package groups](#findings) belonging to this element. | `[]` |
| `containers` | array of objects | [Containers](#containers) associated with this element. | `[]` |
| `content_id` | string | Value identifying the image's contents (config digest). | omitted when `scan_target_kind` is not `content_id` |
| `registry_digests` | array of strings | Registry digests collected for the same image name. | `[]` |
| `identity_resolved` | boolean | Whether the scan target was verified to have the same contents as the running image. | `false` |
| `scan_target_kind` | string | How the scan target was specified. | — |

The values of `scan_target_kind` are listed below.

| Value | Meaning |
| --- | --- |
| `content_id` | Scanned using the running image's config digest (Docker). |
| `registry_digest` | Scanned using the running image's registry digest (Kubernetes). |
| `reference` | Scanned by image name, without verifying that its contents match the running image. |

The following fields have additional notes.

- `identity_resolved`
    - `true` when `scan_target_kind` is not `reference`
- `content_id`
    - Uses the format `sha256:<64 lowercase hexadecimal characters>`
- `registry_digests`
    - Collects digests from successful scans with verified digests for the same image name, covering more than this element alone
    - Each element includes a repository name, for example `debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`
- `image`
    - Matches the diff's `image` or `ref` when they refer to the same image name, so it can be used to correlate entries by image name
- `containers`
    - For Kubernetes, `content_id` is omitted and `registry_digests` is shared across elements with the same image name, so digests cannot distinguish those elements
    - When Kubernetes has multiple elements with the same image name, distinguish them using `containers`, which lists the containers associated with each element

### Containers {#containers}

`containers[]` describes containers running the image.
Even when an image name has multiple digests, each image element includes only containers whose digest matches that element.

An element whose digest could not be verified includes containers with the same image name whose digest could not be verified.

The fields of one `containers[]` element are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Container name. | `""` |
| `workload` | object | [Workload](#workloads) to which the container belongs. | — |

The format of `name` depends on the runtime environment.

| Runtime environment | Format of `name` |
| --- | --- |
| Docker | Container name without the leading slash. |
| Kubernetes | `<namespace>/<pod>/<container>` |

The following example shows a container whose workload association is unknown.

```json
{
  "name": "web-1",
  "workload": {
    "kind": "unknown"
  }
}
```

### Workloads {#workloads}

`containers[].workload` describes the service or Kubernetes resource to which a container belongs.
Its fields are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Workload type. | — |
| `group` | string | Project or namespace containing the workload. | omitted |
| `name` | string | Workload name. | omitted |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `compose` | Docker Compose service. |
| `deployment` | Kubernetes Deployment. |
| `statefulset` | Kubernetes StatefulSet. |
| `daemonset` | Kubernetes DaemonSet. |
| `job` | Kubernetes Job not owned by a CronJob. |
| `cronjob` | Kubernetes CronJob. |
| `pod` | Kubernetes Pod not owned by another resource. |
| `unknown` | Container with an unknown workload association, such as a standalone Docker container. |

The values of `group` and `name` depend on the runtime environment.

| Runtime environment | `group` | `name` |
| --- | --- | --- |
| Docker Compose | Project name. | Service name. |
| Kubernetes | Namespace. | Resource name. |

## Finding fields {#findings}

Each element of `findings[]` is called a package group.
It combines CVEs found in the same package of the same image by [fix status](scan-logic.md#status) (see [Package grouping](scan-logic.md#package-grouping)).

The package group's `vulns[]` contains one detailed record for each vulnerability in the group.

The following example shows one package group for `openssl`.

```json
{
  "package": "openssl",
  "installed": "3.0.7",
  "fixed": "3.0.11",
  "status": "fixed",
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 0
  },
  "upgrade_risk": "distro_update",
  "priority": "act_now",
  "vuln_ids": [
    "CVE-2031-0001"
  ],
  "vulns": [
    {
      "id": "CVE-2031-0001",
      "severity": "CRITICAL",
      "url": "https://avd.example/CVE-2031-0001",
      "title": "openssl: buffer overread",
      "kev": true,
      "ransomware": true,
      "epss": 0.94321,
      "priority": "act_now",
      "refs": [
        {
          "kind": "vendor",
          "label": "vendor advisory",
          "url": "https://vendor.example/advisory/1"
        }
      ]
    }
  ],
  "class": "os",
  "ecosystem": ""
}
```

### Packages {#package-fields}

The fields of one `findings[]` element, representing a package group, are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Package name. | `""` |
| `class` | string | Package classification. | — |
| `ecosystem` | string | Package type. | `""` |
| `installed` | string | Installed version. | `""` |
| `fixed` | string | Fixed version. | `""` |
| `status` | string | Package group's [fix status](#status-values). | — |
| `severity_counts` | object | This package group's [counts by severity](#severity-count-fields). | — |
| `upgrade_risk` | string | Caution level for updating to the fixed version. | `""` |
| `priority` | string | [Response priority](#priority-values) for the package group. | omitted when triage is disabled |
| `vuln_ids` | array of strings | IDs of vulnerabilities in the group. | `[]` |
| `vulns` | array of objects | [Details for each vulnerability](#vulnerability-fields). | `[]` |
| `runtime` | object | [Package group usage](webhook-runtime-reference.md#finding-runtime). | omitted when runtime usage is disabled |

The values of `class` are listed below.

| Value | Meaning |
| --- | --- |
| `os` | OS package. |
| `lang` | Language package. |

The values of `upgrade_risk` are listed below.

| Value | Meaning |
| --- | --- |
| `""` | No fix available. |
| `distro_update` | Update to a fixed version of an OS package. |
| `safe` | Language-package update that does not increase the major version, such as a patch or minor update. |
| `caution` | Language-package update that increases the major version. |
| `unknown` | Language-package update whose versions cannot be compared. |

The following fields have additional notes.

- `class`
    - `lang` for findings that KestreLynx adds for the Node.js and Python runtimes themselves
- `ecosystem`
    - Package type reported by Trivy, such as `debian`, `alpine`, `python-pkg`, or `node-pkg`
    - KestreLynx uses `node-runtime` and `python-runtime` for the runtime findings it adds
    - `""` for unrecognized types
- `fixed`
    - Outputs the fixed version from the first finding incorporated when creating the group
    - When CVEs have different fixed versions, this is one of those versions, and the version in `fixed` may not fix every CVE
- `vuln_ids`
    - Contains the same set as `vulns[].id`

See [Upgrade risk](slack-package-display.md#upgrade-risk) for an explanation of update caution levels and [Exploitation-based triage](scan-logic.md#triage) for priority decisions.

### Vulnerabilities {#vulnerability-fields}

Each `vulns[]` element describes one vulnerability in the package group.
Its fields are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `id` | string | Vulnerability ID. | `""` |
| `severity` | string | Vulnerability severity. | `""` |
| `status` | string | [Fix status](scan-logic.md#status) reported by Trivy. | omitted when it matches the package group's `status` |
| `url` | string | Primary advisory URL. | omitted |
| `title` | string | Short vulnerability description. | omitted |
| `kev` | boolean | `true` when the vulnerability is confirmed to be listed in CISA KEV. | `false` |
| `ransomware` | boolean | `true` when KEV reports known use in ransomware campaigns. | omitted when `false` |
| `epss` | number or `null` | EPSS score. | `null` |
| `priority` | string | Response priority for the vulnerability. | omitted when triage is disabled |
| `refs` | array of objects | [Additional references](#reference-fields). | omitted when no references apply |

Common values of `status` are listed below.

| Value | Meaning |
| --- | --- |
| `fix_deferred` | Fix deferred. |
| `under_investigation` | Under investigation. |
| `unknown` | Fix status unknown. |

The following fields have additional notes.

- `status`
    - When omitted, read it as the same value as the package group's `status`
    - Outputs `unknown` if Trivy's fix status is missing or empty
    - Values returned by Trivy that are not listed above may also appear unchanged
- `severity`
    - Contains the value reported by Trivy without modification, such as `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN`
- `kev`
    - Also `false` when triage is disabled or KEV data is unavailable
- `epss`
    - A value from 0 to 1 representing the probability of exploitation

The following example shows one vulnerability with KEV and EPSS information.

```json
{
  "id": "CVE-2031-0001",
  "severity": "CRITICAL",
  "url": "https://avd.example/CVE-2031-0001",
  "title": "openssl: buffer overread",
  "kev": true,
  "ransomware": true,
  "epss": 0.94321,
  "priority": "act_now",
  "refs": [
    {
      "kind": "vendor",
      "label": "vendor advisory",
      "url": "https://vendor.example/advisory/1"
    }
  ]
}
```

See [Priority values](#priority-values) for `priority`.

### Additional references {#reference-fields}

Each `vulns[].refs[]` element describes an additional reference for the vulnerability.
Its fields are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Reference type. | — |
| `label` | string | Label for displaying the reference. | — |
| `url` | string | Reference URL. | — |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `vendor` | Vendor advisory listed in KEV. |
| `discussion` | Hacker News discussion. |

An example of `label` is `vendor advisory`.

## Receiver implementation requirements {#compatibility}

Receiver programs should read the payload according to the following rules.

- Ignore additional fields that are not documented in the webhook field references
- Do not fail the entire operation when a value is absent from the documented value tables
- Treat omission, `null`, `[]`, and `""` as distinct values, following “When there is no value” in each table
