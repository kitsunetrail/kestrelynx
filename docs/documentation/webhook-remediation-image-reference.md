---
title: Webhook remediation published image fields
---

# Webhook remediation published image fields

This page describes published image items and Kubernetes workload information in remediation plans in the generic webhook payload.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall structure.

## Published image fields {#remediation-image-fields}

The published image fields in `remediation` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `summary` | object | [Published image item counts by category](webhook-remediation-reference.md#remediation-summary-keys) | omitted when there is no plan |
| `items` | array of objects | Remediation plans for individual published images | `[]` |

`summary` counts `items[]` by `category`.
When a plan exists, it includes all eight keys, `pull_again`, `pr_candidate`, `manual`, `not_comparable`, `deferred`, `no_candidate`, `excluded`, and `failed`, and outputs `0` for categories with no matching items.

Each element of `items[]` is a remediation plan that groups images with the same running image name and content identity.
Multiple containers or workloads using the same image are grouped in `services[]` within one item.

Content is identified by the config digest when it is known, or otherwise by the registry digest and platform.
Images with the same name but different content identities become separate items, as do images with the same content but different names.

The following example excerpts the main fields from one item with a candidate for re-pulling content under the same tag.

```json
{
  "key": "web:latest|config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "category": "pull_again",
  "reason": "adopted",
  "tag_kind": "floating",
  "priority": "act_now",
  "services": [
    {
      "project": "shop",
      "service": "web",
      "container": "shop-web-1"
    }
  ],
  "current": {
    "ref": "web:latest",
    "tag": "latest",
    "content": "config:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "digest_kind_unverified": true
  },
  "candidate": {
    "ref": "web:latest",
    "tag": "latest",
    "config_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "manifest_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "top_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  },
  "targets": 4,
  "kev_targets": 3
}
```

The fields in each element of `items[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `key` | string | Item identifier formed by joining the running image name and content identity | — |
| `category` | string | [Plan category values](remediation-reference.md#category-values) | — |
| `reason` | string | Code explaining the category or processing result, as defined in [Reason codes](remediation-reference.md#reason-codes) | omitted |
| `detail` | string | Explanatory text supplementing the reason | omitted |
| `tag_kind` | string | Tag classification for the current image name | omitted when not classified |
| `priority` | string | Highest priority among the findings targeted for comparison, using the values in [Priorities](webhook-reference.md#priority-values) | omitted when unavailable |
| `services` | array of objects | [Services](webhook-remediation-reference.md#remediation-services) using this image | omitted |
| `declared` | array of objects | [Declared images and pull policies](#remediation-image-declared) in Kubernetes Pods | omitted |
| `pull` | array of objects | [Re-pull guidance](#remediation-image-pull) grouped by Kubernetes pull policy | omitted |
| `management` | array of objects | [Management chains](#remediation-image-management) for each Kubernetes workload | omitted |
| `current` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the current image | — |
| `candidate` | object | [Image information](webhook-remediation-reference.md#remediation-image-state) for the candidate | omitted when there is no candidate |
| `targets` | integer | Number of findings targeted for comparison | `0` |
| `kev_targets` | integer | Number of comparison targets listed in CISA KEV | omitted when the count is 0 |
| `comparison` | object | [Comparison results](webhook-remediation-reference.md#remediation-comparison) for the current image and candidate | omitted when no result is available |
| `scans` | array of objects | [Scan records](webhook-remediation-reference.md#remediation-scan-records) for the baseline and candidate | omitted when no records are available |
| `newer_series` | object | [Newer series check results](webhook-remediation-reference.md#remediation-newer-series) | omitted when no result is available |

The following fields have additional notes.

- `key`
    - The format is `<image name>|<content identity>`
    - The content identity has the format `config:sha256:<value>` or `registry:sha256:<value>@<OS>/<architecture>`
    - When content cannot be identified, the value is `<image name>|unconfirmed`, grouping containers whose content is unknown under the same image name
    - The platform variant is not included, so `key` cannot distinguish items that differ only in variant
- `targets` and `kev_targets`
    - Each combination of vulnerability ID and package class, ecosystem, and name counts as one finding
    - The same combination counts once even when detected in multiple versions or locations
    - Targets are findings with fix status `fixed` and fixed-version information, determined before candidates are checked, and their count differs from the number resolved by the candidate

The values of `tag_kind` are listed below.

| Value | Meaning |
| --- | --- |
| `pinned` | A pinned tag specifying a full version, such as `1.25.3` or `v2.4.1-bookworm` |
| `floating` | A floating tag, such as `latest`, `16`, `1.25`, or `16-alpine` |
| `excluded` | An image name excluded from candidate lookup, such as a digest-pinned reference, a prerelease, or an unsupported format |

See [Distributed image tags](remediation-logic.md#published-image-tags) for candidate selection and [Image candidate reasons](remediation-reference.md#image-reasons) for reasons for exclusion.

## Kubernetes workload information {#remediation-image-kubernetes}

`declared`, `pull`, and `management` are included when information about Kubernetes workloads is available.
See [Image name updates](webhook-diff-reference.md#reference-change-fields) for the workload key formats used by these fields.

### Declared images and pull policies {#remediation-image-declared}

Each element of `items[].declared[]` represents a combination of a workload key, the image name in the Pod spec, and the pull policy.
Identical combinations are grouped into one element, while different image names or pull policies produce separate elements even for the same workload.

The fields in each element of `items[].declared[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `workload` | string | Target workload key | — |
| `ref` | string | Image name in the Pod spec | omitted when unreadable |
| `pull_policy` | string | The Pod spec's `imagePullPolicy` | omitted when unset |

The values of `pull_policy` are listed below.

| Value | Meaning |
| --- | --- |
| `Always` | Checks the image with the registry when the container starts |
| `IfNotPresent` | Pulls the image if it is not present on the node |
| `Never` | Uses the image on the node without pulling it |

The following fields have additional notes.

- `ref`
    - Declarations that do not match the running image name or could not be read are also retained
- `workload`
    - `declared[]` includes declarations from containers belonging to this item
    - For containers with the same running image name but different content, declarations are also added when the declared image name does not match or cannot be read
    - These added declarations may contain workload keys absent from this item's `services[]`
- `pull_policy`
    - Defaults are not filled in when the policy is unset; guidance based on the effective pull policy is output in `pull[]`

See [Kubernetes image names and re-pull guidance](remediation-logic.md#kubernetes-image-references) for how declarations are checked against running image names.

### Re-pull guidance {#remediation-image-pull}

`items[].pull[]` provides guidance grouped by pull policy when `category` is `pull_again`.
Workload keys with the same pull policy are deduplicated, grouped, and sorted for output.

The fields in each element of `items[].pull[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `guidance` | string | Action needed to use the new image content | — |
| `policy` | string | Effective pull policy from the spec or its default when unset | — |
| `workloads` | array of strings | Workload keys covered by this guidance | `null` |

The values of `guidance` are listed below.

| Value | Meaning |
| --- | --- |
| `restart_pulls` | Restarting the Pods pulls the new content |
| `change_tag_or_digest` | A change to a pinned tag or digest is required |
| `import_to_node` | The image must be imported onto the node |

The values of `policy` are `Always`, `IfNotPresent`, and `Never`, as in [Declared images and pull policies](#remediation-image-declared).
They correspond to `restart_pulls`, `change_tag_or_digest`, and `import_to_node`, respectively.

The following fields have additional notes.

- `policy`
    - When the spec does not set a policy, guidance uses `Always` for `latest` or an unspecified tag, and `IfNotPresent` otherwise
    - Declarations whose pull policy cannot be read are excluded from the guidance
- `workloads`
    - Normal plan generation outputs only pull policies with at least one target
    - If a record without a value is output, the key is retained with `null`

See [Kubernetes image names and re-pull guidance](remediation-logic.md#kubernetes-image-references) for re-pull conditions.

### Management chains {#remediation-image-management}

`items[].management[]` represents the management chains identified for each workload.
Here, an owner is a Kubernetes resource involved in creating or updating the workload, or a tool such as Helm, Argo CD, or Flux identified as an owner by labels or annotations.

Multiple elements can share a workload key if the chains identified for individual Pods differ.

The following example shows Deployment `web` with owner information for Helm release `my-release` and Argo CD Application `myapp`.
This is one element of `management[]`.

The outer array of `chains` contains one chain, whose inner array lists three owners from nearest to the workload.
Because there is only one chain, `conflicting` is omitted.

```json
{
  "workload": "deployment/default/web/web",
  "chains": [
    [
      {
        "kind": "kubernetes",
        "resource": "deployment",
        "name": "web",
        "scope": "default"
      },
      {
        "kind": "helm",
        "name": "my-release",
        "scope": "default",
        "confidence": "claimed"
      },
      {
        "kind": "argocd",
        "name": "myapp",
        "confidence": "claimed"
      }
    ]
  ]
}
```

The fields in each element of `items[].management[]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `workload` | string | Target workload key | — |
| `chains` | array of arrays of objects | List of chains with [Owners in a chain](#remediation-image-chain-owner) ordered from nearest to the workload | `null` |
| `conflicting` | boolean | Whether this element has multiple management chains | omitted when `false` |

The following fields have additional notes.

- `chains`
    - In the example above, `chains[0]` is one chain, and `chains[0][0]`, `chains[0][1]`, and `chains[0][2]` are the owners in that chain
    - The inner array lists owners from nearest to the workload, such as a Kubernetes resource, a Helm release, and an Argo CD Application
    - Multiple chains in the outer array do not mean that the first chain takes precedence
    - Normal collection includes only workloads whose chains were identified; when a record without chains is output, the field is `null`
- `conflicting`
    - The value is `true` when the outer array contains multiple chains
    - Having multiple owners in a single chain does not by itself make the value `true`

### Owners in a chain {#remediation-image-chain-owner}

`items[].management[].chains[][]` is one element of the inner array of `chains`, representing one owner in the chain.
In the example above, these are the three objects whose `kind` values are `kubernetes`, `helm`, and `argocd`.

The fields in each element of `items[].management[].chains[][]` are listed below.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `kind` | string | Category of the tool or resource acting as the owner | `""` |
| `resource` | string | Kubernetes resource kind | omitted |
| `resource_id` | string | Identifier for a resource kind that cannot be distinguished by `kind` and `resource` alone | omitted |
| `name` | string | Name of the resource, release, Application, or other owner | omitted |
| `scope` | string | Namespace to which the owner belongs | omitted |
| `confidence` | string | Value indicating how far the owner information has been verified | omitted |

The values of `kind` are listed below.

| Value | Meaning |
| --- | --- |
| `kubernetes` | Kubernetes resource |
| `helm` | Helm release |
| `argocd` | Argo CD Application |
| `flux` | Flux Kustomization or HelmRelease |
| `compose` | Docker Compose project |
| `kustomize` | Kustomize overlay |
| `""` | Unknown owner |

Current Kubernetes collection outputs `kubernetes`, `helm`, `argocd`, and `flux` as `kind` values.
A normal Kustomize apply leaves no labels or annotations identifying the owner, so `kustomize` is not output.

The values of `resource` are listed below.

| Value | Meaning |
| --- | --- |
| `deployment` | Deployment |
| `statefulset` | StatefulSet |
| `daemonset` | DaemonSet |
| `cronjob` | CronJob |
| `job` | Job |
| `replicaset` | ReplicaSet |
| `pod` | Pod with no owning controller |
| `other` | Kubernetes resource outside the listed kinds |

`resource` is used when `kind` is `kubernetes`.
Current Kubernetes collection does not output `replicaset` or `other`.

The values of `confidence` are listed below.

| Value | Meaning |
| --- | --- |
| `claimed` | Owner indicated by labels, annotations, or similar markers, without verification of the management relationship itself |
| `asserted` | Information explicitly provided by the user, without verification by the tool |
| `attested` | Information based on provenance whose signature has been verified |

Current Kubernetes collection outputs `claimed` for Helm, Argo CD, and Flux owners, and omits `confidence` for Kubernetes resources.
This collection does not output `asserted` or `attested`.

The following fields have additional notes.

- `resource_id`
    - A Flux Kustomization uses `kustomizations.kustomize.toolkit.fluxcd.io`
    - A Flux HelmRelease uses `helmreleases.helm.toolkit.fluxcd.io`
    - When `kind` is `kubernetes` and `resource` is `other`, the format is `<kind>.<group>`, identifying the resource kind and API group
    - This is not a UID identifying an individual resource, so combine it with `kind`, `resource`, `scope`, and `name` to distinguish owners
- `scope`
    - This is the namespace name of a Kubernetes resource, Helm release, or Flux resource, rather than a fixed category value
    - If the workload and owner belong to different namespaces, this contains the owner's namespace
    - The Argo CD Application namespace is omitted because it is not collected
- `confidence`
    - `claimed` indicates information read from labels or annotations that a management tool placed on the resource
    - Omission does not mean that a signature or management relationship has been verified
