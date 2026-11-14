---
title: Selecting base image update candidates
---

# Selecting base image update candidates

For pinned tags, KestreLynx selects candidates for PRs that change the tag in `FROM`.
For floating tags, it provides rebuild guidance.

This page explains how KestreLynx selects the `FROM` to update, matches base layers, and estimates the effect of rebuilding.
See [Terms](remediation.md#terms) for the terminology used on this page.

## Identifying the base image {#base-image-selection}

KestreLynx follows `FROM` inheritance from the selected build stage to identify the external image to update.
It obtains the Dockerfile location and stage selection from the following information.

- When using a Dockerfile mapping, use its `target` to select the stage
- When Compose's `build:` identifies the location to change, use its context, Dockerfile, and `build.target`
- When a Dockerfile mapping and Compose's `build:` use the same repository and base branch, check that the Dockerfile path and `target` agree
- On Kubernetes, use a `dockerfile` mapping to specify the target and check that the image name in the Pod spec matches the running image

KestreLynx uses the stage named by the resulting `target`, or the last stage when it is omitted.

The following fictional Dockerfile excerpt shows the difference between inheritance through `FROM build` and copying through `COPY --from=build`.

```dockerfile
FROM golang:1.22.1 AS build
FROM build AS test
FROM debian:12.5.1-slim AS runtime
COPY --from=build /out /out
```

The selected stage determines which `FROM` is considered for a tag change.

| `target` | Path followed | `FROM` considered for a tag change |
| --- | --- | --- |
| `test` | `test` → `build` → external image | `FROM golang:1.22.1 AS build` |
| Omitted or `runtime` | `runtime` → external image | `FROM debian:12.5.1-slim AS runtime` |

References in `COPY --from` are not followed when identifying the base.
When the final `runtime` stage is selected, the `FROM` in `build` is not an update target.

The tag determines whether KestreLynx compares update candidates or provides guidance.
Here, the “current base” is the image that the tag in the current Dockerfile's `FROM` points to in the registry now.

| Base tag | Processing |
| --- | --- |
| Pinned tag | Compare the latest patch in the same series |
| Floating tag | Match the layers of the base currently referenced by the tag against the running image |

Adopting a pinned-tag candidate requires it to resolve at least one base fix target without introducing new findings.
See [Verification scope by target](remediation-logic.md#verification-scope) for the decision conditions and what is verified.

If the candidate in the same series does not resolve the findings, KestreLynx also checks whether it can proceed to [Checking newer series](remediation-image-logic.md#newer-series-check).

For floating tags, KestreLynx does not create tag update PRs or compare vulnerability counts before and after an update.
See [Dockerfile input requirements](remediation-source-formats.md#dockerfile-formats) for inputs that allow KestreLynx to locate the change.

## Matching base layers {#base-layer-matching}

KestreLynx checks the layer sequence to determine whether the current base image forms the foundation of the running image.
It matches the base's layer sequence against the first layers of the running image, including their order.

The matching result determines what happens next.

| Matching result | Processing |
| --- | --- |
| Match with a pinned tag | Proceed to selecting base fix targets and comparing candidates |
| Mismatch | Do not treat a comparison of that base as representative of the running image |
| Empty or unusable layer information | Treat as “Not comparable” |
| Match with a floating tag | Determine that no update is visible from the base currently referenced by the tag |

A mismatch with a floating tag also does not qualify as a candidate with confirmed improvements.
See [Rebuild estimates for floating tags](#rebuild-check) for estimates included in rebuild guidance.

!!! note "Layer matching and build provenance"

    A match establishes correspondence between filesystem layers.
    Even if a later instruction reinstalls a package with the same name and version, Trivy may report it as belonging to a base layer.

### Selecting base findings {#base-findings}

KestreLynx selects which findings to use as base fix targets.
It treats findings according to the layers reported by the Trivy scanner.

| Layer containing the finding | Treatment as a base fix target |
| --- | --- |
| A matched base layer | Include as a target |
| A layer after the base | Do not include as a target |
| No layer information | Do not include unless the language runtime conditions are met |
| The same layer ID appears both inside and outside the base and cannot be distinguished | Do not include unless the language runtime conditions are met |

### Handling language runtime findings {#base-runtime-findings}

For findings in language runtimes themselves, such as Node.js and Python, KestreLynx also uses version environment variables to decide whether to treat them as coming from the base.
This determines how findings are attributed to the base; it does not prove build provenance.

For pinned tags, KestreLynx checks all of the following conditions.

1. The current base's layer sequence matches the first layers of the running image
2. Both the running image's configuration and the current base's configuration contain the runtime's version environment variable
3. The environment variable has the same value in the running image and the current base

The variables are `NODE_VERSION` for Node.js and `PYTHON_VERSION` for Python.
If an environment variable occurs more than once, KestreLynx uses its last value.

When all conditions are met, runtime findings that could not be assigned to a layer are included as base fix targets.
The comparison between the current base and the candidate also checks runtimes, and the candidate is rejected as undetermined if a runtime being compared cannot be checked on either side.

## Rebuild estimates for floating tags {#rebuild-check}

KestreLynx checks the current base against the running image to estimate the effect of rebuilding for rebuild guidance.
This is separate from the normal candidate comparison used to decide whether to propose a PR, and no image is built.

The check applies when a floating tag is used in `FROM` and the current base's layers do not match the first layers of the running image.
This layer mismatch is recorded as `floating_base_unconfirmed`.

KestreLynx matches package locations and CVEs and records the result in `rebuild_check`.

One fix plan item targets one `FROM` in one Dockerfile.
Results from multiple running images built using that `FROM` are combined in that item.

For language runtimes themselves, KestreLynx estimates the effect of rebuilding when the following conditions are met.

1. The running image has findings in the language runtime itself
2. The runtime version can be checked from the current base's image configuration

When these conditions are met, KestreLynx estimates how many findings would disappear if a rebuild inherited the base's version and records the result in `rebuild_runtimes`.
It considers only CVEs currently detected in that runtime and does not count CVEs introduced by the new version.

Because this is not a comparison of finished images, the classification remains `not_comparable` (“Not comparable”).

Guidance for the entire item combines estimates for all running images using the same `FROM`.
It includes an estimate for the entire item only when every target running image has the reason `floating_base_unconfirmed`.

For example, suppose two running images use the same `FROM`, with one image's layers mismatching the current base and the other's matching it.
The mismatching image retains its individual `rebuild_runtimes` record, but no estimate is included for the entire item.

!!! note "Known limitations for language runtimes"

    - If a later layer replaces only the `node` or `python` executable, KestreLynx cannot distinguish it when the version environment variable is unchanged
    - The rebuild estimate may be inaccurate if the Dockerfile reinstalls the runtime or overrides the version through `ENV`

Scan preparation checks the comparison conditions and scan limits.

| Preparation | Processing |
| --- | --- |
| Current base | Scan the content currently referenced by the tag from the registry under the [scan comparison conditions](remediation-logic.md#comparison-conditions) |
| Running image | Rescan if its scan conditions differ from those used for comparison |
| Scan count | Use the remaining `baseline_rescans_per_cycle` allowance |
| Identical base content | Scan only once per cycle |

The check runs after planning, language package updates, and newer series checks, but before the plan is saved.
It reserves time and registry requests for PR processing through the same mechanism as the [Limits and reserving capacity for PR processing](remediation-image-logic.md#newer-series-limits).

If the check stops to preserve capacity for PR processing, it records `newer_series_reserved`.

### Matching method {#rebuild-check-matching}

For a package in the same location, KestreLynx checks whether the current base still has the target CVE.

A package's `status` is the vulnerability fix status reported by Trivy.
`fixed` indicates that a fixed version has been released, not that the vulnerability has been resolved in the running image.

The findings used for this check are selected as follows.

| Target | Findings used |
| --- | --- |
| Running image | Findings within the severity range whose status is `fixed` and that have a fixed version |
| Current base | All findings within the severity range, including those without a fixed version |
| Language runtimes themselves | Findings in `rebuild_runtimes` determined by [Rebuild estimates for floating tags](#rebuild-check) |

Packages are matched by type, class (OS or language package), name, and location.
`PkgPath` and `Target` are package location information reported by the Trivy scanner.

The table shows the location used for each package type and when location matching leaves a finding undetermined.

| Package type | Location used for matching | When matching is not possible |
| --- | --- | --- |
| OS package | Match by package name without using a path | The base's OS cannot be identified |
| `node-pkg` | Use `PkgPath` as reported | `PkgPath` is empty |
| `python-pkg` | Use `PkgPath` with the package's own version removed from `.dist-info` or `.egg-info` components | `PkgPath` is empty |
| `jar` | Use `PkgPath` with the package's own version removed when the filename ends in `-<version>.jar` | `PkgPath` is empty |
| Other types | Use `PkgPath`, or a `Target` containing `/` as a path when `PkgPath` is empty | `PkgPath` is empty and `Target` contains no `/` |

For example, the following paths differ only in pip's own version and are matched as the same location.

| pip version | `PkgPath` reported by Trivy |
| --- | --- |
| `25.0.1` | `usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA` |
| `25.3` | `usr/local/lib/python3.12/site-packages/pip-25.3.dist-info/METADATA` |

A finding is also left undetermined when any of the following applies.

- The base contains multiple versions at the same location
- The base contains the same version at the same location but does not report the CVE
- A language runtime finding is not included in `rebuild_runtimes` for the version where it was detected

For types other than OS packages, `node-pkg`, `python-pkg`, and `jar`, KestreLynx checks other locations only when neither the matching package nor the target CVE is found at the same location in the base.
If another location contains a package with the same type, class, and name, the finding is left undetermined.

### Matching results {#rebuild-check-results}

`rebuild_check` describes findings expected to disappear, findings that remain, undetermined counts, and related results.
The fields used in the Webhook's [Check against the current base](webhook-remediation-dockerfile-reference.md#dockerfile-rebuild-check) are listed below.

| Field | Meaning |
| --- | --- |
| `gone` | Package records where the base has a different version at the same location without the target CVE |
| `remaining` | Package records where the base has the same CVE at the same location |
| `not_in_base` | Records of OS packages or packages in global `node_modules` that are absent from the same location in the base |
| `other_not_in_base` | Number of other packages absent from the same location in the base, such as application dependencies outside the scope of `not_in_base` |
| `only_in_base` | Package records with base findings within the severity range whose status is `fixed` and that have a fixed version, with no matching finding at the same location in the running image |
| `undetermined` | Number of findings that could not be determined |

The check's status is recorded in `rebuild_check.status`.
When there are multiple running images, their individual statuses determine the status of the entire item.

| Status | Meaning | Condition for the entire item |
| --- | --- | --- |
| `checked` | All target findings have been determined | Every running image is `checked` |
| `partial` | Some findings are undetermined | None is `not_checked` and at least one is `partial` |
| `not_checked` | No comparison was made, with an explanation recorded in `reason` and `detail` | At least one is `not_checked` |

The following example has two running images using the same `FROM`, both with the reason `floating_base_unconfirmed`.

| Running image A's status | Running image B's status | Status of the entire item |
| --- | --- | --- |
| `checked` | `partial` | `partial` |

The following rules also apply when combining results from multiple running images for the entire item.

- The item's `rebuild_check` is included only when every running image has the reason `floating_base_unconfirmed`
- `gone` includes a finding only when it disappears from every running image that has it
- If the base version differs by platform, each version has a separate record

See [Rebuild guidance](remediation-update-results.md#rebuild-guidance) for how to read floating tag guidance, notification branches, and limitations of the estimates.

## When a merged PR has not been deployed {#base-update-not-deployed}

This check identifies cases where a base update PR has been merged but the running images were still built from the old base.
Because it uses PR processing records, it runs only when PR processing is enabled through `pull_requests`.

For an item with the reason `base_layers_mismatch`, KestreLynx checks all five conditions below.

- The repository was verified through GitHub during the latest fix plan processing, and its ID matches the repository ID in the record
- A Dockerfile PR created by KestreLynx has been merged and targets the same repository, base branch, file, and stage
- Nobody has changed the PR's branch or base, and its contents remain as created by KestreLynx
- The `FROM` after the PR's change and the `FROM` in the current Dockerfile specify the same image and tag
- Every running image's image ID matches an ID recorded for the running images when the PR was created

For example, using A and B as illustrative tags of the same image, the PR changed A to B and the current Dockerfile also specifies B.
Image names are matched allowing equivalent names such as `python` and `docker.io/library/python`.

If all conditions are met, the item's reason changes to `base_update_not_deployed`.
If multiple PRs qualify, KestreLynx uses the one with the highest number.

The item's category remains `not_comparable`, and each running image's result remains `base_layers_mismatch`.

## Rebuild command guidance {#rebuild-commands}

Rebuild guidance shows commands appropriate to how the image is built.
When Compose's `build:` and a `container/<name>` mapping use the same Dockerfile, it shows both `docker compose build --pull` and `docker build --pull`.

Recreate the containers using their respective rebuilt images.
