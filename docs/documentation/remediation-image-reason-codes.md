---
title: Image and source reason codes
---

# Image and source reason codes

Look up reason codes for image candidate comparison and adoption, and source retrieval and editing.
See [Result values](remediation-reason-codes.md#result-values) and [Reason codes](remediation-reason-codes.md#reason-codes) for result values and reason categories.

KEV is CISA's Known Exploited Vulnerabilities catalog of vulnerabilities confirmed to have been exploited.

Choose a subsection for the target or processing stage you want to check.

| Reference |
| --- |
| [Comparison conditions](#image-comparison-reasons) |
| [Tags and candidate decisions](#image-candidate-reasons) |
| [Limits and retrieval failures](#image-retrieval-reasons) |
| [Image references](#image-reference-reasons) |
| [Base images](#image-base-reasons) |
| [Checks across multiple containers](#image-container-reasons) |
| [Dockerfile](#source-dockerfile-reasons) |
| [Compose](#source-compose-reasons) |
| [Kubernetes manifests](#source-kubernetes-reasons) |
| [Kustomize](#source-kustomize-reasons) |
| [Helm values](#source-helm-reasons) |
| [Dependency files](#source-dependency-reasons) |
| [Packages](#source-package-reasons) |
| [Source retrieval](#source-retrieval-reasons) |

File retrieval and image-reference matching codes shared with Kustomize and Helm values appear under [Kubernetes manifests](#source-kubernetes-reasons), and ordinary init-container checks appear under [Kustomize](#source-kustomize-reasons).

See [Terms](remediation.md#terms) for the terminology used on this page.

## Image candidate reasons {#image-reasons}

Image candidate reasons describe whether scans can be compared and whether a candidate can be adopted into the plan.

### Comparison conditions {#image-comparison-reasons}

These codes describe information needed for baseline and candidate scans and reasons they cannot be compared.

| Code | Meaning | Details |
| --- | --- | --- |
| `scan_failed` | A scan failed | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `entity_unverified` | The running image could not be confirmed or compared with the registry content | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `conditions_unknown` | Conditions such as Trivy, databases, severities, or analysis settings are unknown for the baseline or candidate scan | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `conditions_differ` | Conditions such as Trivy, databases, severities, or analysis settings differ between the baseline and candidate scans | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_unknown` | The image's operating system or CPU architecture is unknown | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_differ` | The compared images have different operating systems or CPU architectures | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `variant_unsupported` | The image platform specifies a `variant`, such as ARM `v7` | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `packages_missing` | The scan result has no package list | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `packages_truncated` | The package list in the scan result is truncated | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `unknown_package_type` | The baseline or candidate findings, or the candidate package list, contain an unsupported package type | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `type_not_analysed` | The candidate scan did not analyse the target package type | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `targets_not_detected_on_baseline` | Target findings selected from the original scan were not detected in the comparison scan of the running image or current base image | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `analysis_incomplete` | The image analysis was incomplete | [Comparison conditions](remediation-logic.md#comparison-conditions) |

The baseline can use the original scan if its conditions match the candidate scan, or a rescan performed for comparison.

### Tags and candidate decisions {#image-candidate-reasons}

These codes describe tag lookup results and changes to findings in a candidate.

| Code | Meaning | Details |
| --- | --- | --- |
| `no_newer_tag` | No newer tag exists | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `same_content` | The newer tag has the same content | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets` | The candidate does not resolve the target findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `locally_built` | The image was built on its host and is outside published-image candidate searches | [Local build exclusion](remediation-image-logic.md#local-builds) |
| `partial_improvement` | The candidate resolves only some findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `introduced_findings` | The candidate introduces new findings | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `introduced_kev` | The candidate introduces a KEV-listed vulnerability | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `adopted` | The candidate passed the scan-comparison decision and was adopted into the remediation plan | [Comparison conditions](remediation-logic.md#comparison-conditions) |

Candidate adoption alone does not mean that files were updated or a PR was created.

### Limits and retrieval failures {#image-retrieval-reasons}

These codes describe causes that stopped registry retrieval or candidate checks.

| Code | Meaning | Details |
| --- | --- | --- |
| `auth_required` | The registry requires authentication | [Private image authentication](remediation-setup.md#configure-registry-auth) |
| `platform_not_found` | The candidate has no image for the running image's platform | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_ambiguous` | Multiple candidate images match the platform | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `platform_mismatch` | The candidate platform differs from the running image | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `registry_error` | The registry returned an error | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `tag_listing_incomplete` | The tag list could not be read to the end | [Tag discovery](remediation-image-logic.md#tag-discovery) |
| `newer_series_tag_list_incomplete` | The complete tag list needed to choose newer series could not be read to the end | [Newer series check](remediation-image-logic.md#newer-series-check) |
| `newer_series_reserved` | Checking newer series stopped to leave time and registry requests for PR processing | [Newer series check](remediation-image-logic.md#newer-series-check) |
| `candidate_scan_limit` | The limit on candidate scans in one cycle was reached | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `baseline_rescan_limit` | The limit on baseline image rescans was reached | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `tag_page_limit` | The limit on tag-list requests was reached | [Tag discovery](remediation-image-logic.md#tag-discovery) |
| `registry_budget_exhausted` | The registry request limit was reached | [Tag discovery](remediation-image-logic.md#tag-discovery) |
| `rate_limited` | A rate limit was reached when accessing a registry or GitHub during planning | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `cycle_deadline` | The cycle's execution time limit was reached | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `registry_timeout` | A registry request timed out | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |

### Image references {#image-reference-reasons}

These codes describe image references and tags for which candidates cannot be searched.

| Code | Meaning | Details |
| --- | --- | --- |
| `digest_only` | The reference has a digest but no tag | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `tag_and_digest` | The reference has both a tag and a digest | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `prerelease` | The tag has a prerelease format | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `bare_digest` | The image reference is only a digest, so its repository is unknown | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `unparsable` | The image reference cannot be parsed | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `unsupported_tag_format` | The tag format is unsupported | [Published image tags](remediation-image-logic.md#published-image-tags) |

### Base images {#image-base-reasons}

These codes describe matching a Dockerfile's base image against the layers of a running image.

| Code | Meaning | Details |
| --- | --- | --- |
| `base_layers_mismatch` | The base-image layers referenced by the tag do not match the beginning of the running image | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `base_update_not_deployed` | The base-image update PR was merged, but the running image is unchanged since the PR was created | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `base_layers_unusable` | The running-image and base-image layers cannot be compared | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `base_onbuild` | The base image has `ONBUILD` triggers | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `no_base_derived_findings` | No fixable findings are in the base-image layers | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `base_unchanged` | The current base-image layers referenced by the tag match the beginning of the running image, so no base-image update can be confirmed | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `floating_base_unconfirmed` | The base-image layers currently referenced by the floating-tag `FROM` do not match the beginning of the running image | [Base-layer matching](remediation-base-image-logic.md#base-layer-matching) |

### Checks across multiple containers {#image-container-reasons}

These codes describe whether containers sharing a file or image can adopt a common candidate.
When checking Kubernetes declarations, containers with the same running image reference are checked together.

| Code | Meaning | Details |
| --- | --- | --- |
| `declared_ref_mismatch` | A checked container's Pod spec image reference differs from its running image reference, making the grouped item `not_comparable` | [Kubernetes image references and repulling](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `declared_ref_unavailable` | A checked container's Pod spec image reference cannot be read, making the grouped item `not_comparable` | [Kubernetes image references and repulling](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `dockerfile_set_not_adopted` | No candidate could be adopted in common by all workloads sharing the Dockerfile | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `compose_set_not_adopted` | No candidate could be adopted in common by all services sharing the image | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `instances_missing` | A mapped container has no running instance, an instance has no readable running image reference, or an instance has no plan item | [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |
| `mixed_references` | Running instances disagree on the declared or running image reference | [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |
| `kubernetes_set_not_adopted` | Containers whose shared image is updated in the same file have different adopted candidates | [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |

If Dockerfile or Compose targets cannot adopt a common candidate, also check each workload's or service's reason.

## Source reasons {#source-reasons}

Source reasons describe whether update files can be retrieved, interpreted, and matched to running images.

### Dockerfile {#source-dockerfile-reasons}

These codes describe reading a Dockerfile, identifying its base image, and determining whether it can be edited.

| Code | Meaning | Details |
| --- | --- | --- |
| `dockerfile_file_not_found` | The Dockerfile is not at the configured path | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_file_unusable` | The Dockerfile is not a regular file, is a Git LFS pointer, or exceeds the size limit for reading during PR processing | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dockerfile_invalid` | The Dockerfile cannot be parsed, or edit verification failed | — |
| `dockerfile_target_missing` | The specified build stage does not exist | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_stage_cycle` | Following stage references never reaches an external image | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_variable` | The base image or platform contains a variable | — |
| `dockerfile_scratch` | The base image is `scratch` | — |
| `dockerfile_digest` | The base image is specified by digest | — |
| `dockerfile_tag_unsupported` | The base-image tag has a format for which candidates cannot be searched | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `dockerfile_frontend` | A nonstandard syntax frontend is specified | — |
| `dockerfile_escape` | The `escape` directive is set | — |
| `dockerfile_ambiguous_range` | The tag's exact location in the file cannot be identified | — |
| `dockerfile_onbuild` | An inherited stage has `ONBUILD` | — |
| `dockerfile_stage_platform` | An intermediate `FROM` has `--platform` | — |
| `dockerfile_not_editable` | The base image does not use a pinned tag | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_source_mismatch` | The base image or stage read from the Dockerfile differs from what the remediation plan compared | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `dockerfile_mapping_differs` | The configured Dockerfile differs from the Dockerfile referenced by Compose | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |

### Compose {#source-compose-reasons}

These codes describe Compose build settings and conditions that prevent editing `image`.

| Code | Meaning | Details |
| --- | --- | --- |
| `compose_no_build` | The target service has no `build` setting | [Base-image selection](remediation-base-image-logic.md#base-image-selection) |
| `compose_build_remote_context` | The build context is a URL or repository | — |
| `compose_build_inline` | The build uses `dockerfile_inline` | — |
| `compose_build_additional` | The build uses `additional_contexts` | — |
| `compose_build_path` | A build path is absolute, outside the repository, or malformed | — |
| `compose_build_unsupported_form` | The `build` syntax is unsupported | — |
| `compose_build_undetermined` | How the service is built cannot be determined | [Local build exclusion](remediation-image-logic.md#local-builds) |
| `compose_invalid` | The Compose file cannot be parsed, or edit verification failed | — |
| `compose_service_missing` | The target service or its `image` key is missing from the Compose file | — |
| `compose_build` | The service builds its image | [Local build exclusion](remediation-image-logic.md#local-builds) |
| `compose_include_or_extends` | The Compose file has a top-level `include`, or the target service uses `extends` | [Compose formats](remediation-source-formats.md#compose-formats) |
| `compose_merge_key` | The path to `image` contains a merge key | — |
| `compose_anchor_or_alias` | The `image` value involves a YAML anchor or alias | — |
| `compose_not_string` | The `image` value is not a simple string | — |
| `compose_block_scalar` | The `image` value is a block scalar | — |
| `compose_variable` | The `image` value contains a variable | — |
| `compose_digest` | The `image` value includes a digest | — |
| `compose_source_mismatch` | The file's `image` differs from the running image | [Source verification](remediation-logic.md#source-verification) |
| `compose_file_not_found` | The Compose file is not at the configured path | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `compose_file_unusable` | The Compose file is not a regular file, is a Git LFS pointer, or exceeds the read-size limit | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |

### Kubernetes manifests {#source-kubernetes-reasons}

These codes describe identifying workloads and containers in a manifest and determining whether their image references can be edited.

| Code | Meaning | Details |
| --- | --- | --- |
| `manifest_file_not_found` | The Kubernetes manifest, Kustomize file, or Helm values file is not at the configured path | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_file_unusable` | The target Kubernetes manifest, Kustomize file, or Helm values file is not a regular file, is a Git LFS pointer, or exceeds the read-size limit | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_invalid` | The manifest cannot be parsed, contains duplicate keys, or failed edit verification | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_anchor_or_alias` | The path to the container or document identification involves a YAML anchor or alias | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_merge_key` | The path to the container or document identification contains a merge key | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_not_string` | The `image` value is not a simple string | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_block_scalar` | The `image` value is a block scalar | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_variable` | The `image` value contains a variable | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_digest` | The `image` value includes a digest | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_tag_missing` | The `image` value has no tag | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_image_automation` | The `image` line has a Flux image automation `$imagepolicy` comment | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `manifest_template` | The manifest contains a template expression | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `image_updater_file` | The target Kubernetes manifest, Kustomize file, or Helm values file shares a directory with an Argo CD Image Updater write-back file | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `source_object_missing` | The manifest has no document for the workload object | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `source_object_ambiguous` | The manifest has multiple documents for the workload object | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `source_container_missing` | The object has no editable container with the specified name | [Manifest formats](remediation-source-formats.md#manifest-formats) |
| `source_mismatch` | The image reference read from a Kubernetes manifest, Kustomize file, or Helm values file differs from the Pod spec or running image reference | [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) · [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) · [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) |
| `mapping_conflict` | Two or more mappings of the file refer to the same container in the same document | [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) |

### Kustomize {#source-kustomize-reasons}

These codes describe whether an `images` entry in a kustomization can be edited.

| Code | Meaning | Details |
| --- | --- | --- |
| `kustomize_invalid` | The kustomization is not one valid YAML document, contains duplicate keys, or fails post-edit checks | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_missing` | The kustomization has no `images` entry with the mapped name | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_ambiguous` | Multiple `images` entries have the mapped name | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_tag_not_set` | The `images` entry has no `newTag`, or it is empty | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_unsupported_feature` | The kustomization uses a feature that could change which containers the `images` setting affects | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_chained` | Another `images` entry also changes the target entry's name or resulting image | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_digest` | The `images` entry pins a digest | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_anchor_or_alias` | An anchor or alias involves the `images` entry | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_merge_key` | A merge key involves the `images` entry | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_not_string` | A value in the `images` entry is not a simple string | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_block_scalar` | A value in the `images` entry is a block scalar | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_variable` | A value in the `images` entry contains a variable | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_template` | The kustomization contains a template expression | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_automation` | The `newTag` line has a Flux image automation `$imagepolicy` comment | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `init_container_unverified` | An ordinary init container listed in a Kustomize or Helm values mapping cannot be confirmed to have used the same image as a listed running container in the same Pod | [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) · [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) |

### Helm values {#source-helm-reasons}

These codes describe whether a values image setting can be edited and whether affected containers have been declared.

| Code | Meaning | Details |
| --- | --- | --- |
| `helm_invalid` | The values file is not one valid YAML document, contains duplicate keys, or fails post-edit checks | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_key_missing` | The values file has no value at the mapped key | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_tag_from_chart` | The key has no tag, so the chart's own default is used | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_digest` | The image at the key is pinned by digest | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_values_shape` | The key is neither a `repository` and `tag` mapping nor a `repository:tag` string | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_not_string` | The image string, or a `repository`, `tag`, optional `registry`, or `digest` value, cannot be read as a simple string | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_block_scalar` | A string value in the image setting is a block scalar | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_variable` | A string value in the image setting contains a variable | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_template` | The values file contains a template expression | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_anchor_or_alias` | A node on the path to the key has an anchor or alias | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_merge_key` | A mapping on the path to the key has a merge key | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_image_automation` | An image line has a Flux image automation `$imagepolicy` comment | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `undeclared_affected_workload` | A container absent from the mapping's `workload` and `kustomize.affects` or `helm_values.affects` declares the same image reference and could be affected by the edit | [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) · [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) |

`affects` lists containers other than `workload` that are affected by the tag change, including ordinary init containers.

### Dependency files {#source-dependency-reasons}

These codes describe whether dependency declaration files, such as `package.json`, and lockfiles can be read and updated.

| Code | Meaning | Details |
| --- | --- | --- |
| `dependency_files_not_found` | No dependency files were found | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `ambiguous_dependency_files` | Multiple combinations of dependency files match, so one cannot be selected | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `dependency_file_unusable` | A dependency file is not a regular file, is a Git LFS pointer, or its contents cannot be read | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `unsupported_lockfile` | The lockfile format is unsupported | — |
| `go_replace_unsupported` | `go.mod` contains an unsupported `replace` directive | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `go_exclude_unsupported` | `go.mod` contains an unsupported `exclude` directive | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `go_binary_not_from_source` | The image's Go binary does not match the target `go.mod`, or an incomplete package list prevents matching | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `jar_bundled_copy` | A copy of the package is bundled inside another archive and cannot be fixed by updating the project's dependency files | [Maven package selection](remediation-maven-logic.md#maven-package-selection) · [Gradle package selection](remediation-gradle-logic.md#gradle-package-selection) |
| `maven_app_jar_ambiguous` | The target project's archive cannot be identified in the image | [Maven dependency files](remediation-dependency-formats.md#maven-inputs) |
| `maven_model_unsupported` | The pom files use a form whose resolution cannot be reproduced during update checks | [Maven dependency files](remediation-dependency-formats.md#maven-inputs) |
| `maven_parent_mismatch` | The pom file at the parent lookup location does not match the declared parent | [Maven dependency files](remediation-dependency-formats.md#maven-inputs) |
| `maven_reactor_unsupported` | The project's modules cannot be read as one build | [Maven dependency files](remediation-dependency-formats.md#maven-inputs) |
| `gradle_build_unsupported` | Dependency declarations or execution settings cannot be read because the build uses multiple projects or unsupported statements or arguments, such as `apply from` or dynamic versions | [Build script forms](remediation-dependency-formats.md#gradle-build-forms) |
| `gradle_locking_unenforced` | The build is not configured to enforce the lockfile exactly, with lockMode `STRICT` and all configurations locked | [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) |
| `gradle_plugin_unsupported` | The build uses a plugin or version that is not allowed | [Allowed plugins](remediation-dependency-formats.md#gradle-plugins) |
| `workspace_unsupported` | The project has an unsupported npm, pnpm, or uv workspace layout, or Go `go.work` or `vendor` | [npm dependency files](remediation-dependency-formats.md#npm-inputs) · [pnpm dependency files](remediation-dependency-formats.md#pnpm-inputs) · [uv dependency files](remediation-dependency-formats.md#uv-inputs) · [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `workspace_settings_unsupported` | The workspace settings file contains unsupported settings | — |
| `dynamic_metadata` | Project metadata is determined dynamically | — |
| `unsupported_requirements` | The requirements syntax is unsupported | — |
| `unparsable_source` | A dependency file cannot be parsed | — |
| `unsupported_source_settings` | An unsupported package source setting is present | — |

### Packages {#source-package-reasons}

These codes describe matching installed versions against dependency files and checking package sources.

| Code | Meaning | Details |
| --- | --- | --- |
| `scan_not_pinned` | The scan result is not tied to a specific image | [Source verification](remediation-logic.md#source-verification) |
| `not_found_in_source` | The dependency files do not list the package at its installed version | [Source verification](remediation-logic.md#source-verification) |
| `global_node_modules` | The package is in global `node_modules` and cannot be fixed by updating dependency files | [Source verification](remediation-logic.md#source-verification) |
| `non_registry_source` | The package comes from somewhere other than a supported public registry | — |
| `sdist_only` | The package has only a source distribution | — |
| `forced_by_override` | An override pins the package version | — |
| `marker_not_evaluated` | The dependency's environment marker has not been evaluated | — |
| `invalid_marker` | The dependency's environment marker is invalid | — |
| `multiple_versions` | Multiple versions or occurrences of the same package cannot be handled as one update | — |
| `unparsable_version` | The package version cannot be parsed | — |

Packages in global `node_modules` are displayed differently by notification destination.

| Destination | Display |
| --- | --- |
| Webhook | Includes the package and reason code |
| Slack and email | Omits the package from "Manual" and omits the item if no other packages can be shown |
| End-of-support guidance in Slack and email | Keeps a `runtime_eol` item even when no other packages can be shown |

### Source retrieval {#source-retrieval-reasons}

These codes describe causes that stopped repository or dependency-file retrieval.

| Code | Meaning | Details |
| --- | --- | --- |
| `source_not_found` | The source repository or branch was not found | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_access_denied` | Access to the source repository was denied | [Prepare GitHub access](remediation-setup.md#prepare-github-access) |
| `source_too_large` | The source is too large to read | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `file_too_large` | A dependency file is too large to read | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `byte_budget_exhausted` | The limit on bytes read from the source was reached | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_error` | Reading the source failed | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `github_budget_exhausted` | The GitHub request limit was reached | [Missing plans](remediation-troubleshooting.md#check-missing-plan) |
| `source_read_failed` | Retrieving dependency files again failed | [Update failures](remediation-troubleshooting.md#check-update-failure) |
