---
title: Supported formats for files that specify images
---

# Supported formats for files that specify images

Use this page to check which image declarations KestreLynx can update automatically in Compose, Kubernetes manifests, Kustomize, Helm values, and Dockerfiles.

Choose the section for the file you want to check.

| File type | Section |
| --- | --- |
| Compose file | [Compose formats](#compose-formats) |
| Kubernetes manifest | [Manifest formats](#manifest-formats) |
| `kustomization.yaml` and related filenames | [Kustomize formats](#kustomize-formats) |
| Helm values file | [Helm values formats](#helm-values-formats) |
| Dockerfile | [Dockerfile formats](#dockerfile-formats) |

See [Source reasons](remediation-image-reason-codes.md#source-reasons) for reason codes and the rules linked at the end of each section for the scope of PRs that are withheld.
See [Terms](remediation.md#terms) for the terminology used on this page.

## Compose formats {#compose-formats}

For Compose, KestreLynx edits the tag in an image name written directly in `services.<service>.image`.
It compares the image repository name and tag with those of the running image.

The following checks establish whether the current file declaration matches the running image.

| Current declaration | Matching check |
| --- | --- |
| A string in `services.<service>.image` | Its repository name and tag must match the running image, and the tag position must be identifiable |
| `nginx:1.27.2` and `docker.io/library/nginx:1.27.2` | Docker Hub shorthand is expanded so these references match |
| `nginx:1.27.2` and `nginx:1.27.3` | These references do not match because their tags differ |

Selecting the new tag is separate from checking that the current declarations match.
The following examples show which tags qualify as patch updates within the same series.

| Tag change | Eligibility as an update |
| --- | --- |
| Pinned tags `1.2.3` and `1.2.3-alpine` | Can be changed to a newer patch in the same series |
| Changing `1.2.3-alpine` to `1.2.4-alpine` | Counts as a patch update within the same series |
| Changing `1.2.3-alpine` to `1.3.0-alpine` or `1.2.4-bookworm` | Does not count as a patch update within the same series |

The following declarations prevent automatic editing and require manual action.

| Declaration | Reason code |
| --- | --- |
| A value containing `$` in the target `image` | `compose_variable` |
| A digest in the target image name | `compose_digest` |
| A YAML anchor on the document root | `compose_anchor_or_alias` |
| An anchor or alias on the `services` mapping | `compose_anchor_or_alias` |
| An anchor or alias on the target service mapping | `compose_anchor_or_alias` |
| An anchor or alias on the target `image` value | `compose_anchor_or_alias` |
| A merge key at the document root | `compose_merge_key` |
| A merge key in the `services` mapping | `compose_merge_key` |
| A merge key in the target service mapping | `compose_merge_key` |
| A block scalar for `image` | `compose_block_scalar` |
| A non-string `image` | `compose_not_string` |
| `include` at the document root | `compose_include_or_extends` |
| `extends` on the target service | `compose_include_or_extends` |

The following example puts anchors on the target service mapping, `web`, and on its `image` value.

```yaml
services:
  web: &service
    image: &image nginx:1.27.2
```

Either `&service` alone or `&image` alone requires manual action with `compose_anchor_or_alias`.

Floating tags such as `latest`, `22-alpine`, and `1.2` are candidates for “Re-pull”; KestreLynx does not create a PR to rewrite an image name that keeps the same tag.

An image built with `build:` is excluded from searches for published images.
If `build:` has an empty-string, null, or unreadable value, KestreLynx cannot determine whether the service builds its image and reports `compose_build_undetermined`.

Dockerfile and dependency-file updates are handled separately from tag updates for the image built with `build:`.

See [Published image tags](remediation-image-logic.md#published-image-tags) for tag selection and [Excluding local builds](remediation-image-logic.md#local-builds) for handling build targets.

## Manifest formats {#manifest-formats}

For manifests, KestreLynx edits only the tag in the target container `image`, preserving formatting and comments.
The table shows where each image name comes from and which parts must match.

| Source | Value read | Parts that must match |
| --- | --- | --- |
| The Pod declaration in the cluster | The target container `image` in the Pod spec | Image repository name and tag |
| The image actually running | The target container image name obtained from Pod status | Image repository name and tag |
| The manifest on GitHub | The `image` of the container being edited | Image repository name and tag |

The document and container to edit are selected using the following conditions.

| Location to check | Supported condition |
| --- | --- |
| YAML documents | A plain manifest may contain multiple documents in one file |
| `apps/v1` objects | The object is a `Deployment`, `StatefulSet`, or `DaemonSet` |
| `batch/v1` objects | The object is a `Job` or `CronJob` |
| `v1` objects | The object is a `Pod` |
| `apiVersion` and `kind` | They match the type of the mapped workload |
| `metadata.name` | It matches `manifest.object.name`, or the workload name when that setting is omitted |
| A populated `metadata.namespace` | It matches the namespace of the mapped workload |
| Omitted `metadata.namespace` | The other identity fields identify exactly one document without filtering by namespace |
| Container name | It matches the mapped container name |
| Container type | It is a regular container or a native sidecar with `restartPolicy: Always` |
| Target `image` | The matched image name has an explicit tag |

The following declarations and file conditions require manual action.

| Declaration | Reason code |
| --- | --- |
| Duplicate keys in the file (all YAML documents are checked before and after editing) | `manifest_invalid` |
| A digest in the target image name | `manifest_digest` |
| A value containing `$` in the target `image` | `manifest_variable` |
| An omitted tag in the target image name | `manifest_tag_missing` |
| A block scalar for `image` | `manifest_block_scalar` |
| An `image` other than a simple string | `manifest_not_string` |
| Anchors or aliases on the path to the edit | `manifest_anchor_or_alias` |
| Anchors or aliases involved in document identity, such as `metadata` | `manifest_anchor_or_alias` |
| A merge key on the path to the edit | `manifest_merge_key` |
| A merge key in document identity | `manifest_merge_key` |
| A Flux `$imagepolicy` comment on the target `image` line | `manifest_image_automation` |
| `{{` anywhere in the file | `manifest_template` |
| An Argo CD Image Updater write-back file, `.argocd-source-*.yaml`, in the same directory | `image_updater_file` |
| A file image name that differs from the Pod spec or running image name | `source_mismatch` |
| Multiple mappings pointing to the same container in the same document, including a document with no namespace | `mapping_conflict` |

Flux uses `$imagepolicy` in an end-of-line comment as an image automation marker.
A target line containing `$imagepolicy`, as in the following example, requires manual action.

```yaml
image: nginx:1.25.3 # {"$imagepolicy": "flux-system:web:tag"}
```

Objects inside a `List` and regular init containers are not edited.
See [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) for PR creation conditions.

## Kustomize formats {#kustomize-formats}

For Kustomize, KestreLynx edits only `newTag` in the `images` entry named by `kustomize.image`.
The KestreLynx setting `remediation.mappings[].kustomize.affects` lists containers affected by the tag change other than the container specified in `workload`.

The table shows supported declarations and conditions for matching the image name read from the file.

| Location to check | Conditions and scope |
| --- | --- |
| Filename | Use `kustomization.yaml`, `kustomization.yml`, or `Kustomization` |
| YAML documents | The file contains exactly one document |
| Target entry | Exactly one `images[].name` matches `kustomize.image` |
| `newTag` | Only the existing string is replaced, preserving quotes, comments, and line breaks |
| `newName` | The existing value is preserved |
| Image name read from the file | The repository name and tag derived from `name` or the existing `newName`, together with `newTag`, match the Pod spec and running image name |

Quote tags that would otherwise be interpreted as numbers.

Values are checked in `name` and `newName` in every `images` entry, and in `newTag` in the entry being edited.
The following declarations and file conditions require manual action.

| Declaration | Reason code |
| --- | --- |
| Missing `newTag` | `kustomize_tag_not_set` |
| An empty-string `newTag` | `kustomize_tag_not_set` |
| A non-string value being read, such as a number | `kustomize_not_string` |
| An explicit YAML tag on a value being read | `kustomize_not_string` |
| A block scalar in a value being read | `kustomize_block_scalar` |
| `$` in a value being read | `kustomize_variable` |
| A `digest` field in the target entry | `kustomize_digest` |
| A digest in the target image name | `kustomize_digest` |
| Anchors or aliases involving the document root | `kustomize_anchor_or_alias` |
| Anchors or aliases involving `images` or its entries | `kustomize_anchor_or_alias` |
| Anchors or aliases involving values being read | `kustomize_anchor_or_alias` |
| A merge key at the document root | `kustomize_merge_key` |
| A merge key in an `images` entry | `kustomize_merge_key` |
| `{{` anywhere in the file | `kustomize_template` |
| A spelling that differs from a known field name in case, such as `Newtag` | `kustomize_invalid` |
| Duplicate keys differing only in case | `kustomize_invalid` |
| Use of `imageTags`, `patches`, `replacements`, `components`, `helmCharts`, or `helmGlobals` | `kustomize_unsupported_feature` |
| Use of `generators`, `transformers`, `vars`, `patchesStrategicMerge`, or `patchesJson6902` | `kustomize_unsupported_feature` |
| Remote `resources` | `kustomize_unsupported_feature` |
| Remote `bases` | `kustomize_unsupported_feature` |
| The `name` of another entry matching image names before or after the target entry changes them | `kustomize_image_chained` |
| The target `name` matching image names before or after another entry changes them | `kustomize_image_chained` |
| A `name` that is not a valid regular expression, including in non-target entries | `kustomize_invalid` |
| A Flux `$imagepolicy` comment on the `newTag` line | `kustomize_image_automation` |
| `.argocd-source-*.yaml` in the same directory | `image_updater_file` |
| The specified file being absent | `manifest_file_not_found` |
| A file that is not of an editable type | `manifest_file_unusable` |
| A file image name that differs from the Pod spec or running image name | `source_mismatch` |

The following change is also left to the user, without a specific reason code listed here.

| Location to change | Handling |
| --- | --- |
| `newName` itself | Manual action |

Kustomize matches `name` as a regular expression.
The following example is rejected because another entry changes the same image name.

```yaml
images:
  - {name: busybox, newName: nginx, newTag: "1.27.2"}
  - {name: nginx, newTag: "1.27.2"}
```

If only `newTag` in the first entry is changed to `1.27.3`, each entry specifies the following image name.

| Entry | Matching `name` | Image name written with the current settings | Image name written after updating the first `newTag` |
| --- | --- | --- | --- |
| First | `busybox` | `nginx:1.27.2` | `nginx:1.27.3` |
| Second | `nginx` | `nginx:1.27.2` | `nginx:1.27.2` |

Editing the first entry is rejected because its resulting `nginx:1.27.3` also matches `name: nginx` in the second entry.
Editing the second entry also results in `kustomize_image_chained`, because the image name written by the first entry matches `name: nginx` in the second entry.

See [Kustomize and Helm values PRs](remediation-kubernetes-logic.md#kustomize-and-helm-prs) for checks on the containers listed in `workload` and `affects` and for regular init containers, and [Configure Kustomize PRs](remediation-setup-kubernetes.md#kustomize-pull-requests) for mapping configuration.

## Helm values formats {#helm-values-formats}

For Helm values, KestreLynx edits only the tag portion of the value selected by `helm_values.key`.
The image repository name, including the registry, and tag read from the file must match the Pod spec and running image name.

You must verify that other values files, `--set`, or other settings do not override the selected value, and that changing the key changes the image actually used.

A YAML mapping is a collection of keys and values.
For the following `apps/values.yaml`, set `helm_values.key: image` to select the YAML mapping, rather than specifying `image.tag`.

```yaml
image:
  registry: docker.io
  repository: library/nginx
  tag: "1.27.2"
```

The table shows supported declarations.

| Location to check | Conditions and scope |
| --- | --- |
| File | Use a `.yaml` or `.yml` values file |
| YAML documents | The file contains one document with no duplicate keys |
| Image specified as a YAML mapping | It has `repository` and a string `tag`; `registry` is optional |
| Image specified as a string | It uses a value such as `"repo:tag"` |
| `helm_values.key` | It specifies the path to the YAML mapping or string that declares the image |
| Tag editing | Existing quotes and comments are preserved |
| A YAML mapping with an unquoted tag | Double quotes are added if Helm would not read the new tag, such as `1.10` or `on`, as a string |

When quotes are added, the PR body records that change.

For a YAML mapping, values are checked in `repository`, `tag`, and any specified `registry` or `digest` fields.
For an image specified as a string, the entire string selected by `helm_values.key` is checked.

The following declarations and file conditions require manual action.

| Declaration | Reason code |
| --- | --- |
| No value at the path specified by `helm_values.key` | `helm_key_missing` |
| A missing `tag` in a YAML mapping, which uses the chart default | `helm_tag_from_chart` |
| An empty-string `tag` in a YAML mapping, which uses the chart default | `helm_tag_from_chart` |
| An omitted tag in an image specified as a string, which uses the chart default | `helm_tag_from_chart` |
| A non-string value being read, such as a number, boolean, or null | `helm_not_string` |
| An explicit YAML tag on a value being read | `helm_not_string` |
| An existing unquoted `tag` in a YAML mapping that Helm does not read as a string | `helm_not_string` |
| A block scalar in a value being read | `helm_block_scalar` |
| `$` in a value being read | `helm_variable` |
| A non-empty `digest` in the target YAML mapping | `helm_digest` |
| A digest in an image specified as a string | `helm_digest` |
| A `repository` containing a tag | `helm_values_shape` |
| A `repository` containing a digest | `helm_values_shape` |
| `name` in the same YAML mapping as `repository` | `helm_values_shape` |
| `image` in the same YAML mapping as `repository` | `helm_values_shape` |
| Anchors or aliases on the path to the target key | `helm_anchor_or_alias` |
| Anchors or aliases involving values being read | `helm_anchor_or_alias` |
| An anchor on a key in a YAML mapping along the path | `helm_invalid` |
| An anchor on a key in the target YAML mapping | `helm_invalid` |
| An alias used as a key anywhere in the file | `helm_anchor_or_alias` |
| A merge key at the document root | `helm_merge_key` |
| A merge key on the path to the target key | `helm_merge_key` |
| A merge key in the target YAML mapping | `helm_merge_key` |
| An unquoted key that Helm does not read as a string in a YAML mapping along the path | `helm_invalid` |
| An unquoted key that Helm does not read as a string in the target YAML mapping | `helm_invalid` |
| Keys interpreted as the same key, such as `"true"` and `on`, in a YAML mapping along the path | `helm_invalid` |
| Keys interpreted as the same key, such as `"true"` and `on`, in the target YAML mapping | `helm_invalid` |
| Multiple YAML documents | `helm_invalid` |
| Duplicate keys anywhere in the file | `helm_invalid` |
| Invalid YAML | `helm_invalid` |
| `{{` anywhere in the file | `helm_template` |
| A Flux `$imagepolicy` comment on a `repository`, `registry`, or `tag` line | `helm_image_automation` |
| A Flux `$imagepolicy` comment on the line of an image specified as a string | `helm_image_automation` |
| `.argocd-source-*.yaml` in the same directory | `image_updater_file` |
| The specified file being absent | `manifest_file_not_found` |
| A file that is not of an editable type | `manifest_file_unusable` |
| A file image name that differs from the Pod spec or running image name | `source_mismatch` |

See [Kustomize and Helm values PRs](remediation-kubernetes-logic.md#kustomize-and-helm-prs) for checks on containers affected by the tag change and handling of regular init containers, and [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) for assumptions about value overrides.
See [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests) for mapping configuration, including `affects`.

## Dockerfile formats {#dockerfile-formats}

For Dockerfiles, KestreLynx identifies the external image used by the selected build stage as the base image and edits the pinned tag in its `FROM`.
The table shows declarations that allow KestreLynx to identify the target `FROM` and Dockerfile location.

| Location to check | Conditions and scope |
| --- | --- |
| A pinned tag in `FROM` | It has no variables or digest, and its position can be identified |
| Build `target` | The stage with the specified name is used |
| Omitted `target` | The last stage is used |
| A `FROM` naming an earlier stage | The references can be followed to a `FROM` naming an external base image |
| `--platform` on a `FROM` naming an external image | A static value can be specified |
| Compose build context | A static path inside the repository can be specified |
| Compose `dockerfile` | Use a path relative to the build context, such as `docker/Dockerfile`, to specify a file inside the repository |
| Compose `target` | Use a stage name such as `runtime`, starting with a letter and containing at most 128 letters, digits, `_`, `.`, or `-` |

Specify Compose `dockerfile` and `target` as non-empty strings without variables, explicit YAML tags, or aliases.
Leading or trailing whitespace and control characters are also rejected.

For `dockerfile`, absolute paths, paths starting with `~`, paths containing `\`, and paths that leave the repository are rejected.

The following declarations prevent automatic updates and require manual action.

| Declaration | Reason code |
| --- | --- |
| A variable in an image name in a `FROM` between the target stage and its base | `dockerfile_variable` |
| A variable in `--platform` in a `FROM` between the target stage and its base | `dockerfile_variable` |
| `--platform` on a `FROM` naming an earlier stage | `dockerfile_stage_platform` |
| A nonstandard syntax frontend | `dockerfile_frontend` |
| An `escape` directive | `dockerfile_escape` |
| `ONBUILD` in an inherited stage | `dockerfile_onbuild` |
| `ONBUILD` in the base image | `base_onbuild` |

The following declarations cannot be used to derive the Dockerfile edit location from Compose.

| Declaration | Reason code |
| --- | --- |
| A remote build context | `compose_build_remote_context` |
| `dockerfile_inline` | `compose_build_inline` |
| `additional_contexts` | `compose_build_additional` |

The following base declarations are excluded from automatic editing.

| Declaration | Reason code |
| --- | --- |
| `FROM scratch` | `dockerfile_scratch` |
| An image name containing a digest in `FROM` | `dockerfile_digest` |

For floating tags, KestreLynx compares the layers of the base currently referenced by the tag with those of the running image and, depending on the result, provides guidance to fetch the base again and rebuild.
It does not create a tag-update PR for a floating tag; see [Matching base layers](remediation-base-image-logic.md#base-layer-matching) for the checks and conditions for that guidance.

The following editable example places a static `--platform` on the `FROM` that names the external image.

```dockerfile
FROM --platform=linux/amd64 python:3.12.3-slim AS base
FROM base AS app
```

The following example requires manual action because `--platform` is on the `FROM` that names the earlier `base` stage.

```dockerfile
FROM python:3.12.3-slim AS base
FROM --platform=linux/amd64 base AS app
```

See [Identifying the base image](remediation-base-image-logic.md#base-image-selection) for selecting the edit location and checking mappings.
