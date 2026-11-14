---
title: Conditions for Kubernetes tag update pull requests
---

# Conditions for Kubernetes tag update pull requests

This page explains when KestreLynx creates tag update PRs for Kubernetes manifests, Kustomize, and Helm values, and which PRs it skips when checks fail.
For how candidate tags are chosen, see [Image candidate selection](remediation-image-logic.md#image-selection).

For the terms used on this page, see [Terms](remediation.md#terms).

## Kubernetes image references and pulling images again {#kubernetes-image-references}

KestreLynx checks whether the image reference in the Pod spec matches the reference of the running image.
It does this before looking for candidates for a published image.

It normalizes abbreviated repository names and compares tags and digests.
The running image reference normally comes from the Pod's `status.containerStatuses[].image`.

With containerd, `image` can be the image config ID (`sha256:…`) when the node holds the image without a tag.
This can happen, for example, after pulling an image specified only by digest.

When `image` is a config ID, KestreLynx uses the same container's `imageID` to choose the running image reference.

| Contents of `imageID` | Value used as the running image reference |
| --- | --- |
| A reference containing a repository and digest, such as `ghcr.io/example/app@sha256:…` | The repository and digest from `imageID` |
| A value without a repository | The original `image` value |

Using the repository and digest avoids displaying only the config ID in the notification's image field.
It also allows comparison with a digest reference in the Pod spec.

KestreLynx groups the running containers it observed by their running image reference.
The group includes containers from different Pods or workloads, and each container's spec reference is compared with its running image reference.

If any comparison fails, plan items for that image reference are marked not comparable (`not_comparable`), with reason `declared_ref_mismatch`.
If a spec image reference cannot be read, the items are also not comparable, with reason `declared_ref_unavailable`.

When new content under a floating tag improves the scan results, KestreLynx provides the following guidance based on `imagePullPolicy`.
The table's `pull[].guidance` field contains the pull guidance for each image item in the webhook's `remediation.items[]`.

| `imagePullPolicy` | `pull[].guidance` | Guidance |
| --- | --- | --- |
| `Always` | `restart_pulls` | Restarting the Pod pulls the new content |
| `IfNotPresent` | `change_tag_or_digest` | The node reuses its local content, so a fixed tag or digest is required |
| `Never` | `import_to_node` | The image must be imported onto the node |

## Kubernetes manifest PRs {#kubernetes-manifest-prs}

A manifest PR is created after checking that the Pod spec, running image, and file being edited name the same image, and that all update targets can adopt the same candidate.
These checks use the mappings in `remediation.mappings`.

KestreLynx checks every mapping that points to the same repository, base branch, and manifest file.
Creating a PR requires the following conditions.

- Each mapped container has running Pods, and all running image references can be obtained
- Each container's spec image reference matches its running image reference
- Across the Pods of the same workload, running containers with the mapped container name share one image reference
- Every target updating the same image in the same file has a plan item and can adopt a candidate with the same tag and digest
- The image reference being edited in the file matches both the Pod spec reference and the running image reference

For example, KestreLynx compares the `app` containers across the Pods of Deployment `web`.
Mixed versions of `app` during a rolling update fail this check.

The check does not require application containers and sidecars with different names to use the same image reference.

For example, the Pod spec, running image, and `apps/web.yaml` all name `nginx:1.27.2`.
If `1.27.3` in the same series can be adopted, KestreLynx creates a PR that changes only the tag in the file.

The following fictional example places three Deployments, `web`, `worker`, and `api`, in `apps/web.yaml` and maps each one's `app` container.
It compares which containers are checked, which are updated, and which PRs are skipped if a check fails.

| Container | Image used | Checks | Change | If a check fails |
| --- | --- | --- | --- | --- |
| `web/app` | `nginx:1.27.2` | Running state and the `1.27.3` candidate | Tag update to `1.27.3` | All PRs for the file are skipped |
| `worker/app` | `nginx:1.27.2` | Running state and the `1.27.3` candidate | Tag update to `1.27.3` | All PRs for the file are skipped |
| `api/app` | A different image with nothing to fix | Running state | No change | All PRs for the file are skipped |

Because `web/app` and `worker/app` are targets for the same image update, each needs a plan item and the same candidate.
The `api/app` container is excluded from the update and does not block other PRs merely because it has nothing to fix.

Even though `api/app` is not updated, it must have instances with status `running`, and all their running image references must be available.
The `api/app` instances across the Pods must share one image reference that also matches their spec references.

If any running-state or candidate condition fails, KestreLynx skips every PR targeting that manifest file.

If multiple mappings point to the same container in the same document within a file, they are treated as conflicting mappings, with reason `mapping_conflict`.
KestreLynx marks the update for manual handling (`manual`, shown as “Needs a decision” in Slack).

The overlap check also runs before editing when workloads from different namespaces are mapped to a document that omits its namespace.

KestreLynx selects targets for the same image update from containers mapped to that manifest.
Unmapped containers are left unchanged even when they use the same image in the same Pod template.

The following fictional example shows the update scope when `app` and `log` in the same Pod template use the same image.
If only `app` is mapped, only `app` is updated, and `log` is listed as unchanged in the PR body.

See [Source mappings](configuration.md#remediation-mappings) for configuration and [Manifest formats](remediation-source-formats.md#manifest-formats) for file restrictions.

## Kustomize and Helm values PRs {#kustomize-and-helm-prs}

Kustomize and Helm values PRs are created after checking the containers affected by a tag change together and confirming that all can adopt the same candidate.
The checks cover the container in the mapping's `workload` and the other affected containers listed in `affects`.

The following Kustomize mapping shows the relationship between `workload` and `affects`.
For Helm, the same two additional containers are listed in `helm_values.affects`.

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      kustomize:
        path: apps/kustomization.yaml
        image: nginx
        affects:
          - deployment/example/worker/app
          - deployment/example/web/prepare
```

The workload key `deployment/example/web/app` identifies container `app` in Deployment `web` in namespace `example`.
The example checks `web/app`, `worker/app`, and `web/prepare`, where `prepare` is an ordinary init container in `web`.

KestreLynx checks the following conditions across all listed containers.

- Each container can be verified in the observed Pods, and its spec image reference matches its running image reference
- All listed containers share one current image reference
- Every target can adopt a candidate with the same tag and digest

For an ordinary init container, KestreLynx reads the image it used from the Pod status and compares it with a listed running container in the same Pod.
The following references and content must match.

| Check | Values that must match |
| --- | --- |
| Image reference | The references in the init container's spec and status, and the running container's reference |
| Image content | The content of the image used by the init container and that of the running container's image |

Once the references and content match, KestreLynx uses the compared running container's scan results to check the init container.

No PR is created if the status, image content, image reference, or an available scan result cannot be verified.
The reason is `init_container_unverified` or another applicable reason.

The user must confirm that `workload` and `affects` list every container affected by the tag change.
KestreLynx relies on that confirmation and also checks the observed information for omissions.

KestreLynx looks for unlisted containers that declare the same image reference as the listed containers.
If one is found within the following scope, PR creation stops with reason `undeclared_affected_workload`.

- Running containers that share a namespace, Helm release, or Flux Kustomization with a listed workload
- Containers in the Pod definitions of listed workloads, including waiting containers, native sidecars, and ordinary init containers

If `worker/app` is omitted from the example while declaring the same image reference, it is detected as a running container in the same namespace, `example`.
If `web/prepare` is omitted, it is detected from the Pod definition for `web`.

If a running-state check fails for a mapping of a file, every PR targeting that file is skipped.
If the containers being updated fail candidate or omission checks, every PR for the same file is also skipped.

See [Kubernetes mappings](configuration.md#remediation-mappings-kubernetes) for configuration details, and [Configure Kustomize PRs](remediation-setup-kubernetes.md#kustomize-pull-requests) and [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests) for examples.

### Kustomize PRs {#kustomize-prs}

For Kustomize, KestreLynx checks the image reference produced by the selected `images` entry to determine whether its `newTag` can be updated.
In the example, `images[nginx].newTag` is updated when `web/app`, `worker/app`, and `web/prepare` meet the shared conditions.

The image reference is built from `name` (or an existing `newName`) and `newTag`.
It must match both the Pod spec image reference and the running image reference.

KestreLynx does not build the Kustomize configuration.
For restrictions on editable files, see [Kustomize formats](remediation-source-formats.md#kustomize-formats).

### Helm values PRs {#helm-values-prs}

For Helm values, KestreLynx checks the image reference obtained from the selected key to determine whether its tag can be updated.
In the example in [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests), `image.tag` is updated when `web/app`, `worker/app`, and `web/prepare` meet the shared conditions.

Depending on how the values are written, KestreLynx compares the following reference with both the Pod spec image reference and the running image reference.

- The image reference formed from the combined `registry` and `repository`, plus `tag`
- The image reference specified as a string

KestreLynx does not render Helm charts.
The user must confirm that other settings do not override the selected key and that changing it changes the image reference actually used.

For example, if another values file or CI's `--set` overrides the tag, changing the selected key does not change the image reference actually used.
KestreLynx does not check the following overrides.

- Flux HelmRelease `spec.values`
- Argo CD `parameters`, `valuesObject`, and `valuesFrom`
- CI's `--set`
- Other values files

The PR body states the assumptions that the value is not overridden and that all affected containers are listed, along with the scope KestreLynx checked.
It also states that KestreLynx has not verified the absence of tag management by other tools.

Detectable Flux `$imagepolicy` comments and Argo CD Image Updater write-back files are checked as described in [Helm values formats](remediation-source-formats.md#helm-values-formats).
