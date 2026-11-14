---
title: Enabling remediation plans and pull requests on Kubernetes
---

# Enabling remediation plans and pull requests on Kubernetes

Use this procedure to check remediation plans and then enable remediation pull requests in KestreLynx running on Kubernetes.
Complete the [shared preparation](remediation-setup.md#enable-fix-plans) first (GitHub access, source mappings, and private image authentication if needed), then configure plans, verify startup, configure pull requests, and [enable and apply PR creation](#kubernetes-enable-pr-creation).

See [Terms](remediation.md#terms) for the terminology used on this page.

## Configure remediation plans {#kubernetes-plans}

Choose what remediation plans will examine.

1. Merge the following minimal configuration into the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml`

    To examine candidates only for published images, you can start with this configuration alone.
    If you store configuration in a Secret, edit the `config.yml` used to create that Secret.

    ```yaml
    remediation:
      enabled: true
    ```

    Merge into the existing `remediation` section without duplicating it, and keep PR creation at `remediation.pull_requests.enabled: false` (the default).

2. Add mappings to also examine language packages or base images

    This example specifies language packages and a base image in the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret).

    ```yaml
    remediation:
      mappings:
        - workload: deployment/example/web/app
          repository: example/application
          base_branch: main
          dependencies:
            directory: .
          dockerfile:
            path: docker/Dockerfile
    ```

    Omit `dependencies` or `dockerfile` if you do not want to examine that target.
    See [Mapping the source](remediation-setup.md#map-source) for choosing keys and preparing dependency directories.

Use the workload key shown in notifications for `workload`.
In `deployment/example/web/app`, `deployment` is the kind, `example` is the namespace, `web` is the workload name, and `app` is the container name.

See [Kubernetes mappings](configuration.md#remediation-mappings-kubernetes) for key constraints and [Basic settings](configuration.md#remediation-basics) for enablement settings.

Remediation plans additionally LIST `deployments`, `statefulsets`, `daemonsets`, and `cronjobs`, but the provided read-only ClusterRole needs no additional permissions.

## Verify remediation plan startup {#kubernetes-verify-plans}

Apply the edited configuration and verify that remediation plans run.

1. Verify that you have merged the [remediation plan settings](#kubernetes-plans) into the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret)

2. From the repository root, apply the ConfigMap and restart the KestreLynx Pod

    For a Secret, replace the first command that applies the ConfigMap with the Secret update procedure in [Authenticate to private registries inside the cluster](getting-started.md#kubernetes-private-registry).

    ```sh
    kubectl apply -f deploy/kubernetes/configmap.yaml
    kubectl rollout restart -n kestrelynx deployment/kestrelynx
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    ```

3. Run the following command to check configuration loading and remediation plan results

    ```sh
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    Check the following log messages and values to verify enablement and plan creation.

    | What to verify | Log message | Values to check |
    | --- | --- | --- |
    | Remediation plans enabled | `fix plan enabled` | `pull_requests=false` |
    | Plan created | `fix plan built` | Item counts: `items`, `dependency_units`, and `dockerfile_items` |
    | Update candidate counts | `fix plan built` | `update_candidate`, `dependency_update_candidates`, and `dockerfile_update_candidates` |

    Zero plan items or update candidates do not mean that enablement failed.

    At the scan after startup or the next scheduled scan, check that the notification shows the intended workloads, sources, and update targets.
    See [Displayed fields](remediation-results.md#slack-fields) for display meanings, or [Check for missing plans](remediation-troubleshooting.md#check-missing-plan) if no plan appears.

## Configure remediation pull requests {#kubernetes-enable-pull-requests}

Specify the files that remediation pull requests will update.
Complete [remediation plan startup verification](#kubernetes-verify-plans), then follow these steps.

1. Configure mappings for what you want to update using the sections on this page
2. For npm, pnpm, pip, uv, Go, or Gradle package updates, follow [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) through configuring the work namespace and mappings, then return to this page (not needed for Maven alone)
3. [Enable and apply PR creation](#kubernetes-enable-pr-creation), then verify startup and processing results

Use the update target to choose the configuration key and procedure.

| What to update | Configuration key | Procedure |
| --- | --- | --- |
| Manifest image tags | `manifest` | [Configure PRs for manifests and Dockerfiles](#kubernetes-pull-requests) |
| Kustomize image tags | `kustomize` | [Configure Kustomize PRs](#kustomize-pull-requests) |
| Image tags in Helm values | `helm_values` | [Configure Helm values PRs](#helm-values-pull-requests) |
| Dockerfile base images | `dockerfile` | [Configure PRs for manifests and Dockerfiles](#kubernetes-pull-requests) |
| Language packages | `dependencies` | [Mapping the source](remediation-setup.md#map-source) and [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |

Specify only one of `manifest`, `kustomize`, and `helm_values` for a container's image tag.
Language package updates, except Maven updates, require work Pods.

### Configure PRs for manifests and Dockerfiles {#kubernetes-pull-requests}

Specify where to update manifest image tags and Dockerfile base images.

Edit `remediation.mappings` in the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret).
This example updates the tag for `web/app` in `apps/web.yaml` and the base image for `api/app` in `docker/Dockerfile`.

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/deployment
      base_branch: main
      manifest:
        path: apps/web.yaml
    - workload: deployment/example/api/app
      repository: example/application
      base_branch: main
      dockerfile:
        path: docker/Dockerfile
        target: runtime
```

The `runtime` in `target: runtime` is the stage name assigned by `FROM ... AS runtime` in `docker/Dockerfile`.
Replace it with the stage name used to build the target image, or omit `target` when using the last stage.

To also update language packages, npm, pnpm, pip, uv, Go, and Gradle require [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates).
See [Manifest formats](remediation-source-formats.md#manifest-formats) for editable formats and [Kubernetes manifest PRs](remediation-kubernetes-logic.md#kubernetes-manifest-prs) for PR creation conditions.

### Configure Kustomize PRs {#kustomize-pull-requests}

Specify where to update tags managed by Kustomize `images` and which containers a tag change affects.
Because a container's image tag must have only one source, replace any existing `manifest` or `helm_values` setting with `kustomize`.

1. Check the `images` entry to update in `apps/kustomization.yaml` in the target repository

    This example file manages the tag for `nginx`.

    ```yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization
    resources:
      - web.yaml
      - worker.yaml
    images:
      - name: nginx
        newTag: "1.27.2" # Tag to use
    ```

2. Edit `remediation.mappings` in the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret)

    In this example, the `app` containers in `web` and `worker`, and the regular init container `prepare` in `web`, use the same `images` entry.

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

    For a regular init container, the Pod status must show that its image reference and content match those of a listed running container in the same Pod.
    The scan result for that running container is also required.

    For detailed checks when these conditions cannot be verified, see [Checking for a missing PR](remediation-troubleshooting.md#check-missing-pr).

    Set `image` to `images[].name`.
    For `workload`, choose any one container whose tag is set by that `images` entry.

    List every other container in `affects`, including regular init containers.
    The containers in the example are listed as follows.

    | Container | Where to specify it |
    | --- | --- |
    | `deployment/example/web/app` | `workload` |
    | `deployment/example/worker/app` | `kustomize.affects` |
    | `deployment/example/web/prepare` (regular init container) | `kustomize.affects` |

3. Verify that `workload` and `affects` list every container affected by the tag change, including regular init containers

    You must verify this because KestreLynx does not render Kustomize.
    Omit `affects` only if you have verified that the container in `workload` is the only one affected.

See [Kubernetes mappings](configuration.md#remediation-mappings-kubernetes) for configuration constraints, [Kustomize formats](remediation-source-formats.md#kustomize-formats) for file formats, and [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs) for PR creation conditions.

### Configure Helm values PRs {#helm-values-pull-requests}

Specify where to update tags managed by Helm values and which containers a tag change affects.
Because a container's image tag must have only one source, replace any existing `manifest` or `kustomize` setting with `helm_values`.

1. Check the YAML key that specifies the image in `apps/values.yaml` in the target repository

    This example file specifies the image under the `image` key.

    ```yaml
    image:
      registry: docker.io
      repository: library/nginx
      tag: "1.27.2" # Tag to use
    ```

    Set `helm_values.key` to the path to the key containing `repository` and `tag`, rather than to `tag` itself.
    `registry` is optional, and `key: image` also works with a string such as `image: "nginx:1.27.2"`.

    If `apps/values.yaml` uses a nested structure such as `app: {image: "nginx:1.27.2"}`, set `helm_values.key` to `app.image`.

2. Edit `remediation.mappings` in the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret)

    In this configuration, the `app` containers in `web` and `worker`, and the regular init container `prepare` in `web`, use the `image` key from the first example.

    ```yaml
    remediation:
      mappings:
        - workload: deployment/example/web/app
          repository: example/deployment
          base_branch: main
          helm_values:
            path: apps/values.yaml
            key: image
            affects:
              - deployment/example/worker/app
              - deployment/example/web/prepare
    ```

    For a regular init container, the Pod status must show that its image reference and content match those of a listed running container in the same Pod.
    The scan result for that running container is also required.

    For detailed checks when these conditions cannot be verified, see [Checking for a missing PR](remediation-troubleshooting.md#check-missing-pr).

    For `workload`, choose any one container whose tag is set by that values key.
    List the rest in `affects`, including regular init containers.

    | Container | Where to specify it |
    | --- | --- |
    | `deployment/example/web/app` | `workload` |
    | `deployment/example/worker/app` | `helm_values.affects` |
    | `deployment/example/web/prepare` (regular init container) | `helm_values.affects` |

3. Verify that `workload` and `affects` list every container affected by the tag change, including regular init containers

    Omit `affects` only if you have verified that the container in `workload` is the only one affected.

4. Verify that the specified key provides the final image value and is not overridden by other settings

    KestreLynx does not render Helm, so check the following sources of overrides.

    - Flux HelmRelease `spec.values`
    - Argo CD `parameters`, `valuesObject`, and `valuesFrom`
    - CI `--set` options or other values files

See [Kubernetes mappings](configuration.md#remediation-mappings-kubernetes) for configuration constraints, [Helm values formats](remediation-source-formats.md#helm-values-formats) for file formats, and [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) for PR creation conditions.

### Enable and apply PR creation {#kubernetes-enable-pr-creation}

Enable PR creation for the configured update targets and apply the settings to KestreLynx.
First review token permissions and common considerations in [PR creation prerequisites and cautions](remediation-setup.md#enable-pr-creation).
For the storage location, check [`remediation.storage_dir` in Basic settings](configuration.md#remediation-basics).

1. Preserve existing mappings, GitHub tokens, credentials, and storage settings, and merge the following into the `config.yml` entry under `data` in `deploy/kubernetes/configmap.yaml` (or `config.yml` for a Secret)

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: true
    ```

    Manifest, Dockerfile, Kustomize, and Helm values updates use only the read-only RBAC permissions for scanning.

2. From the repository root, apply the ConfigMap and restart the KestreLynx Pod

    For a Secret, replace the first command that applies the ConfigMap with the Secret update procedure in [Authenticate to private registries inside the cluster](getting-started.md#kubernetes-private-registry).

    ```sh
    kubectl apply -f deploy/kubernetes/configmap.yaml
    kubectl rollout restart -n kestrelynx deployment/kestrelynx
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    ```

3. Run the following command to verify that PR creation is enabled and check its results

    ```sh
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    Check the following log messages and values to verify PR creation enablement and processing results.

    | What to verify | Log message | Values to check |
    | --- | --- | --- |
    | PR creation enabled | `fix plan enabled` | `pull_requests=true` |
    | PR processing results | `pull request stage finished` | `created` for the number created and `problems` for the number of stage-wide problems |

    If no PR is created, see [Check for missing PRs](remediation-troubleshooting.md#check-missing-pr).
