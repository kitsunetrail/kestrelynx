---
title: Preparing Kubernetes language-package updates
---

# Preparing Kubernetes language-package updates

## Preparing work Pods {#kubernetes-language-updates}

KestreLynx runs npm, pnpm, pip, uv, Go, and Gradle updates in disposable work Pods that it creates in a namespace you prepare.

Maven updates use KestreLynx to edit `pom.xml` and Trivy to scan it, so they do not require work Pod setup.

First, follow [Preparing GitHub access](remediation-setup.md#prepare-github-access) to configure a GitHub token with the permissions required for remediation PRs.
Follow [Mapping the source](remediation-setup.md#map-source) to set `dependencies.directory` in the target entry in `remediation.mappings`.

Prepare work Pods in this order.

1. Check the [requirements](#work-pod-requirements)
2. Edit the files following [Preparing the manifests](#work-pod-manifests)
3. Run the commands in [Applying the manifests](#work-pod-apply)
4. Follow [Configuration](#work-pod-config) to configure the work namespace and mappings, then return to the Kubernetes page

See [Terms](index.md#terms) for the terminology used on this page.

### Requirements {#work-pod-requirements}

Check that the cluster and nodes running work Pods meet these requirements.

| Requirement | Required value or state |
| --- | --- |
| Kubernetes version | `1.30` or later |
| KestreLynx configuration | `kubernetes.enabled: true` |
| Node log storage settings | kubelet `containerLogMaxSize` of at least `144Mi` on every node that runs work Pods |
| Node process limits | A PID limit restricting the number of processes per Pod on every node that runs work Pods |
| Networking | A CNI that enforces NetworkPolicy |

At least `144Mi` is needed because the largest result log is about 94.56 MiB through the API and about 143.69 MiB when stored on a node.
KestreLynx rejects results that are incomplete because the log was truncated or rotated.

### Preparing the manifests {#work-pod-manifests}

Adjust the names, allowed images, and network destinations for work Pods in the supplied manifests.

1. Go to the root of the KestreLynx repository containing `deploy/kubernetes/work/`

    If you do not have a local copy, obtain it and enter the directory with these commands.

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. Edit the files in `deploy/kubernetes/work/` using the following tables

All filenames in the tables are relative to `deploy/kubernetes/work/`.

In the supplied manifests, the work namespace, work ServiceAccount, and PriorityClass are all named `kestrelynx-work`.

For any name you keep as `kestrelynx-work`, you do not need to edit the keys in the table for that name.
If you change a name, set all keys in the table for the name you are changing to the same new name.

The following table lists the keys to change when renaming the work namespace.

| File | Keys |
| --- | --- |
| `00-namespace.yaml` | Namespace `metadata.name`, ServiceAccount `metadata.namespace` |
| `10-rbac.yaml` | Role and RoleBinding `metadata.namespace` |
| `30-resourcequota.yaml` | `metadata.namespace` |
| `40-networkpolicy.yaml` | `metadata.namespace` |
| `51-validatingadmissionpolicybinding.yaml` | `spec.paramRef.namespace`, `spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"]` |
| `52-policy-params.yaml` | `metadata.namespace` |

The following table lists the keys to change when renaming the work ServiceAccount.

| File | Keys |
| --- | --- |
| `00-namespace.yaml` | ServiceAccount `metadata.name` |
| `52-policy-params.yaml` | `data.serviceAccount` |

The following table lists the keys to change when renaming the PriorityClass.

| File | Keys |
| --- | --- |
| `20-priorityclass.yaml` | `metadata.name` |
| `52-policy-params.yaml` | `data.priorityClass` |

Even when renaming resources, do not change `metadata.name` in `50-validatingadmissionpolicy.yaml` or `51-validatingadmissionpolicybinding.yaml` from `kestrelynx-work`.

Before creating work Pods, KestreLynx checks that the Pod creation policy named `kestrelynx-work` is enforced.
Changing `metadata.name` prevents KestreLynx from confirming that the Pod creation policy is enforced, so language-package updates that use work Pods require manual handling (`work_admission_unverified`).

Do not change `preemptionPolicy: Never` in `20-priorityclass.yaml` either.
Changing `preemptionPolicy` makes language-package updates that use work Pods require manual handling (`work_priority_class_missing`).

In the three tables with a "Value in supplied manifests" column, edit the listed keys only for items whose values in the supplied manifests differ from your installation.

In `10-rbac.yaml`, align the KestreLynx ServiceAccount name and namespace with your installation.

| Value to align | Keys | Value in supplied manifests |
| --- | --- | --- |
| KestreLynx ServiceAccount name and namespace | RoleBinding `subjects[0].name` and `subjects[0].namespace` | Name and namespace: `kestrelynx` |

In `52-policy-params.yaml`, align the image repositories and architecture with your installation.

| Value to align | Keys | Value in supplied manifests |
| --- | --- | --- |
| KestreLynx image repository for receiving input files | `data.receiverRepository` | `ghcr.io/kitsunetrail/kestrelynx` |
| Work image repositories | `data.workRepositories` | `node`, `python`, `golang`, and `gradle` under `docker.io/library/` |
| Architecture of the KestreLynx Pod and execution nodes | `data.arch` | `amd64` |

Set `workRepositories` to a list of image repository names allowed for work Pods, specified as a single string separated by commas without spaces.
Include the registry hostname in repository names, but omit tags and digests.

You can remove repositories for languages you do not update from `workRepositories`.
The following table lists the language packages to update and the required repository names in the supplied manifests.

| Language packages to update | Required repository |
| --- | --- |
| npm and pnpm | `docker.io/library/node` |
| pip and uv | `docker.io/library/python` |
| Go | `docker.io/library/golang` |
| Gradle | `docker.io/library/gradle` |

If you configure a mirror with `remediation.worker.registry`, align all repositories listed in `workRepositories` with their download locations in the mirror.

If the image repository used for an update is absent from `workRepositories`, that update fails (`update_job_failed`).
The failure details show the repository name that needs to be added.

If none of the repositories in `workRepositories` match any of KestreLynx's work images, all language-package updates that use work Pods require manual handling (`work_admission_unverified`).

In `40-networkpolicy.yaml`, align the NetworkPolicy DNS selectors and outbound TCP 443 address ranges with your installation.

| Value to align | Keys | Value in supplied manifests |
| --- | --- | --- |
| NetworkPolicy DNS selectors | `spec.egress[0].to[0].namespaceSelector.matchLabels` and `spec.egress[0].to[0].podSelector.matchLabels` | `kubernetes.io/metadata.name: kube-system`, `k8s-app: kube-dns` |
| Address range allowed for outbound TCP 443 | `spec.egress[1].to[0].ipBlock.cidr` | `0.0.0.0/0` |
| Address ranges excluded from outbound TCP 443 | `spec.egress[1].to[0].ipBlock.except` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10` |

The supplied example allows outbound TCP 443 to destinations in `cidr: 0.0.0.0/0`, excluding the ranges in `except`.
Include the cluster's Pod, Service, and node address ranges in the exclusions in `except`.

See [Work containers](configuration.md#remediation-worker) for image source settings and [Work container network](outbound-communication.md#worker-network) for the scope of network restrictions.

### Applying the manifests {#work-pod-apply}

Apply the prepared manifests to create the work namespace, its restrictions, and additional permissions for KestreLynx.

Run these commands in order from the root of the KestreLynx repository.
They apply the namespace, restrictions, policy parameters, policy and binding, and permissions in that order.

```sh
kubectl apply -f deploy/kubernetes/work/00-namespace.yaml
kubectl apply -f deploy/kubernetes/work/20-priorityclass.yaml
kubectl apply -f deploy/kubernetes/work/30-resourcequota.yaml
kubectl apply -f deploy/kubernetes/work/40-networkpolicy.yaml
kubectl apply -f deploy/kubernetes/work/52-policy-params.yaml
kubectl apply -f deploy/kubernetes/work/50-validatingadmissionpolicy.yaml
kubectl apply -f deploy/kubernetes/work/51-validatingadmissionpolicybinding.yaml
kubectl apply -f deploy/kubernetes/work/10-rbac.yaml
```

The work namespace enforces the Pod Security `restricted` profile, and the work ServiceAccount has no permissions or token.
The supplied ResourceQuota limits the Pod count to 8 and also limits CPU, memory, and ephemeral storage.

Applying the Role and RoleBinding grants KestreLynx the following additional permissions only in the work namespace.

| Resource | Additional operations |
| --- | --- |
| `pods` | `create`, `get`, `list`, `delete` |
| `pods/attach` | `create` and `get` for connections that send input files to the receiving container's standard input |
| `pods/log` | `get` to collect encrypted results |

The scanning ClusterRole is read-only, and no permissions to operate on other resources, including Secrets, are added.
See [work Pod execution](remediation-worker-logic.md#kubernetes-work-pods) for Pod safeguards and execution conditions.

### Configuration {#work-pod-config}

In the KestreLynx configuration, set `remediation.worker.kubernetes.namespace` to the work namespace and map the update targets.

1. Merge the following YAML into the existing configuration in `data.config.yml` in `deploy/kubernetes/configmap.yaml`

    Preserve the existing GitHub token and `remediation.mappings`.
    If you manage configuration in a Secret, edit the `config.yml` used to create that Secret.

    In the example, set `namespace` to the work namespace you applied, and adjust `workload` and `repository` to the update target.

    ```yaml
    kubernetes:
      enabled: true
    remediation:
      enabled: true
      pull_requests:
        enabled: true
      worker:
        kubernetes:
          namespace: kestrelynx-work
      mappings:
        - workload: deployment/example/api/app
          repository: example/application
          base_branch: main
          dependencies:
            directory: .
    ```

    If you changed the work ServiceAccount or PriorityClass name, align `remediation.worker.kubernetes.service_account` and `remediation.worker.kubernetes.priority_class` in the same `config.yml`.
    See [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) for configuration defaults and constraints.

2. Return to [Enable and apply PR creation](remediation-setup-kubernetes.md#kubernetes-enable-pr-creation) on the Kubernetes page to enable PR creation, apply the configuration, and verify startup and processing results
