---
title: Enabling remediation plans and pull requests
---

# Enabling remediation plans and pull requests

First enable remediation plans and check the notifications, then enable remediation pull requests.
Use this page for preparation shared across environments, then follow the environment-specific pages to apply the configuration and verify startup.

See [Overview](remediation.md#overview) for an overview and [Scope and requirements](remediation-reference.md#scope-and-requirements) for supported environments and inputs.
See [Communication destinations](outbound-communication.md#outbound-communication) for required destinations.

See [Terms](remediation.md#terms) for the terminology used on this page.

## Enabling remediation plans {#enable-fix-plans}

Enabling remediation plans starts with shared preparation and continues with startup verification for your environment.

If you only want to check candidates for published images, skip preparing GitHub repositories, tokens, and mappings, and start at step 3.
If you also want to check base images or language packages, start at step 1.

Follow these steps in order.

1. [Prepare GitHub access](#prepare-github-access) by choosing the repositories and obtaining any required tokens
2. Use [Mapping the source](#map-source) to choose configuration keys and file locations for the update targets
3. If you use private images, [configure registry authentication](#configure-registry-auth)
4. Follow the page for the environment being monitored to edit and apply the required configuration and verify startup and notifications

Choose the next page based on the environment being monitored.

| Environment being monitored | Next page |
| --- | --- |
| Compose or docker run | [Enabling remediation plans and pull requests on Docker](remediation-setup-docker.md) |
| Kubernetes | [Configure remediation plans](remediation-setup-kubernetes.md#kubernetes-plans) |

Choose the configuration location and how to apply changes based on how KestreLynx itself runs.
For the provided deployments, edit the following configuration.

| How KestreLynx runs | File or configuration location to edit | How to apply changes |
| --- | --- | --- |
| Compose | `config.yml` in the deployment directory | Recreate the container |
| docker run | The host's `config.yml` mounted at `/etc/kestrelynx/config.yml` | Recreate the container |
| Inside a Kubernetes cluster | `data.config.yml` in `deploy/kubernetes/configmap.yaml` | Apply the ConfigMap and restart the Pod |

If you manage configuration in a Secret, edit the `config.yml` used to create that Secret.
Apply changes using the Secret update procedure in [Authenticate to private registries inside the cluster](getting-started.md#kubernetes-private-registry).

Merge the examples below into the existing `config.yml` you are editing.
Do not add duplicate `remediation` sections to the same file.

In the provided Compose deployment, plan and PR processing records are stored in the state volume.
If you change `remediation.storage_dir`, choose a location that survives container recreation (see [Basic settings](configuration.md#remediation-basics)).

### Preparing GitHub access {#prepare-github-access}

Preparing GitHub access means choosing where to read source files, where to target PRs, and which tokens are needed.
Check token requirements and permissions for your intended use.

| What you want to do | Token |
| --- | --- |
| Read source files from public repositories to create plans only | Not required |
| Read source files from private repositories to create plans only | Contents: Read |
| Create and manage remediation PRs in public or private repositories | Contents and Pull requests: Read and write |

Prepare the repositories and tokens in the following order.

1. Choose the GitHub repositories and the branch used both to read source files and to target PRs
2. If a token is required, obtain a fine-grained token limited to the target repositories
3. Set the default `remediation.github.token` or per-owner `remediation.github.tokens` in the `config.yml` you are editing
4. Make configuration files containing tokens readable only by their owner and exclude them from repository commits

If the target repositories have multiple owners, obtain a token for each owner.
A fine-grained token can grant access to repositories belonging to only one owner (a user or organization).

For `example-org/application` and `example-user/deployment`, merge the following settings into `remediation.github.tokens` in `config.yml`.
Replace the example tokens with tokens that have access to the target repositories of each owner.

```yaml
remediation:
  github:
    tokens:
      - owner: example-org
        token: example-token-for-org
      - owner: example-user
        token: example-token-for-user
```

Owners not listed in `tokens` use the default `remediation.github.token`.
You can configure only `token`, or omit the default token if you list every owner in `tokens`.

When PR creation is disabled and neither a per-owner token nor a default token is available, public repositories are read anonymously.
See [GitHub access](configuration.md#remediation-github) for configuration details.

### Mapping the source {#map-source}

Choose the configuration key based on what you want to update and the environment being monitored.

| What you want to update | Configuration key | Supported environments |
| --- | --- | --- |
| Image tags in a Compose file | `compose` | Compose |
| Image tags in Kubernetes manifests | `manifest` | Kubernetes |
| Tags in Kustomize `images` entries | `kustomize` | Kubernetes |
| Image tags in Helm values | `helm_values` | Kubernetes |
| Dockerfile base images | `dockerfile` | Compose, docker run, Kubernetes |
| Language packages | `dependencies` | Compose, docker run, Kubernetes |

Use this page to choose configuration keys and file locations for the update targets.
Follow the page for your environment to edit `remediation.mappings` and enable remediation plans.

Both `path` and `directory` are relative to the GitHub repository root.
For example, `path: compose.yml` refers to `compose.yml` at the repository root.

For Maven or Gradle, set `dependencies.directory` to the following directory.

| Package manager | Directory to specify in `dependencies.directory` |
| --- | --- |
| Maven | The directory containing `pom.xml` |
| Gradle | The directory containing `gradle.lockfile`, the build script, and settings |

For a Maven multi-module project, specify the directory of the root `pom.xml` whose `modules` entries lead to each module.
If `pom.xml` is at the repository root, specify `.`.

Check [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) for locking configuration and required files.
See [Source mappings](configuration.md#remediation-mappings) for constraints on multiple mappings and [Basic settings](configuration.md#remediation-basics) for the enablement keys.

### Configuring private image authentication {#configure-registry-auth}

Private image authentication provides credentials for reading images during remediation planning and regular scans.
This configuration is unnecessary if you use only public images.

If authentication is required, edit `config.yml` in the following order.

1. Obtain credentials that can read the target images
2. Add `registries` for the target host at the top level of `config.yml`

    For `registry.example.com`, merge the following configuration and replace the credentials with the actual values.

    ```yaml
    registries:
      - host: registry.example.com
        username: example-puller
        password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
    ```

3. If the server that issues temporary tokens (the token service) uses a different host, verify the credential destination and add it to `token_hosts`

    For Docker Hub, merge the following configuration into `registries` in the same `config.yml` and replace the credentials with the actual values.

    ```yaml
    registries:
      - host: docker.io
        username: example-puller
        password: "REPLACE_WITH_REGISTRY_READ_TOKEN"
        token_hosts: [auth.docker.io]
    ```

See [Image registry authentication](configuration.md#registries) for configuration requirements and [Credential destinations](outbound-communication.md#credential-destinations) for destination restrictions.
To configure and apply authentication inside a Kubernetes cluster, follow [Authenticate to private registries inside the cluster](getting-started.md#kubernetes-private-registry).

## Enabling remediation pull requests {#enable-pull-requests}

Follow the page for your environment to configure, apply, and verify remediation pull requests.
Complete remediation plan startup verification for your environment and confirm that the notifications show the intended workloads, sources, and update targets before continuing.

First check [PR creation prerequisites and cautions](#enable-pr-creation), then follow the section for the environment being monitored.

| Environment being monitored | Next section |
| --- | --- |
| Compose or docker run | [Enabling remediation pull requests](remediation-setup-docker.md#docker-enable-pull-requests) |
| Kubernetes | [Configure remediation pull requests](remediation-setup-kubernetes.md#kubernetes-enable-pull-requests) |

### PR creation prerequisites and cautions {#enable-pr-creation}

Before enabling PR creation, check token permissions and assign responsibility across hosts.
Follow [Preparing GitHub access](#prepare-github-access) to verify that every mapped repository has a token with permission to create PRs.

When running on multiple hosts, assign PR creation for the same file in the same repository to one instance.
This applies to Compose files, Kubernetes manifests, Kustomize, Helm values, Dockerfiles, and dependency files.

PR deduplication operates per host.
On other hosts, omit the relevant mappings or enable plans only with `remediation.pull_requests.enabled: false`.

Creating a PR may trigger workflows in the target repository that run on `pull_request`.
When editing the PR body, preserve the identifying marker in its HTML comment, which is used to reconcile and recover records.

To edit and apply the configuration, follow [Enabling remediation pull requests](remediation-setup-docker.md#docker-enable-pull-requests) for Docker or [Enable and apply PR creation](remediation-setup-kubernetes.md#kubernetes-enable-pr-creation).
