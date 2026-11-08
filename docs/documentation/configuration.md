# Configuration

This page describes the YAML configuration file. The container image uses `/etc/kestrelynx/config.yml` by default. Unknown YAML fields produce an error.

The complete annotated example is available in [`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml).

## Scan targets {#scan-target}

No settings in this section are needed to scan a Docker host. Configure them to scan a Kubernetes cluster.

When running in a Pod inside the cluster, use the two options below and leave `kubernetes.api_server`, `kubernetes.token_file`, `kubernetes.ca_file`, and `kubernetes.tls_server_name` empty.

In Kubernetes mode, when `schedule.run_on_start` is enabled, KestreLynx waits up to 30 seconds before the first scan for all containers in its own Pod to be reported as `Running` by the API.

- It identifies its own Pod using the ServiceAccount namespace and `HOSTNAME`.
- It skips the wait if it cannot read its own Pod, such as when running outside the cluster, using another cluster's API server, or when `HOSTNAME` is not the Pod name.
- If not all containers are `Running` within 30 seconds, it logs a warning and starts the scan.

| Option | Default | Description |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Scan a Kubernetes cluster instead of a Docker host. |
| `kubernetes.namespaces` | `[]` | Namespaces to scan. Empty or omitted means every namespace. Each value must be 1–63 bytes of lowercase alphanumerics and hyphens, starting and ending with an alphanumeric. |

#### Connecting from outside the cluster {#scan-target-outside}

When connecting to the API server from outside the cluster, such as from a Docker container on another host, configure the following options in addition to those above.

Language-package updates using work Pods have not been verified when connecting from outside the cluster.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `kubernetes.api_server` | yes | empty | API server URL starting with `https://` and reachable from KestreLynx. |
| `kubernetes.token_file` | yes | empty | File containing a token for a ServiceAccount with the permissions in the supplied ClusterRole (`deploy/kubernetes/clusterrole.yaml`). The file is reread on every scan, so replacing it takes effect on the next scan without a restart. Tokens created with `kubectl create token` expire, and scans fail after expiration. A non-expiring token can be created using a Secret of type `kubernetes.io/service-account-token` with the `kubernetes.io/service-account.name` annotation set to the ServiceAccount name. |
| `kubernetes.ca_file` | yes | empty | File containing the cluster CA certificates in PEM format. The file is reread on every scan. It must be readable and contain valid PEM certificates at runtime; there is no insecure fallback. |
| `kubernetes.tls_server_name` | When the host name or address in `api_server` is absent from the API server's certificate | empty | Name present in the certificate, such as `kubernetes`, to use for TLS certificate validation. Used when connecting through a load balancer or DNS name, for example. Empty means no server-name override. |

## Image registry authentication {#registries}

Configure private registry credentials in the top-level `registries` setting.
These credentials are used when Trivy fetches images from the registry on that host for scanning. They are also used when remediation planning reads information from the same registry about tags and images being considered as update targets.

Connections use HTTPS only, and certificates must be trusted by KestreLynx.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `registries` | no | `[]` | Per-host image registry credentials. |

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `host` | yes | none | Hostname or IPv4 address as used in image references, with an optional port from `1` to `65535`; no scheme, path, or user information. Hostnames are case-insensitive, and `docker.io`, `index.docker.io`, and `registry-1.docker.io` are treated as the same host. Credential entries must not have duplicate `host` values after normalization. |
| `username` | yes | none | Nonempty string without whitespace, control characters, or `:`. |
| `password` | yes | none | Nonempty password or access token without whitespace or control characters. |
| `token_hosts` | no | `[]` | Additional token service hosts allowed to receive credentials; each value uses the same format as `host`. For Docker Hub authentication, set `host: docker.io` and `token_hosts: [auth.docker.io]`. |

See [Credential destinations](outbound-communication.md#credential-destinations) for environment variables used by Trivy, their exemption from `token_hosts` restrictions, and destination and redirect restrictions, and [Private image authentication](remediation-setup.md#configure-registry-auth) for setup instructions.

## Schedule {#schedule}

| Option | Default | Description |
| --- | --- | --- |
| `schedule.daily_at` | empty | Local time in `HH:MM`. Use the container's `TZ` environment variable to select the timezone. When empty, run every 24 hours from startup. |
| `schedule.run_on_start` | `true` | Run one scan immediately when KestreLynx starts. |

## Scanning {#scan}

See the following pages for runtime matching rules, limitations, and advisory download destinations.

- Node.js: [Node.js runtime findings](scan-logic.md#node-runtime), [Node.js advisory downloads](outbound-communication.md#node-runtime-download)
- Python: [Python runtime findings](scan-logic.md#python-runtime), [Python advisory downloads](outbound-communication.md#python-runtime-download)

| Option | Default | Description |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | Severities retained for analysis and notification, including Node.js and Python runtime findings. Allowed values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`. |
| `scan.node_runtime.enabled` | `true` | Download security advisories and check the Node.js version recorded in `NODE_VERSION` against them. `false` disables both downloads and checks. |
| `scan.python_runtime.enabled` | `true` | Download security advisory data and check the CPython version recorded in `PYTHON_VERSION` against it. `false` disables both downloads and checks. |

## Prioritization {#triage}

See [Outbound communication](outbound-communication.md#outbound-communication) for where KestreLynx connects and what it sends.

| Option | Default | Description |
| --- | --- | --- |
| `triage.enabled` | `true` | Enable CISA KEV- and EPSS-based prioritization. |
| `triage.act_now_epss` | `0.10` | EPSS probability at or above which a CVE becomes act now. Must be at least `triage.watch_epss` and at most `1`. |
| `triage.watch_epss` | `0.01` | EPSS probability at or above which a CVE is at least watch. Must be greater than `0` and at most `triage.act_now_epss`. |
| `triage.kev_url` | empty | Override the CISA KEV feed URL, for example with a local mirror. |
| `triage.epss_url` | empty | Override the EPSS feed URL, for example with a local mirror. |
| `triage.discussion_links` | `true` | Look up Hacker News discussions for act-now CVEs. |

## Notifications {#notifications}

### Notification destinations {#notify-destinations}

At least one destination is required. Email alone satisfies this requirement.

Configure either a Slack incoming webhook or the bot-token pair, not both. A generic webhook and email can be used alongside either Slack delivery method.

See [Thread reports](slack-display.md#thread-display) for thread placement and footers, and [Notification language](slack-display.md#notification-language) for the content that is translated.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `notify.slack_webhook_url` | no | empty | Slack incoming webhook URL for channel notifications. |
| `notify.slack_bot_token` | When `notify.slack_channel` is set | empty | Slack bot token with `chat:write`. Bot delivery supports thread posts and links to the previous report. |
| `notify.slack_channel` | When `notify.slack_bot_token` is set | empty | Destination Slack channel ID for bot delivery. |
| `notify.generic_webhook_url` | no | empty | Endpoint that receives structured JSON. |
| `notify.email.host` | When any `notify.email` field is set | empty | SMTP host name or IP, without a scheme or port. |
| `notify.email.port` | When any `notify.email` field is set | none | SMTP port (`1`–`65535`). |
| `notify.email.tls` | When any `notify.email` field is set | none | `starttls` (upgrade after connect) or `tls` (implicit TLS). Unencrypted SMTP is refused. |
| `notify.email.username` | When `notify.email.password` is set | empty | SMTP username. Omit together with `password` when SMTP authentication is not used. |
| `notify.email.password` | When `notify.email.username` is set | empty | SMTP password. Omit together with `username` when SMTP authentication is not used. |
| `notify.email.from` | When any `notify.email` field is set | empty | Sender address. |
| `notify.email.to` | When any `notify.email` field is set | empty | One or more recipient addresses. |
| `notify.language` | no | `en` | Language for Slack and email notifications and PR bodies: `en` or `ja`; other values are configuration errors. Generic webhook JSON remains in English. |

### Notification mode {#notify-mode}

See [Package changes](diff-logic.md#package-changes) for changes treated as differences, and [Scan notification conditions](notification-conditions.md#notification-conditions) for when notifications are sent.

| Option | Default | Description |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff` reports changes; `full` reports all current findings on every scan. |
| `notify.full_report_day` | `monday` | Weekday for a full report in diff mode. Use a weekday name from `monday` through `sunday`, or `never` to disable it. |
| `notify.notify_on_clean` | `false` | Send a notification when no vulnerabilities are found. |

## State and environment name {#state}

See [Setup instructions](getting-started.md) for persisting the directory containing `state.path`, and [History continuity](diff-logic.md#state-lifecycle) for how history is handled.

| Option | Default | Description |
| --- | --- | --- |
| `state.path` | `/var/lib/kestrelynx/state.json` | File used for scan history and diff calculations. |
| `environment.name` | empty | Name for this instance's scan history. Empty means the unnamed default environment. A non-empty value must be 1–63 bytes of lowercase alphanumerics and hyphens, starting and ending with an alphanumeric; values are not normalized. It appears as `[name]` in the Slack header and as `environment.name` in the generic webhook. Adding, changing, or removing the name does not reset history, change first-seen dates, or re-notify existing findings. |

## Remediation plans and pull requests {#remediation}

See the [remediation overview](remediation.md#contents) for an entry point and [Enabling remediation](remediation-setup.md) for setup instructions.

### Basic settings {#remediation-basics}

See [Plan and PR execution scope](remediation-logic.md#plan-and-pr-execution) for the processing enabled by each setting, and [Stored files](remediation-reference.md#stored-records) for stored content.

| Option | Default | Description |
| --- | --- | --- |
| `remediation.enabled` | `false` | Enable read-only remediation plans in Docker or Kubernetes mode. |
| `remediation.pull_requests.enabled` | `false` | Enable fix pull requests; requires remediation plans and a GitHub token. |
| `remediation.storage_dir` | `/var/lib/kestrelynx/remediation` | Absolute directory for plans, delivery records, PR records, and the tool cache. Changing `state.path` does not change this location. |

### GitHub access {#remediation-github}

When remediation PRs are enabled, every repository in `remediation.mappings` requires a token.
A repository with neither a matching token in `tokens` nor a default token causes a startup error.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.github.token` | no | empty | Default GitHub token for repositories whose owners are not listed in `tokens`; must not contain whitespace or control characters. |
| `remediation.github.tokens` | no | `[]` | List of GitHub tokens by owner. A matching repository owner's token is used instead of the default token. |
| `remediation.github.tokens[].owner` | yes | none | GitHub user or organization name. Matching is case-insensitive; duplicate owners cause an error. |
| `remediation.github.tokens[].token` | yes | none | Nonempty GitHub token for that owner's repositories; must not contain whitespace or control characters. |

#### Required token permissions

The following table shows the permissions required for GitHub tokens.
Use fine-grained tokens limited to the target repositories.

| Purpose | Required token permissions |
| --- | --- |
| Reading source code from public repositories to create remediation plans | None |
| Reading source code from private repositories to create remediation plans | Contents: Read |
| Creating and managing remediation PRs | Contents and Pull requests: Read and write |

See [Credential destinations](outbound-communication.md#credential-destinations) for where the token is sent.

### Source mappings {#remediation-mappings}

Use `remediation.mappings` to specify the GitHub repository and source files associated with each running container.
KestreLynx reads these files to create remediation plans and uses them as update targets when remediation PRs are enabled.

All sources in one entry use the same `repository` and `base_branch`.
For sources in different repositories or on different branches, create separate entries with the same `workload`.

See [Supported input formats](remediation-reference.md#supported-inputs) for supported file formats.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.mappings` | no | `[]` | Lists the associations between running containers and the GitHub source files used for remediation plans and remediation PRs. |

#### docker run {#remediation-mappings-docker-run}

For a container started with `docker run`, set `workload` to `container/<name>`.

Specify `dockerfile` to update the Dockerfile's base image or `dependencies` to update language packages.
Configure either source type or both.

```yaml
remediation:
  mappings:
    - workload: container/example-api
      repository: example/application
      base_branch: main
      dockerfile:
        path: Dockerfile
      dependencies:
        directory: .
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | yes | none | Identifies the target container as `container/<name>`. Use the value shown in the `NAMES` column of `docker ps`; names are case-sensitive. |
| `remediation.mappings[].repository` | yes | none | Specifies the GitHub repository containing the target files, in `owner/name` form. |
| `remediation.mappings[].base_branch` | yes | none | Specifies the Git branch from which to read the target files. Remediation PRs also target this branch. |
| `remediation.mappings[].dockerfile.path` | When `dockerfile` is set | none | Specifies the path to the Dockerfile used to build the target image, relative to the repository root. |
| `remediation.mappings[].dockerfile.target` | no | Last stage in the Dockerfile | Names the stage used to build the target image. The base image inherited by this stage is the update target. |
| `remediation.mappings[].dependencies.directory` | When `dependencies` is set | none | Specifies the directory containing the dependency files that manage the language packages to update, relative to the repository root. Use `.` for the repository root. |

#### Compose {#remediation-mappings-compose}

For a service running with Compose, set `workload` to `compose/<project>/<service>`.

Choose `compose` to update image tags in a Compose file, `dockerfile` to update a Dockerfile's base image, or `dependencies` to update language packages.
Specify one or more of these three source types.

```yaml
remediation:
  mappings:
    - workload: compose/shop/web
      repository: example/shop
      base_branch: main
      compose:
        path: compose.yml
        service: web
      dependencies:
        directory: .
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | yes | none | Identifies the target service as `compose/<project>/<service>`. Use the running container's `com.docker.compose.project` label value for `project` and its `com.docker.compose.service` label value for `service`. |
| `remediation.mappings[].repository` | yes | none | Specifies the GitHub repository containing the target files, in `owner/name` form. |
| `remediation.mappings[].base_branch` | yes | none | Specifies the Git branch from which to read the target files. Remediation PRs also target this branch. |
| `remediation.mappings[].compose.path` | When `compose` is set | none | Specifies the path to the target Compose file, relative to the repository root. |
| `remediation.mappings[].compose.service` | When `compose` is set | none | Names the service whose image tag will be updated in the file specified by `compose.path`. |
| `remediation.mappings[].dockerfile.path` | When `dockerfile` is set | none | Specifies the path to the Dockerfile used to build the target image, relative to the repository root. |
| `remediation.mappings[].dockerfile.target` | no | Last stage in the Dockerfile | Names the stage used to build the target image. The base image inherited by this stage is the update target. |
| `remediation.mappings[].dependencies.directory` | When `dependencies` is set | none | Specifies the directory containing the dependency files that manage the language packages to update, relative to the repository root. Use `.` for the repository root. |

You can omit `dockerfile` when the Dockerfile and build stage can be determined from the Compose `build` setting.
See [Base image selection](remediation-logic.md#base-image-selection) for the supported conditions and checks against an explicit `dockerfile` setting.

#### Kubernetes {#remediation-mappings-kubernetes}

For a Kubernetes container, set `workload` to `<kind>/<namespace>/<name>/<container>`.

For image tag updates, choose `manifest` for a plain manifest, `kustomize` for Kustomize, or `helm_values` for a Helm values file.
For each container, specify only the one method that manages its image tag.

Specify `dockerfile` for Dockerfile base image updates or `dependencies` for language package updates.
Each entry requires at least one source type.

When remediation plans are enabled, mappings to namespaces outside the scope of `kubernetes.namespaces` produce a startup warning and are not used in plans.

```yaml
remediation:
  mappings:
    - workload: deployment/example/web/app
      repository: example/application
      base_branch: main
      manifest:
        path: apps/web.yaml
      dockerfile:
        path: docker/Dockerfile
      dependencies:
        directory: .
```

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.mappings[].workload` | yes | none | Identifies the target container as `<kind>/<namespace>/<name>/<container>`. Use `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod` for `kind`; `namespace` is the namespace, `name` is the name of the workload of that kind, and `container` is the container name. |
| `remediation.mappings[].repository` | yes | none | Specifies the GitHub repository containing the target files, in `owner/name` form. |
| `remediation.mappings[].base_branch` | yes | none | Specifies the Git branch from which to read the target files. Remediation PRs also target this branch. |
| `remediation.mappings[].manifest.path` | When `manifest` is set | none | Specifies the path to the manifest containing the target container's image tag, relative to the repository root. |
| `remediation.mappings[].manifest.object.kind` | no | Manifest `kind` corresponding to the `workload` kind | Specifies the kind of the target object in the file. Use the `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, or `Pod` kind that corresponds to the `workload` kind. |
| `remediation.mappings[].manifest.object.name` | no | `name` from `workload` | Specifies the target object's name in the file. Set this when the name in the file differs from the running workload's name. |
| `remediation.mappings[].kustomize.path` | When `kustomize` is set | none | Specifies the path to the target Kustomize file, relative to the repository root. The filename must be `kustomization.yaml`, `kustomization.yml`, or `Kustomization`. |
| `remediation.mappings[].kustomize.image` | When `kustomize` is set | none | Identifies the `images` entry whose `newTag` will be updated, using that entry's `name` value. Do not include a tag or digest. |
| `remediation.mappings[].kustomize.affects` | no | `[]` | Lists every container other than `workload` affected by changing the selected `images` entry's tag, using `<kind>/<namespace>/<name>/<container>` form. Include ordinary init containers. Before omitting this setting, confirm that only the container identified by `workload` is affected. |
| `remediation.mappings[].helm_values.path` | When `helm_values` is set | none | Specifies the path to the target values file, relative to the repository root. The extension must be `.yaml` or `.yml`. |
| `remediation.mappings[].helm_values.key` | When `helm_values` is set | none | Identifies the key that specifies the image, such as `image` or `app.image`. Select the entry containing `repository` and `tag`, or a string entry such as `nginx:1.27.2`, rather than the `tag` field itself. Dots separate levels; each key name uses letters, digits, `_`, or `-`. |
| `remediation.mappings[].helm_values.affects` | no | `[]` | Lists every container other than `workload` affected by changing the tag at the selected values key, using `<kind>/<namespace>/<name>/<container>` form. Include ordinary init containers. Before omitting this setting, confirm that only the container identified by `workload` is affected. |
| `remediation.mappings[].dockerfile.path` | When `dockerfile` is set | none | Specifies the path to the Dockerfile used to build the target image, relative to the repository root. |
| `remediation.mappings[].dockerfile.target` | no | Last stage in the Dockerfile | Names the stage used to build the target image. The base image inherited by this stage is the update target. |
| `remediation.mappings[].dependencies.directory` | When `dependencies` is set | none | Specifies the directory containing the dependency files that manage the language packages to update, relative to the repository root. Use `.` for the repository root. |

See [Kustomize PR configuration](remediation-setup.md#kustomize-pull-requests) and [Helm values PR configuration](remediation-setup.md#helm-values-pull-requests) for examples and instructions for listing affected containers.

### Processing limits {#remediation-limits}

See [Reason codes](remediation-reference.md#reason-codes) for outcomes caused by limits, [PR management](remediation-logic.md#pr-management) for PR handling, and [Work container execution](remediation-logic.md#worker-execution) for execution deadlines and cleanup.

The [Newer series check](remediation-logic.md#newer-series-check) shares the candidate-scan, baseline-rescan, tag-listing, and registry-request limits with normal processing.

| Option | Default | Description |
| --- | --- | --- |
| `remediation.limits.candidate_scans_per_cycle` | `10` | Candidate-image scans per cycle; positive integer. |
| `remediation.limits.baseline_rescans_per_cycle` | `10` | Baseline rescans per cycle to match comparison conditions; positive integer. |
| `remediation.limits.registry_requests_per_cycle` | `200` | Image-registry HTTP requests per cycle, including token exchanges; positive integer. Requests that check whether authentication is required before scanning running images do not count toward this limit, but the same requests before scanning candidate images do count. |
| `remediation.limits.tag_pages_per_repository` | `20` | Tag-list requests per image repository, including requests to find the target version series; positive integer. |
| `remediation.limits.cycle_timeout` | `30m` | Deadline for planning, dependency updates, and PR processing; positive duration, excluding ordinary running-image scans. |
| `remediation.limits.new_prs_per_cycle` | `3` | New PRs per cycle when PRs are enabled; positive integer. |
| `remediation.limits.open_prs` | `10` | Open KestreLynx PRs across all configured repositories when PRs are enabled; positive integer. |
| `remediation.limits.dependency_jobs_per_cycle` | `3` | Dependency update units attempted per cycle; positive integer, not a count of packages or containers. |
| `remediation.limits.job_timeout` | `6m` | Deadline for each work container's creation, execution, and result collection; from `1m` to `60m30s`. |

### Work containers {#remediation-worker}

Work containers are disposable containers used to run dependency updates (such as lockfile updates) with npm, pnpm, pip, uv, Go, or Gradle separately from KestreLynx itself when updating language packages for remediation PRs.

See [Pinning official images](remediation-logic.md#worker-images) for pinning and handling unavailable work images, [Supported runtimes](remediation-reference.md#supported-runtimes) for version series, and [Work image downloads](outbound-communication.md#worker-image-downloads) for network destinations.

See [Waiting after tool publication](remediation-logic.md#tool-release-age), [Tool downloads and verification](remediation-logic.md#tool-verification), and [Tool cache reuse](remediation-logic.md#tool-cache) for tool handling.

See [Container inputs](remediation-logic.md#worker-inputs) for checks when passing the worker program to a container.

| Option | Default | Description |
| --- | --- | --- |
| `remediation.worker.registry` | empty | Docker Hub mirror in lowercase `host[:port][/path]` form; empty uses Docker Hub. Do not include a scheme, tag, digest, `//`, or `..`; paths use lowercase letters, digits, and the separators `.`, `_`, and `-`. The mirror must serve `library/node`, `library/python`, `library/golang`, and `library/gradle` with the same contents as the official images under the specified host and path. |
| `remediation.worker.tool_versions.min_release_age` | `72h` | Minimum wait between publication and use of npm, pnpm, or uv; positive duration such as `72h` or `30m`, excluding `0` and negative values. |
| `remediation.worker.tool_versions.cache_max_size` | `1GiB` | Maximum npm, pnpm, and uv cache size; integer bytes or an integer followed by `B`, `KiB`, `MiB`, or `GiB`, with a minimum of `128MiB`. |
| `remediation.worker.program_dir` | empty | Empty or an absolute directory containing a worker program for development; not required for standard releases. |

#### Kubernetes {#remediation-worker-kubernetes}

These settings apply to language-package updates in Kubernetes mode. The user applies the work namespace and necessary resources following the [setup steps](remediation-setup.md#kubernetes-language-updates).

These settings require `kubernetes.enabled: true`. Invalid names, image references, or numeric values cause a startup error.

| Option | Required | Default | Description |
| --- | --- | --- | --- |
| `remediation.worker.kubernetes.namespace` | When another `remediation.worker.kubernetes` field is set | empty | Namespace for work Pods. When unset, language-package updates other than Maven require manual action with `work_namespace_not_configured`. |
| `remediation.worker.kubernetes.service_account` | no | `kestrelynx-work` | ServiceAccount for work Pods; specify one without permissions or a token. |
| `remediation.worker.kubernetes.priority_class` | no | `kestrelynx-work` | PriorityClass for work Pods; specify one with `preemptionPolicy: Never`. |
| `remediation.worker.kubernetes.receiver_image` | When updating language packages from outside the cluster | empty | KestreLynx image for the container receiving input files, in `repository@sha256:...` form. When empty, read the digest-pinned reference from the status of KestreLynx's own Pod. Outside the cluster, KestreLynx cannot obtain this reference from its own Pod, so leaving this empty prevents language-package updates with `work_image_unavailable`. |
| `remediation.worker.kubernetes.max_concurrent_pods` | no | `1` | Maximum work Pods held by the same instance at once, from `1` to `16`, including finished Pods that have not been deleted and excluding Pods already being deleted; the work namespace's ResourceQuota limits the total including those. |
| `remediation.worker.kubernetes.runtime_class` | no | empty | Unsupported and must remain empty; setting it requires manual action with `work_runtime_class_unsupported`. |

## Runtime usage {#runtime}

[Runtime usage](runtime-usage.md) is an experimental feature. See that page for Sensor setup, observation rules, muting conditions, notification resumption, and permissions.

Containers with the label `io.kestrelynx.runtime.exclude=true` are excluded from runtime usage assessment; only the lowercase value `true` matches.

| Option | Default | Description |
| --- | --- | --- |
| `runtime.enabled` | `false` | Read Sensor evidence and include runtime usage in notifications. Leave disabled when no Sensor is installed. Available only for Docker; enabling it together with `kubernetes.enabled: true` is a configuration error. |
| `runtime.mute_unfixable_not_in_use` | `false` | Mute eligible findings with no fix and no observed use for 7+ days in Slack. Requires `runtime.enabled: true`; priority is unchanged and all findings remain in the generic webhook. |
| `runtime.evidence_dir` | `/var/lib/kestrelynx-runtime` | Absolute path where the Sensor evidence volume is mounted. Must match the Sensor's `--evidence-dir`. |
