# KestreLynx

**English** | [日本語](README.ja.md)

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[Documentation](https://kestrelynx.dev/) ·
[Getting started](docs/documentation/getting-started.md) ·
[Configuration reference](docs/documentation/configuration.md)

> An agent that regularly scans images used by running Docker and Kubernetes containers and sends **prioritized vulnerabilities and changes since the last scan** to Slack or a webhook.

## What it does

- **Image scanning**: HIGH / CRITICAL detection with [Trivy](https://github.com/aquasecurity/trivy) by default
- **Scan deduplication**: shared results for images confirmed to be identical
- **Prioritization**: act now / watch / low, based on severity, CISA KEV, and EPSS
- **Package grouping**: fix availability, fixed versions, and upgrade-risk annotations
- **Unpatched vulnerabilities**: inclusion of findings without available fixes
- **Base-OS EOL**: prominent reporting of images with unsupported operating systems
- **Change tracking**: new findings, added CVEs, newly available fixes, priority escalations, and resolutions
- **Environment identification**: optional environment name in Slack headers
- **Container identification**: container names, Compose project/service, and Kubernetes workload information in the generic webhook
- **Running-image verification**: scan pinning to observed identifiers such as digests, with identity matching

## Supported environments

| Target | Operation and scope |
| --- | --- |
| Docker | One instance per host; running images across all Compose projects and standalone containers |
| Kubernetes | In-cluster deployment; read-only ServiceAccount; all or selected namespaces |

- **Kubernetes ownership**: Deployment, StatefulSet, DaemonSet, Job, and CronJob associations (`unknown` for unresolved ownership)
- **Scan targets**: containers running at discovery time, including Kubernetes native sidecars
- **Excluded targets**: ordinary init containers and ephemeral containers
- **Verified Kubernetes setup**: Ubuntu on linux/amd64, single-node K3s 1.36 with containerd 2.3
- **Unverified Kubernetes setups**: multiple nodes, mixed architectures, arm64, EKS / GKE / AKS, CRI-O, and authenticated private registries
- **Details**: [verification record and constraints](docs/development/kubernetes-support.md)

## What a notification looks like

This example uses the default `diff` mode.

```text
🛡️ KestreLynx [prod-vps] — scan results for 2026-06-28 09:00
12 images scanned, 3 affected

🆕 New since last scan (2)
🚨 nginx:1.25.3
   • libnghttp2-14 1.52.0-1 → 1.52.0-1+deb12u1 (HIGH 2)  🟢 upgrade: distro security patch
     ↳ CVE-2023-44487 HIGH · CISA KEV (exploited in the wild) · EPSS >99%
       📎 advisory · vendor advisory · 💬 HN (166 pts)
🔕 myapp:latest
   • webpack 4.46.0 → 5.89.0 (HIGH 1)  🟠 upgrade: major version bump — needs care [lang]

✅ Resolved since last scan (1)
• myapp:latest: postcss

📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 4 low — oldest act-now/watch unresolved 12 day(s)
```

- **Changes detected**: changed findings and open counts, including priority escalations such as KEV additions
- **Open findings, no changes**: short summary
- **No issues or changes**: no notification by default (configurable with `notify.notify_on_clean`)
- **Weekly report**: full report on Mondays by default, with day selection and disabling options
- **Reference links**: advisories, vendor guidance from KEV, and relevant Hacker News discussions

### Choosing a notification target

| Target | Delivery | Required settings |
| --- | --- | --- |
| Slack Incoming Webhook | Summary in the channel | `notify.slack_webhook_url` |
| Slack Bot | Summary plus a thread with open-finding details in diff mode | `notify.slack_bot_token` and `notify.slack_channel` |
| Generic webhook | Structured JSON POST with current scan results and, in diff mode, changes | `notify.generic_webhook_url` |

- **Slack Bot details**: evidence, references, and time open for act-now/watch findings; counts for low-priority findings
- **Report refresh**: on changes and weekly report days
- **Slack Bot on quiet days**: link to the last detailed report
- **Slack Bot requirements**: `chat:write` scope and invitation to the destination channel
- **Allowed combination**: either Slack Incoming Webhook or Slack Bot, plus the generic webhook
- **Unsupported combination**: Slack Incoming Webhook and Slack Bot together

## Quick start: Docker

You need a working Docker host and at least one notification target. The distributed image includes Trivy.

```sh
# 1. Copy the repository's example configuration and set a notification target
cp config.example.yml config.yml
$EDITOR config.yml

# 2. Start the agent (change TZ to your timezone)
docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=UTC \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest

# 3. Check startup and scan results
docker logs -f kestrelynx
```

- **Scan schedule**: immediately on startup and daily at 09:00 in the example configuration
- **Timezone**: the container's `TZ`
- **Persistent storage**: `kestrelynx-state` volume
- **Stored data**: diff history, first-seen dates, and intel cache
- **Recreation and updates**: reuse of the existing volume
- **Deployment unit**: one instance per host, covering all containers and Compose projects

### Running with Docker Compose

```sh
cp config.example.yml config.yml
$EDITOR config.yml
docker compose up -d
docker compose logs -f
```

- **Configuration file**: included [docker-compose.yml](docker-compose.yml)
- **Default `TZ`**: `UTC` (`Asia/Tokyo` for Japan time)

### Docker socket access

- **Discovery**: running-container listing through `GET /containers/json`
- **Image access**: Docker API reads by Trivy
- **Container operations**: no start, stop, or modification functionality
- **`:ro` limitation**: no restriction on Docker API permissions
- **Mount targets**: trusted images only

## Running on Kubernetes

1. Preparation of the [deployment manifests](deploy/kubernetes/)
2. Notification target in the [ConfigMap](deploy/kubernetes/configmap.yaml), plus optional `kubernetes.namespaces` and `environment.name`
3. `TZ` in the [Deployment](deploy/kubernetes/deployment.yaml) and storage settings in the [PVC](deploy/kubernetes/pvc.yaml)
4. Namespace creation and application of the edited manifests

```sh
kubectl create namespace kestrelynx
kubectl apply -f deploy/kubernetes/
kubectl logs -n kestrelynx deployment/kestrelynx -f
```

- **Activation**: `kubernetes.enabled: true`
- **Switching from the example**: removal of the `docker` section in `config.example.yml` (startup error with explicit `docker.socket`)
- **Unnecessary components**: Docker socket and per-node agents
- **Connectivity requirement**: scanner Pod access to the target registry for Trivy image retrieval
- **Private registry credentials**: credential-mount example in the Deployment (unverified in a real cluster)
- **Credential inheritance**: no automatic transfer of workload `imagePullSecrets`
- **Unsupported scope**: node-only images, deleted registry digests, K3s `registries.yaml` mirrors/rewrites, and air-gapped clusters
- **History storage**: PVC, with no concurrent writes to the same state file by multiple instances
- **Supplied Deployment**: one replica with the `Recreate` strategy

## Key configuration

See [config.example.yml](config.example.yml) for all configuration options and the [configuration reference](docs/documentation/configuration.md) for notification and scheduling details.

| Setting | Behavior |
| --- | --- |
| `schedule.daily_at` | Daily scan time (`09:00` in the example; 24-hour interval if omitted or empty) |
| `schedule.run_on_start` | Startup scan (default: `true`) |
| `scan.severity` | Included severities (default: `[HIGH, CRITICAL]`) |
| `notify.mode` | `diff`: change notifications (default); `full`: full report every scan |
| `notify.full_report_day` | Weekly report day in diff mode (default: `monday`; disabled: `never`) |
| `notify.notify_on_clean` | Notifications with no issues or changes (default: `false`) |
| `environment.name` | Optional environment name for reports (example: `prod-vps`) |
| `state.path` | History file (default: `/var/lib/kestrelynx/state.json`) |
| `triage.enabled` | `true`: KEV/EPSS prioritization (default); `false`: severity-based notifications |
| `triage.act_now_epss` / `triage.watch_epss` | EPSS thresholds (defaults: `0.10` / `0.01`) |
| `triage.discussion_links` | Hacker News discussion lookup (default: `true`) |

- **Environment-name characters**: lowercase alphanumerics and hyphens, with alphanumeric first and last characters
- **Environment-name length**: 1–63 characters, or empty
- **Multiple environments**: separate environment names and state storage per instance
- **History continuity after rebuilds or migrations**: retention of the environment name and state

## Network access and interpreting results

- **Intel matching**: bulk KEV/EPSS downloads and local joins, without transmitting detected CVE lists
- **Default intel sources**: `www.cisa.gov` and `epss.empiricalsecurity.com`
- **Discussion search endpoint**: `hn.algolia.com`
- **Search data**: CVE IDs qualifying as act-now based on exploitation signals
- **Search opt-out**: `triage.discussion_links: false`, with CVE delivery to notification targets still enabled
- **Other traffic**: vulnerability database and image retrieval by Trivy, plus results sent to configured notification targets
- **Failed scans or unconfirmed identity**: retention of previous findings, without resolution based on that cycle's results
- **Resolution meaning**: disappearance from the current monitored scope, including stopped containers or scope changes
- **Upgrade-risk annotations**: indicators such as version-change size, without compatibility or safety guarantees

A resolved finding is not proof of patch application. See [How KestreLynx works](docs/documentation/how-it-works.md) for notification rules and output details.

## Development

```sh
go test ./... -short   # fast unit tests (no Docker / network needed)
go test ./...          # also runs integration tests that use Trivy (needs trivy + network)
go build ./...
```

Build and preview the documentation locally:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Preview the Japanese documentation in a separate process:

```sh
mkdocs serve --config-file mkdocs.ja.yml
```

Documentation changes pushed to `main` are built and deployed by
[`docs.yml`](.github/workflows/docs.yml). Before the first deployment, select
**GitHub Actions** under **Settings → Pages → Build and deployment → Source**.

## License

[GNU AGPL-3.0](LICENSE). Copyright (c) 2026 Kitsune Trail.
