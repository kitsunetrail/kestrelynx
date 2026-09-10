# Configuration

This page describes the YAML configuration file. The container image uses
`/etc/kestrelynx/config.yml` by default. Unknown YAML fields produce an error.

The complete annotated example is available in
[`config.example.yml`](https://github.com/kitsunetrail/kestrelynx/blob/main/config.example.yml).

## Schedule

| Option | Default | Description |
| --- | --- | --- |
| `schedule.daily_at` | empty | Local time in `HH:MM`. When empty, run every 24 hours from startup. |
| `schedule.run_on_start` | `true` | Run one scan immediately when KestreLynx starts. |

Use the container's `TZ` environment variable to select the timezone used by
`daily_at`.

## Scanning

| Option | Default | Description |
| --- | --- | --- |
| `scan.severity` | `[HIGH, CRITICAL]` | Trivy severities retained for analysis and notification. |

Allowed severity values are `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

## Notification destinations

At least one destination is required.

| Option | Default | Description |
| --- | --- | --- |
| `notify.slack_webhook_url` | empty | Slack incoming webhook URL. |
| `notify.slack_bot_token` | empty | Slack bot token with `chat:write`. Set together with `slack_channel`. |
| `notify.slack_channel` | empty | Destination Slack channel ID for bot delivery. |
| `notify.generic_webhook_url` | empty | Endpoint that receives structured JSON. |
| `notify.notify_on_clean` | `false` | Send a notification when no vulnerabilities are found. |

Configure either `slack_webhook_url` or the bot-token pair, not both. A generic
webhook can be used alongside either Slack delivery method.

Bot delivery adds a full open-findings report in the summary message's thread.
On quiet days, the summary links back to the last full report instead of
reposting it.

## Notification mode

| Option | Default | Description |
| --- | --- | --- |
| `notify.mode` | `diff` | `diff` reports changes; `full` reports all current findings on every scan. |
| `notify.full_report_day` | `monday` | Weekday for a full report in diff mode. Use `never` to disable it. |

Diff mode reports new findings, resolved findings, changes in fix availability,
and priority escalations. When findings remain open but nothing changed,
KestreLynx sends a short heartbeat instead of repeating the entire report.

## State and Docker

| Option | Default | Description |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Path to the Docker socket. |
| `state.path` | `/var/lib/kestrelynx/state.json` | File used for scan history and diff calculations. |

Persist the directory containing `state.path` with a Docker volume, or a
persistent volume in Kubernetes. The intel feed cache lives in an `intel`
directory beside `state.path`, by default `/var/lib/kestrelynx/intel`.

## Kubernetes

| Option | Default | Description |
| --- | --- | --- |
| `kubernetes.enabled` | `false` | Scan a Kubernetes cluster instead of a Docker host. |
| `kubernetes.api_server` | empty | Kubernetes API server URL. When empty, use `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`. A non-empty value must start with `https://`. |
| `kubernetes.token_file` | empty | ServiceAccount token file. When empty, use `/var/run/secrets/kubernetes.io/serviceaccount/token`. |
| `kubernetes.ca_file` | empty | Cluster CA bundle in PEM format. When empty, use `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`. |
| `kubernetes.tls_server_name` | empty | Override the server name used to validate the API server's TLS certificate. Empty means no override. |
| `kubernetes.namespaces` | `[]` | Namespaces to scan. Empty or omitted means every namespace. |

Setting `docker.socket` to a value, including `""`, together with `kubernetes.enabled: true`
fails at startup. Omitting the key or setting it to `null` does not cause this conflict.
An empty `docker:` section is accepted. Remove the entire `docker:` section when enabling Kubernetes.

Inside a cluster, `api_server`, `token_file`, and `ca_file` can remain empty to
use the Pod's injected API server address and mounted ServiceAccount token and
CA. With Kubernetes enabled, startup fails if `api_server` is empty and either
API server environment variable is missing. The CA bundle must be readable and
contain valid PEM certificates at runtime; there is no insecure fallback.

Each namespace must be a DNS-1123 label: lowercase alphanumerics and hyphens,
1–63 bytes, starting and ending with an alphanumeric. When namespaces are set,
Pods, ReplicaSets, and Jobs are listed separately in each namespace. Node
listing remains cluster-wide.

## Environment

| Option | Default | Description |
| --- | --- | --- |
| `environment.name` | empty | Optional name for this instance's scan history. Empty means the unnamed default environment. |

A non-empty name must be a DNS-1123 label: lowercase alphanumerics and hyphens,
1–63 bytes, starting and ending with an alphanumeric. Values are not normalized;
uppercase letters, dots, underscores, and whitespace are rejected.

When set, the name appears as `[name]` in the Slack header and as `name` in the
generic webhook payload's `environment` object. That object always includes
`kind`, either `docker` or `kubernetes`, derived from the enabled adapter. The
environment kind is not configurable. The webhook omits `name` when it is empty.

The name labels scan history rather than identifying the host; it is not
derived from a hostname or IP address. It is safe to keep the same name across
host rebuilds and migrations while retaining the state file. Adding, changing,
or removing the name does not reset history, change first-seen dates, or
re-notify existing findings.

## Exploitation-based triage

| Option | Default | Description |
| --- | --- | --- |
| `triage.enabled` | `true` | Enable CISA KEV- and EPSS-based prioritization. |
| `triage.act_now_epss` | `0.10` | EPSS probability at or above which a CVE becomes act now. |
| `triage.watch_epss` | `0.01` | EPSS probability at or above which a CVE is at least watch. |
| `triage.kev_url` | empty | Override the CISA KEV feed URL, for example with a local mirror. |
| `triage.epss_url` | empty | Override the EPSS feed URL, for example with a local mirror. |
| `triage.discussion_links` | `true` | Look up Hacker News discussions for act-now CVEs. |

KEV and EPSS feeds are downloaded in bulk and joined locally by CVE ID. The
host's complete CVE list is not uploaded to an external service. When discussion
links are enabled, act-now CVE IDs are sent as search queries to
`hn.algolia.com`. Set `discussion_links: false` to prevent that CVE egress, or
disable triage entirely to stop the additional intelligence-feed downloads.

Thresholds must satisfy:

```text
0 < watch_epss <= act_now_epss <= 1
```
