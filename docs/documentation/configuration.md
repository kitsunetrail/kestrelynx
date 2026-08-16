# Configuration

This page describes the YAML configuration file. The container image uses
`/etc/stackwatch/config.yml` by default. Unknown YAML fields produce an error.

The complete annotated example is available in
[`config.example.yml`](https://github.com/kitsunetrail/stackwatch/blob/main/config.example.yml).

## Schedule

| Option | Default | Description |
| --- | --- | --- |
| `schedule.daily_at` | empty | Local time in `HH:MM`. When empty, run every 24 hours from startup. |
| `schedule.run_on_start` | `true` | Run one scan immediately when StackWatch starts. |

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
StackWatch sends a short heartbeat instead of repeating the entire report.

## State and Docker

| Option | Default | Description |
| --- | --- | --- |
| `docker.socket` | `/var/run/docker.sock` | Path to the Docker socket. |
| `state.path` | `/var/lib/stackwatch/state.json` | File used for scan history and diff calculations. |

Persist the directory containing `state.path` with a Docker volume.

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
