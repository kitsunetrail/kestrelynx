# KestreLynx

**English** | [日本語](README.ja.md)

[![CI](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/kestrelynx/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

[Documentation](https://kestrelynx.dev/) ·
[日本語](https://kestrelynx.dev/ja/) ·
[Configuration reference](https://kestrelynx.dev/documentation/configuration/)

> An agent that scans your running Docker containers every day and sends only the **actionable vulnerabilities** — prioritized — to Slack or a webhook.

Built for self-hosters and homelab folks. It does the tedious work of reading Trivy's raw output for you, and surfaces what you can fix *right now*.

> ⚠️ **Status: MVP / WIP.** Currently focused on Docker-only, CVE notifications.

## What a notification looks like

```
🛡️ KestreLynx — scan results for 2026-06-28 09:00
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

Instead of dumping every CVE every day, it tells you **what changed** — and which of it
actually matters. Every finding is triaged into **act now / watch / low** by combining
severity with real-world exploitation signals: the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(confirmed exploitation in the wild) and [EPSS](https://www.first.org/epss/) (predicted
exploitation probability). A CRITICAL that nobody is exploiting stays out of your way; a
HIGH that ransomware crews are actively using tops the message, with the evidence right
there. If a known CVE gets added to KEV overnight, the next digest calls it out as
**⬆️ escalated** — that's the notification you actually needed. On days where nothing
changed, you get one line, not a wall of text. A full report goes out once a week
(configurable), and the complete data is always available via the generic webhook.

Act-now findings also carry the links a responder would search for anyway: the advisory,
the vendor guidance from the KEV entry, and the Hacker News discussion when a substantial
one exists. Links, not AI summaries — every line in the message is a verifiable fact.

**Privacy note**: the intel feeds are bulk downloads joined locally — your CVE list never
leaves the host, with one documented exception: discussion-link lookup queries
hn.algolia.com for **act-now CVEs only** (a handful of well-known, actively exploited
CVEs). Set `triage.discussion_links: false` for zero CVE egress.

## What it does

1. Reads the unique images of your running containers from `docker.sock` (a single `GET /containers/json` — it never controls containers)
2. Scans each image with [Trivy](https://github.com/aquasecurity/trivy) (CVE DB is handled by Trivy)
3. Keeps only **HIGH / CRITICAL** findings
4. Triages each CVE into **act now / watch / low** using CISA KEV and EPSS (fetched in bulk daily, joined locally; disable with `triage.enabled: false`)
   and attaches advisory / vendor-guidance / HN-discussion links to act-now findings
5. Aggregates per package and annotates upgrade risk (for language packages, semver tells you whether the bump is safe or needs care)
6. Flags base-OS end-of-life (EOL) as top priority
7. Diffs against the previous scan, so you're notified about **changes** — including a known CVE **escalating** (entering KEV, EPSS spike) — not reminded of what you already know
8. Notifies Slack / webhook once a day — but only when there's something worth acting on

## Quick start

```sh
# 1. Create your config (just drop in a Slack Incoming Webhook URL to get going)
cp config.example.yml config.yml
$EDITOR config.yml

# 2. Run it
docker run -d --name kestrelynx \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
```

(The `kestrelynx-state` volume keeps the scan history that powers diff notifications;
without it, everything is re-announced as new whenever the container is recreated.)

**A note on the Docker socket**: KestreLynx only performs a GET request to list running
containers (`GET /containers/json`) — it never starts, stops, or modifies anything.
However, mounting `docker.sock` gives the container privileged access to the Docker API;
`:ro` makes the filesystem mount read-only but does not restrict Docker API operations.
Mount the Docker socket only into images you trust.

That's it — every container on the host (no matter which compose project or one-off `docker run` started it) is scanned daily.
You don't need one per container or per compose project: **one instance per host**.

### Running with docker compose

A ready-to-use [docker-compose.yml](docker-compose.yml) is included:

```sh
cp config.example.yml config.yml   # then add your Slack webhook to config.yml
docker compose up -d
docker compose logs -f
```

## Configuration

See [config.example.yml](config.example.yml). At minimum, set one of `notify.slack_webhook_url` or `notify.generic_webhook_url` and you're good to go.

Notable knobs:

- `notify.slack_bot_token` + `notify.slack_channel` — deliver via the Slack Web API instead of a webhook (set one or the other). Same channel summary, plus a **full open-findings report in the summary's thread**: urgent/watch findings expanded with evidence, references, and how long each has been open; low collapsed to a count. On no-change days the summary links back to the last full report instead of re-posting it. Needs a bot token with the `chat:write` scope invited to the channel.
- `notify.mode` — `diff` (default) notifies only what changed since the last scan, plus a one-line "open now" summary; `full` resends the complete report every scan.
- `notify.full_report_day` — in diff mode, the weekday to also send the complete report (default `monday`, `never` to disable).
- `state.path` — where diff mode remembers previous scans (default `/var/lib/kestrelynx/state.json`).
- `triage.enabled` — KEV/EPSS-based prioritization (default `true`). Adds outbound HTTPS to `www.cisa.gov` and `epss.empiricalsecurity.com` (two bulk downloads per day, cached next to the state file); set to `false` for severity-only notifications with no extra egress. Thresholds (`act_now_epss`, `watch_epss`) and mirror URLs are configurable.

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

The pipeline is split into small packages: `docker` (enumerate) → `scanner` (run & parse Trivy) → `intel` (fetch & cache KEV/EPSS) → `analyze` (triage, aggregate, assess) → `state` (persist & diff against the previous scan) → `notify` (format & send), tied together by `runner`.

## License

[GNU AGPL-3.0](LICENSE). Copyright (c) 2026 Kitsune Trail.

In short: you're free to use, modify, and self-host it. If you run a modified
version as a network service, you must make your modified source available to
its users.
