# StackWatch

[![CI](https://github.com/kitsunetrail/stackwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/kitsunetrail/stackwatch/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

> An agent that scans your running Docker containers every day and sends only the **actionable vulnerabilities** — prioritized — to Slack or a webhook.

Built for self-hosters and homelab folks. It does the tedious work of reading Trivy's raw output for you, and surfaces what you can fix *right now*.

> ⚠️ **Status: MVP / WIP.** Currently focused on Docker-only, CVE notifications.

## What a notification looks like

```
🛡️ StackWatch — scan results for 2026-06-28 09:00
12 images scanned, 3 affected

🆕 New since last scan (2)
🟠 nginx:1.25.3
   • openssl 3.0.7 → 3.0.11 (CRITICAL 1 / HIGH 0)  🟢 Distro security update
🟠 myapp:latest
   • webpack 4.46.0 → 5.89.0 (CRITICAL 0 / HIGH 1)  🟠 Needs care (major version bump) [lang]

✅ Resolved since last scan (1)
• myapp:latest: postcss

📌 Open now: CRITICAL 1 / HIGH 6 across 3 image(s) — oldest unresolved 12 days
```

Instead of dumping every CVE every day, it tells you **what changed**: new findings in
full detail (with a semver hint on whether the upgrade needs a human decision), what got
resolved, and a one-line running total whose age keeps nagging you — gently — about the
things you haven't fixed yet. On days where nothing changed, you get one line, not a wall
of text. A full report goes out once a week (configurable), and the complete data is
always available via the generic webhook.

## What it does

1. Reads the unique images of your running containers from `docker.sock` (read-only)
2. Scans each image with [Trivy](https://github.com/aquasecurity/trivy) (CVE DB is handled by Trivy)
3. Keeps only **HIGH / CRITICAL** findings
4. Sorts them by Trivy's `Status` (fixable now / waiting on upstream / won't fix)
5. Aggregates per package and annotates upgrade risk (for language packages, semver tells you whether the bump is safe or needs care)
6. Flags base-OS end-of-life (EOL) as top priority
7. Diffs against the previous scan, so you're notified about **changes**, not reminded of what you already know
8. Notifies Slack / webhook once a day — but only when there's something worth acting on

## Quick start

```sh
# 1. Create your config (just drop in a Slack Incoming Webhook URL to get going)
cp config.example.yml config.yml
$EDITOR config.yml

# 2. Run it (mount docker.sock read-only)
docker run -d --name stackwatch \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/stackwatch/config.yml:ro" \
  -v stackwatch-state:/var/lib/stackwatch \
  ghcr.io/kitsunetrail/stackwatch:latest
```

(The `stackwatch-state` volume keeps the scan history that powers diff notifications;
without it, everything is re-announced as new whenever the container is recreated.)

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

- `notify.mode` — `diff` (default) notifies only what changed since the last scan, plus a one-line "open now" summary; `full` resends the complete report every scan.
- `notify.full_report_day` — in diff mode, the weekday to also send the complete report (default `monday`, `never` to disable).
- `state.path` — where diff mode remembers previous scans (default `/var/lib/stackwatch/state.json`).

## Development

```sh
go test ./... -short   # fast unit tests (no Docker / network needed)
go test ./...          # also runs integration tests that use Trivy (needs trivy + network)
go build ./...
```

The pipeline is split into small packages: `docker` (enumerate) → `scanner` (run & parse Trivy) → `analyze` (sort, aggregate, assess) → `state` (persist & diff against the previous scan) → `notify` (format & send), tied together by `runner`.

## License

[GNU AGPL-3.0](LICENSE). Copyright (c) 2026 Kitsune Trail.

In short: you're free to use, modify, and self-host it. If you run a modified
version as a network service, you must make your modified source available to
its users.
