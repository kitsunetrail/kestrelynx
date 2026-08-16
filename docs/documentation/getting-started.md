# Setup instructions

StackWatch runs as one container per Docker host. It discovers and scans the
images used by running containers, then sends the results to Slack or a webhook.

## Requirements

- A Docker host
- Docker Compose or the Docker CLI
- At least one of the following notification destinations:
    - Slack Incoming Webhook
    - Slack bot token and channel
    - Webhook URL

## Run with Docker Compose

Download or clone the repository, then create a local configuration file.

```bash
cp config.example.yml config.yml
```

Configure at least one notification destination as shown below.

```yaml
notify:
  slack_webhook_url: "https://hooks.slack.com/services/..."
```

Start StackWatch.

```bash
docker compose up -d
docker compose logs -f
```

The included Compose file persists scan history in the `stackwatch-state`
volume. This state is required to preserve change-based notifications and
first-seen dates after the container is recreated.

## Run with Docker

```bash
docker run -d --name stackwatch \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/stackwatch/config.yml:ro" \
  -v stackwatch-state:/var/lib/stackwatch \
  ghcr.io/kitsunetrail/stackwatch:latest
```

## Set the timezone

`schedule.daily_at` is interpreted in the timezone specified by `TZ`. The
Compose example uses UTC by default. Change it to the timezone of the host as
needed.

```yaml
environment:
  - TZ=Asia/Tokyo
```

## Reference pages

- See [Configuration](configuration.md) for configuration options.
- See [Notification logic](how-it-works.md) for notification logic.
