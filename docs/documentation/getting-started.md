# Setup instructions

KestreLynx runs as one container per Docker host or as a single-replica Deployment
inside a Kubernetes cluster. It discovers and scans the images used by running
containers, then sends the results to Slack, email, or a webhook.

## Requirements

- A Docker host with Docker Compose or the Docker CLI, or a Kubernetes cluster
  with `kubectl` access and persistent storage
- At least one of the following notification destinations:
    - Slack Incoming Webhook
    - Slack bot token and channel
    - Webhook URL
    - Email over TLS-only SMTP

## Prepare the configuration {#prepare-config}

Create a `config.yml` file for use with Docker and Docker Compose.

1. Download or clone the repository, then create `config.yml`.

    ```bash
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    cp config.example.yml config.yml
    ```

2. Configure at least one notification destination under `notify` in the `config.yml` file created in step 1.

    ```yaml
    notify:
      slack_webhook_url: "https://hooks.slack.com/services/..."
    ```

## Run with Docker

Run the following commands in the directory containing the `config.yml` file created in [Prepare the configuration](#prepare-config) to start KestreLynx and check the logs.

```bash
docker run -d --name kestrelynx \
  --restart unless-stopped \
  -e TZ=UTC \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
  -v kestrelynx-state:/var/lib/kestrelynx \
  ghcr.io/kitsunetrail/kestrelynx:latest
docker logs -f kestrelynx
```

- The `kestrelynx-state` volume preserves scan history and the intel feed cache, so do not delete this volume.

## Run with Docker Compose

Start KestreLynx in the directory containing the `config.yml` file created in [Prepare the configuration](#prepare-config).

```bash
docker compose up -d
docker compose logs -f
```

- The `kestrelynx-state` volume preserves scan history and the intel feed cache, so do not delete this volume.

## Run on Kubernetes

Edit and apply the manifests in `deploy/kubernetes/`.

- One instance covers one cluster.
- Trivy fetches images from the registry, so the scanner Pod needs registry access.

### Start KestreLynx {#kubernetes-steps}

1. Download the repository or clone it with the following commands.

    ```bash
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. Edit `deploy/kubernetes/configmap.yaml`.

    - Configure at least one notification destination.

        ```yaml
        data:
          config.yml: |
            notify:
              slack_webhook_url: "https://hooks.slack.com/services/..."
        ```

    - To scan only specific namespaces, list them in `kubernetes.namespaces` (the default is all namespaces).
    - If multiple instances post to one Slack channel, set `environment.name` to a name that distinguishes the instance.
    - See [Configuration](configuration.md) for other settings.

3. Edit the storage settings in `deploy/kubernetes/pvc.yaml` to suit your cluster.

    - The default is 1 GiB with `ReadWriteOnce` access.
    - This PVC preserves scan history, first-seen dates, and the intel feed cache, so these persist after Pod recreation.

4. Run the following command to create the namespace.

    ```bash
    kubectl create namespace kestrelynx
    ```

5. Follow [Authenticate to private registries](#kubernetes-private-registry) only if you scan images from private registries.

6. Run the following commands to apply the manifests, wait for KestreLynx to start, and then check the logs.

    ```bash
    kubectl apply -f deploy/kubernetes/
    kubectl rollout status -n kestrelynx deployment/kestrelynx
    kubectl logs -n kestrelynx deployment/kestrelynx -f
    ```

    - This creates a ServiceAccount, a read-only ClusterRole and its ClusterRoleBinding, a ConfigMap, a PVC, and a Deployment.
    - This command does not apply `work/`, so apply it separately following [Work Pod configuration](remediation-setup.md#kubernetes-language-updates) only if you use language-package updates.

!!! warning "Do not run two copies"

    Do not change the replica count of 1 or the `Recreate` strategy in `deployment.yaml`, and do not share one state volume between two instances.
    Two Pods writing state data at the same time corrupt the scan history.

### Authenticate to private registries {#kubernetes-private-registry}

KestreLynx does not read inside Pods; it fetches the images used by Pods from registries to scan them, so images in private registries require credentials.
It does not reuse Pod `imagePullSecrets`.

1. Run the following command to create `config.yml` from the configuration in `deploy/kubernetes/configmap.yaml`.

    ```bash
    sed '1,/config.yml: |/d; s/^    //' deploy/kubernetes/configmap.yaml > config.yml
    ```

    - Do not commit this file to the repository because it contains passwords.

2. Add `registries` to the `config.yml` you created in step 1.

    ```yaml
    registries:
      - host: registry.example.com
        username: example-puller
        password: "example-read-token"
    ```

    - See [Image registry authentication](configuration.md#registries) for each key, including `token_hosts`.
    - For Docker Hub, specify `host: docker.io` and `token_hosts: [auth.docker.io]`.

3. Create a Secret from the `config.yml` you created in step 1.

    ```bash
    kubectl create secret generic kestrelynx-config \
      --namespace kestrelynx \
      --from-file=config.yml=config.yml \
      --save-config
    ```

4. Change the `config` volume in `deploy/kubernetes/deployment.yaml` to use the Secret.

    ```yaml
    - name: config
      secret:
        secretName: kestrelynx-config
    ```

If credentials are missing or incorrect, the image appears in notifications as a scan failure.

After moving the configuration to a Secret, use the following commands to apply configuration changes, including when other pages instruct you to apply a ConfigMap.

```bash
kubectl create secret generic kestrelynx-config \
  --namespace kestrelynx \
  --from-file=config.yml=config.yml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart -n kestrelynx deployment/kestrelynx
```

## Remediation plans and pull requests {#remediation}

See the [remediation overview](remediation.md#overview) for an overview of the feature on Docker and Kubernetes.

| Action | Instructions |
| --- | --- |
| Enable update candidate planning | [Enabling remediation plans](remediation-setup.md#enable-fix-plans) |
| Enable GitHub PR creation | [Enabling fix pull requests](remediation-setup.md#enable-pull-requests) |

## Set the timezone

`schedule.daily_at` is interpreted in the timezone specified by `TZ`, which defaults to UTC.

- When running with Docker, change `-e TZ=UTC` in the `docker run` command.
- When running with Docker Compose, change `TZ=UTC` in `docker-compose.yml`.
- When running on Kubernetes, change the `TZ` environment variable in `deploy/kubernetes/deployment.yaml`.

For example, specify `TZ=Asia/Tokyo` to use Japan Standard Time.

## Reference pages

- [Configuration](configuration.md) — configuration options and defaults
- [Scan notification conditions](notification-conditions.md#notification-conditions) — delivery conditions for each notification mode
