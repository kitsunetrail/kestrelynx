# Setup instructions

KestreLynx runs as one container per Docker host or as a single-replica Deployment inside a Kubernetes cluster.
It can also scan a Kubernetes cluster by connecting to its API server from a Docker container outside the cluster.

It discovers and scans the images used by running containers, then sends the results to Slack, email, or a webhook.

## Requirements

- An environment suited to how you run KestreLynx:
    - To scan a Docker host, a Docker host with Docker Compose or the Docker CLI
    - To run inside a Kubernetes cluster, a cluster with `kubectl` access and persistent storage
    - To connect from outside a Kubernetes cluster, a cluster with `kubectl` access and a Docker host with the Docker CLI and access to the API server
- At least one of the following notification destinations:
    - Slack Incoming Webhook
    - Slack bot token and channel
    - Webhook URL
    - Email over TLS-only SMTP

## Prepare the configuration {#prepare-config}

Create a `config.yml` file for use with Docker, Docker Compose, or connections from outside a Kubernetes cluster.

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

You can [deploy inside the cluster](#kubernetes-steps) or [connect from outside the cluster](#kubernetes-outside).
Choose the instructions that suit your environment.

- One instance covers one cluster.
- Trivy fetches images from the registry, so KestreLynx needs registry access from wherever it runs.

### Run inside the cluster {#kubernetes-steps}

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
    - This command does not apply `work/`, so apply it separately following [Work Pod configuration](remediation-setup-work-pods.md#kubernetes-language-updates) only if you use language-package updates.

!!! warning "Do not run two copies"

    Do not change the replica count of 1 or the `Recreate` strategy in `deployment.yaml`, and do not share one state volume between two instances.
    Two Pods writing state data at the same time corrupt the scan history.

### Authenticate to private registries inside the cluster {#kubernetes-private-registry}

When running outside the cluster, configure `registries` directly in `config.yml`, so this procedure is unnecessary.

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

### Run outside the cluster {#kubernetes-outside}

Run KestreLynx on a Docker host outside the cluster and connect to the API server to scan the cluster.
Language-package updates using work Pods have not been verified in this setup. For details, see [Connecting from outside the cluster](configuration.md#scan-target-outside) on the configuration page.

1. Follow [Prepare the configuration](#prepare-config) to clone the repository and create `config.yml`.

2. Run the following commands to create the namespace and a ServiceAccount with read-only permissions.

    ```bash
    kubectl create namespace kestrelynx
    kubectl apply -f deploy/kubernetes/serviceaccount.yaml \
      -f deploy/kubernetes/clusterrole.yaml \
      -f deploy/kubernetes/clusterrolebinding.yaml
    ```

3. Run the following commands to create a non-expiring ServiceAccount token as a Secret and wait for the token to be created.

    ```bash
    kubectl apply -f - <<'EOF'
    apiVersion: v1
    kind: Secret
    metadata:
      name: kestrelynx-token
      namespace: kestrelynx
      annotations:
        kubernetes.io/service-account.name: kestrelynx
    type: kubernetes.io/service-account-token
    EOF
    kubectl wait -n kestrelynx secret/kestrelynx-token --for=jsonpath='{.data.token}'
    ```

4. Run the following commands in the directory containing `config.yml` to save the token and the cluster CA certificate to files.

    ```bash
    kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.token}' | base64 -d > token
    kubectl get secret -n kestrelynx kestrelynx-token -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
    chmod 600 token
    ```

    - Do not commit `token` to the repository because it contains credentials that grant read access to the cluster.

5. Edit `config.yml` to enable the commented-out `kubernetes` section with the following contents.

    ```yaml
    kubernetes:
      enabled: true
      api_server: "https://kubernetes.example.com:6443"
      token_file: /etc/kestrelynx/token
      ca_file: /etc/kestrelynx/ca.crt
    ```

    - Set `api_server` to an API server URL reachable from the KestreLynx container and use the following command to check the URL used by `kubectl` (note that `127.0.0.1` inside the container does not refer to the Docker host).

        ```bash
        kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
        ```

    - If the URL's hostname or address is not included in the API server certificate, set `tls_server_name` following [Connecting from outside the cluster](configuration.md#scan-target-outside).
    - To scan images from private registries, add `registries` to the same `config.yml` following [Image registry authentication](configuration.md#registries).

6. Run the following commands to start KestreLynx and check the logs.

    ```bash
    docker run -d --name kestrelynx \
      --restart unless-stopped \
      -e TZ=UTC \
      -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
      -v "$PWD/token:/etc/kestrelynx/token:ro" \
      -v "$PWD/ca.crt:/etc/kestrelynx/ca.crt:ro" \
      -v kestrelynx-state:/var/lib/kestrelynx \
      ghcr.io/kitsunetrail/kestrelynx:latest
    docker logs -f kestrelynx
    ```

    - The `kestrelynx-state` volume preserves scan history and the intel feed cache, so do not delete this volume.

## Remediation plans and pull requests {#remediation}

See the [remediation overview](remediation.md#overview) for an overview of the feature on Docker and Kubernetes.

| Action | Instructions |
| --- | --- |
| Enable update candidate planning | [Enabling remediation plans](remediation-setup.md#enable-fix-plans) |
| Enable GitHub PR creation | [Enabling fix pull requests](remediation-setup.md#enable-pull-requests) |

## Set the timezone

`schedule.daily_at` is interpreted in the timezone specified by `TZ`, which defaults to UTC.

- When running with Docker or outside a Kubernetes cluster, change `-e TZ=UTC` in the `docker run` command in the corresponding instructions.
- When running with Docker Compose, change `TZ=UTC` in `docker-compose.yml`.
- When running inside a Kubernetes cluster, change the `TZ` environment variable in `deploy/kubernetes/deployment.yaml`.

For example, specify `TZ=Asia/Tokyo` to use Japan Standard Time.

## Reference pages

- [Configuration](configuration.md) — configuration options and defaults
- [Scan notification conditions](notification-conditions.md#notification-conditions) — delivery conditions for each notification mode
