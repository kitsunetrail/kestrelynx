---
title: Enabling remediation plans and pull requests on Docker
---

# Enabling remediation plans and pull requests on Docker

Enable remediation plans and pull requests for Compose services and containers started with `docker run`.
Complete the shared preparation in [Enabling remediation plans](remediation-setup.md#enable-fix-plans) first.

If you only want to check candidates for published images without configuring mappings, set only `remediation.enabled: true` and `remediation.pull_requests.enabled: false` in the host's `config.yml`, then proceed to [Verifying remediation plans](#verify-fix-plans).
If you configure mappings, use the section matching how the monitored containers are started, then [verify remediation plans](#verify-fix-plans) and [enable pull requests](#docker-enable-pull-requests).
Choose the commands for applying the configuration based on how KestreLynx itself is started.

Edit the host's `config.yml` in the KestreLynx deployment directory.
The file created in [Prepare the configuration](getting-started.md#prepare-config) is mounted at `/etc/kestrelynx/config.yml` inside the container.

Merge the examples into the existing configuration without adding a duplicate `remediation` section.
See [Terms](remediation.md#terms) for the terminology used on this page.

## Mapping Compose services {#compose-mappings}

Map Compose services to the files to update in a GitHub repository.

### Identifying the workload key {#identify-workload}

Identify the workload key for the mapping from the running container's Compose labels.

1. Replace `<container-name>` with the target running container's name and run `docker inspect <container-name>`
2. Note the values of the `com.docker.compose.project` and `com.docker.compose.service` labels
3. Use the label values to construct the workload key `compose/<project>/<service>`

If the target container's project is `example` and its service is `web`, the service's workload key is `compose/example/web`.
The Compose project name can differ from the repository or directory name, so use the label value from the running container.

### Configuring the mapping {#compose-mapping-example}

Specify the file to update using the configuration keys selected in the shared [source mapping instructions](remediation-setup.md#map-source).

1. Replace the workload key, GitHub repository, branch, target file, and service name in the example below with their actual values
2. Merge the following configuration into `remediation` in the host's `config.yml`

    This example is for updating an image tag in a Compose file.
    `path: compose.yml` refers to a file at the root of the GitHub repository `example/deployment`.

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: compose/example/web
          repository: example/deployment
          base_branch: main
          compose:
            path: compose.yml
            service: web
    ```

    This example updates the Dockerfile and dependency files of an application you build and run with Compose.
    Instead of the image tag example, merge the following configuration into `remediation` in the host's `config.yml`.

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: compose/example/web
          repository: example/application
          base_branch: main
          dockerfile:
            path: Dockerfile
          dependencies:
            directory: .
    ```

    `path: Dockerfile` and `directory: .` are relative to the root of the GitHub repository `example/application`.

See [Compose settings](configuration.md#remediation-mappings-compose) for configuration keys and constraints on multiple mappings, and [basic settings](configuration.md#remediation-basics) for the enablement keys.

## Mapping docker run containers {#docker-run-mappings}

In Docker mode, map containers started without Compose by their names.
For published images, KestreLynx does not create PRs that change the image tag used to start the container.

To update a Dockerfile or dependency files on GitHub, follow these steps.

1. Run `docker ps --format '{{.Names}}'` to check the running container's name assigned with `docker run --name`
2. Replace the example values below with actual values and merge the configuration into `remediation` in the host's `config.yml`

    This example maps the Dockerfile and dependency directory for `example-api` in one entry.
    Use `dockerfile` for base image updates and `dependencies` for language package updates.

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: false
      mappings:
        - workload: container/example-api
          repository: example/application
          base_branch: main
          dockerfile:
            path: Dockerfile
          dependencies:
            directory: .
    ```

    Within the GitHub repository `example/application`, `path: Dockerfile` refers to the file at the root, and `directory: .` refers to the root directory.

    If the repositories or branches differ, use separate entries with the same `workload`.
    See the shared [source mapping instructions](remediation-setup.md#map-source) for preparing dependency directories and [docker run settings](configuration.md#remediation-mappings-docker-run) for name and configuration constraints.

When recreating a container for the same application, specify the same name with `docker run --name`.
KestreLynx does not verify that the container was built from the specified repository, so do not reuse its name for another application.

Reusing a name can cause PRs based on another application's findings to be created in the repository still named in the configuration.
See [docker run containers](remediation-reference.md#docker-run-containers) for when containers are included and image store limitations.

## Verifying remediation plans {#verify-fix-plans}

Apply the configuration and verify that remediation plans are enabled and have processed the targets.
The following commands use the configuration from the [setup guide](getting-started.md); run them in the directory containing the host's `config.yml`.

1. Recreate the container using the commands for how KestreLynx itself is started

    - If started with Compose, run the following

        ```sh
        docker compose up -d --force-recreate kestrelynx
        ```

    - If started with `docker run`, run the following

        ```sh
        docker stop kestrelynx
        docker rm kestrelynx
        docker run -d --name kestrelynx \
          --restart unless-stopped \
          -e TZ=UTC \
          -v /var/run/docker.sock:/var/run/docker.sock:ro \
          -v "$PWD/config.yml:/etc/kestrelynx/config.yml:ro" \
          -v kestrelynx-state:/var/lib/kestrelynx \
          ghcr.io/kitsunetrail/kestrelynx:latest
        ```

    If you customized the startup options, retain those values and do not delete the `kestrelynx-state` volume.

2. Run `docker compose logs -f kestrelynx` for Compose, or `docker logs -f kestrelynx` for `docker run`
3. In the startup log `fix plan enabled`, verify that `mappings` equals the configured number of mappings and that `pull_requests=false`
4. In the scan after startup or at the next scheduled time, check for `scanned image` for the target image and `fix plan built` for the remediation plan

    Zero values for the candidate counts `update_candidate`, `dependency_update_candidates`, and `dockerfile_update_candidates` do not mean that plans are disabled.
    `fix plan enabled` and `fix plan built` confirm enablement and plan creation.

5. When a notification arrives, check that the workload, source, and update target are as intended using the [displayed fields](remediation-results.md#slack-fields)

If startup fails, check the error message in the log and the [remediation plan and pull request settings](configuration.md#remediation).
If you cannot find a plan, follow [checking for a missing plan](remediation-troubleshooting.md#check-missing-plan).

## Enabling remediation pull requests {#docker-enable-pull-requests}

After [verifying plans](#verify-fix-plans) and reviewing the shared [PR creation prerequisites and precautions](remediation-setup.md#enable-pr-creation), enable remediation pull request creation using the following steps.

1. In the host's `config.yml`, set the following values under `remediation`, retaining the existing mappings, credentials, and storage location

    ```yaml
    remediation:
      enabled: true
      pull_requests:
        enabled: true
    ```

2. In the directory containing the host's `config.yml`, recreate the container using the same commands as step 1 of [Verifying remediation plans](#verify-fix-plans)

3. Run `docker compose logs -f kestrelynx` for Compose, or `docker logs -f kestrelynx` for `docker run`, and check that `fix plan enabled` includes `pull_requests=true`

4. In the next cycle’s notification, check the “Pull request” and “Update” lines against [Displayed fields](remediation-results.md#slack-fields) to verify the PR status and update contents

For npm, pnpm, pip, uv, Go, and Gradle updates, KestreLynx uses the Docker API to create, start, and remove work containers.
Maven updates do not use work containers.

The Docker socket's `:ro` mount does not restrict API operations, so the supplied Compose configuration does not need to change to `:rw`.

If you use a Docker API proxy, allow work container creation, startup, and removal.
If no PR is created, see [checking for a missing PR](remediation-troubleshooting.md#check-missing-pr).
