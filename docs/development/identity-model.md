# Developing the Identity Model

- **Status:** In progress
- **Started:** August 22, 2026
- **Last updated:** August 22, 2026

## Purpose

KestreLynx currently starts scans from image names obtained from Docker.

However, a mutable tag such as `example/api:latest` may point to different content over time.
The same image may also be used by multiple containers or workloads. Continuing to use names as identifiers creates these problems:

- Which image was scanned?
- Which workload is using that image?
- Do differently named images point to the same content?
- Did a later scan examine the same content or a replacement?

We will replace this assumption with a common, read-only identity model.
Docker, Kubernetes, and other environments will each provide their own container and image discovery implementation, while vulnerability scanning, prioritization, change tracking, and notification remain shared.

## Implementation approach

We will make it possible to trace which service runs which image in each environment, and which vulnerabilities were found in that image.
For example, we will associate a Docker host, Compose service, running container, image in use, scan result, and detected vulnerabilities.
An image will be identified not only by a readable name such as `nginx:latest`, but also by a `sha256:...` digest that identifies its actual content.

```text
Docker host: home-server
  └─ Compose service: myapp / web
       ├─ Running container: myapp-web-1
       └─ Image in use
            ├─ Name: ghcr.io/example/myapp:latest
            └─ Content: sha256:abc123...
                 └─ Scan result
                      └─ Package: openssl
                           └─ Vulnerability: CVE-2026-12345
```

When Kubernetes support is added, information obtained from Pods and Deployments will be organized into the same relationships so the existing scanning, analysis, and notification code can be used.
The Docker integration will be the first runtime adapter. The adapter discovers running objects and converts them into the common model.
Scanning, vulnerability analysis, state comparison, and notification will remain shared processes.

## Constraints

- Discovery remains read-only.
- Existing Docker users must be able to keep the same basic setup and notification behavior.
- Human-readable image references remain visible even when the internal scan identity moves to an immutable digest.
- Runtime-specific identifiers must not leak into the shared analysis model.
- If an identifier is unavailable or ambiguous, represent that state instead of guessing.

## Questions under consideration

- How should a Docker host be identified so it remains the same host after restarts or container recreation?
- Which service should a container started without Compose belong to?
- Which digest should be used to avoid scanning the same image more than once?
- How can the identity method change without causing unnecessary notifications from existing scan history?

## Development log

- Started organizing the current scan process and defining the identity model
- Created the identity model development document
