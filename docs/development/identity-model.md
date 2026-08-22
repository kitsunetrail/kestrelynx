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

## Logic

- **Image content is identified by the `ImageID` (the image config digest) reported by Docker.**
  - Registry-side digests (RepoDigests) do not exist for locally built images and can hold multiple values, so they are not used as identifiers; they are kept as display attributes.
  - When a digest cannot be obtained, the image is treated as "unverified" instead of guessing, and that state is made visible in notifications.
- **Scans are executed by digest, not by image name.**
  - Scanning by name risks examining a different image than the running one if the tag moves just before the scan.
  - Specifying the digest guarantees that exactly the running image is scanned.
- **Scan history and notifications remain keyed by image name, as they are today.**
  - Keying history by digest would re-notify all vulnerabilities as "resolved + new" on every image update; keeping the name as the key means existing state files keep working without conversion and no migration step is needed.
  - Digests are recorded as additional information, and an image replacement appears as a single informational line in notifications.
- **This phase targets a single Docker host.**
  - When extending to multiple hosts or Kubernetes, adapters are added while keeping the identifier semantics (the image config digest) shared.
  - If a runtime cannot provide a digest with this meaning, the image is treated as unverified.

## Questions under consideration

- How should a Docker host be identified so it remains the same host after restarts or container recreation?
- Which service should a container started without Compose belong to?

## Development log

- Started organizing the current scan process and defining the identity model
- Created the identity model development document
- Decided the identifier choice, scan method, and history migration approach
