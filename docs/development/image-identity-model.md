# Developing the Image Identity Model

- **Status:** Implemented (image content identity; Docker, single host — container-to-service mapping and multi-host identification are future work)
- **Started:** August 22, 2026
- **Last updated:** August 23, 2026

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

## Decisions

The two questions previously under consideration were settled by fixing the scope of this phase to a single Docker host.

- **Docker host identification is not attempted in this phase.** Tracking history from multiple hosts in one state file needs an identifier saying "which host this record belongs to", but no candidate was stable enough: KestreLynx itself runs in a container so it cannot simply read the host's hostname, and daemon IDs or machine IDs change on reinstallation, so nothing reliably survives reboots and container recreation. The single-host assumption makes this identification unnecessary (the state's `image reference + package` keys are collision-free only under it). Handling multiple hosts or multiple runtimes is a future phase; when that happens, the history subject gains a stable, configuration-supplied scope key (Environment / Workload) rather than a runtime-derived identifier.
- **Mapping a container to the service it belongs to is not attempted in this phase.** For Compose-launched containers, labels such as `com.docker.compose.service` tell us which service a container belongs to, but containers started directly with `docker run` simply carry no such information. This phase does not attempt the container-to-service mapping at all: runtime-specific information such as Compose labels and container IDs stays inside the Docker adapter, and only `Ref`, `ContentID`, and `RegistryDigests` cross into the common model. The mapping will be handled by a future workload model.

## Update history

### August 23, 2026

- Implemented the image identity model. The `ImageID` reported by Docker becomes the `ContentID` after boundary validation (`sha256:` + 64 hex digits); resolved images are scanned by `ContentID` (with `--image-src docker`), while unresolved images fall back to scanning by reference and notifications state explicitly that the match with the running content is unconfirmed.
- State keeps its existing keys and version; `ContentID` and `Images` (per-reference digest sets) are recorded as additional fields, and image replacements are delivered as a single notification line. A copy of the production state file was verified to load without conversion.
- When only some of the entities behind one reference fail to scan, findings are conservatively merged with the previous cycle and resolution decisions are deferred, preventing false notifications.
- The two open questions (how to identify a host, how to map containers to services) moved to decisions by making the single-host assumption explicit.

### August 22, 2026

- Because a mutable tag can point a scan to a different image from the one running, we decided to separate the display name from the content identifier.
- Because `RepoDigests` can be absent from local images or contain multiple values, we selected `ImageID` to identify image content and run scans by digest.
- Using the digest as the history key would cause unnecessary re-notifications, so image names remain the history and notification keys while the digest records changes to the underlying image.
- The first phase targets a single Docker host. Multiple hosts and Kubernetes will be supported by adding runtime adapters.

---

This article is part of the KestreLynx development log. [Learn more about KestreLynx](../index.md)
