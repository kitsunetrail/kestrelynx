# Developing the Environment and Workload Model

- **Status:** In design
- **Started:** August 25, 2026
- **Last updated:** August 26, 2026

## Purpose

Implement the capabilities deferred during the development of the [image identity model](image-identity-model.md):

- Identification that distinguishes multiple environments (Docker hosts, and in the future Kubernetes clusters)
- Mapping containers to the services (workloads) they belong to
- Reworking scan history so that records from multiple hosts can be handled in one state file

## Implementation scope

- **A stable identifier for an environment**
    - Runtime-derived values such as hostnames, Docker daemon IDs, and machine IDs are not stable across reboots and container recreation: they may be unreadable from inside a container or change on reinstallation (confirmed during the image identity model work).
    - The design will therefore use a stable, configuration-supplied scope key as the environment identifier rather than a runtime-derived value. We need to decide how names are chosen, what happens when one is changed or renamed, and how environments map to runtime adapter kinds (Docker, Kubernetes, and so on).
- **A common model for workloads and containers**
    - Compose-launched containers reveal their service through labels, but containers started directly with `docker run` carry no such information at all. When the mapping does not exist, it is represented as "unknown" instead of guessed.
    - Runtime-specific information such as Compose labels and container IDs currently stays inside the Docker adapter. Representing workloads requires redefining what crosses that boundary into the common model.
- **Incorporating scope into scan history (state) and migrating**
    - Adding environments or workloads as history subjects requires changing or extending the state key space.
    - The image identity model achieved zero migration and zero re-notification by keeping keys unchanged and only adding fields; because scope keys touch the history subject itself, we need to examine whether the same approach still works. A migration scheme that keeps existing users' state intact and avoids unnecessary re-notifications at switchover must be designed before any key is added.

## Constraints

- Discovery remains read-only.
- Existing single-host Docker users must be able to keep the same basic setup and notification behavior without additional configuration.
- If an identifier is unavailable or a mapping is unknown, represent that state instead of guessing.
- Runtime-specific identifiers must not leak into the shared analysis model.
- The semantics of the image content identifier (the image config digest) do not change in this phase; environments and workloads are added as layers around it.

## Update history

### August 25, 2026

- Organized the implementation scope of the environment and workload model.
