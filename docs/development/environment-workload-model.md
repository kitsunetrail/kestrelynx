# Developing the Environment and Workload Model

- **Status:** Implemented (environment identification, the common workload/container model, recording into state, and notifications. A single state file still holds a single environment — consolidating multiple environments into one state file remains future work.)
- **Started:** August 25, 2026
- **Last updated:** August 29, 2026

## Purpose

Implement the capabilities deferred during the development of the [image identity model](image-identity-model.md):

- Identification that distinguishes multiple environments (Docker hosts, and in the future Kubernetes clusters)
- Mapping containers to the services (workloads) they belong to
- Reworking scan history so that records from multiple hosts can be handled in one state file

## Implementation

- **Environment identifier**
    - Runtime-derived values such as hostnames, Docker daemon IDs, and machine IDs are not used as identifiers: they may be unreadable from inside a container or change on reinstallation, and none of them stay stable across reboots and container recreation (confirmed during the image identity model work). A configuration-supplied `environment.name` is used as the environment identifier instead.
    - `environment.name` is validated as a DNS-1123 label (lowercase alphanumerics and hyphens, 1-63 bytes, starting and ending with an alphanumeric). An empty string is the unnamed default environment, a distinct, valid state rather than a failed validation. Uppercase, dots, underscores, whitespace, and control characters are all rejected rather than normalized: silently folding `"Prod"` into `"prod"` would mean the tool decides on its own whether two configured names should share history, and that decision is left to whoever can fix the config value.
    - Kind (currently fixed at `docker`) is not a configuration item. A config key for it could only ever record a value that might drift from the Runtime Adapter actually wired up, so the composition root (`main.go`) sets it mechanically from whichever adapter it assembled.
- **Common model for workloads and containers**
    - A Compose-launched container's Workload is resolved only when both `com.docker.compose.project` (project) and `com.docker.compose.service` (service) labels are present and valid. When either is missing, or a value is invalid (empty, over 253 bytes, or containing control characters), the whole thing stays `unknown` rather than being treated as "partially known" — the same rule the image identity model used to ban an intermediate state where canonical is false but ContentID is non-empty.
    - A container's display name (`Container.Name`) is never promoted into a Workload. Unlike a Compose service, it is a label an operator assigns per container at will, so it is kept as its own observed fact on `Container`, separate from Workload.
    - Docker-specific information — container IDs, raw non-Compose labels, and the `Names` array itself — stays inside the Docker adapter; only `Container{Name, Workload, Image}` crosses into the common model.
- **Adapter boundary: the primary observation moves from image to container**
    - The Docker adapter's `RunningImages` was replaced by `RunningContainers`. Container-level observation (which container is running what) is now the primary data, and the set of distinct images to scan (`inventory.DistinctImages`) is derived from it.
    - No additional Docker API call is made: Workload and the display name are both built from the `Names`/`Labels` fields already present in the same `/containers/json` response.
- **Incorporating scope into state: the key space is unchanged**
    - At design time, whether the image identity model's approach (unchanged keys, only added fields) would still work was an open question, since a scope key touches the history subject itself rather than sitting alongside it. In the implementation, the same approach applied directly: Environment was not added to the Findings/EOSL keys at all, only kept as a self-descriptive additional field, `State.Environment` (`environment` on disk). `Compute` and the diff rules never read it.
    - The reason is backward compatibility with older binaries: downgrading simply ignores the `environment` field, so it never triggers a re-notification. Because naming, renaming, and un-naming an environment never change any history key, an existing finding's `FirstSeen` is preserved through all of them, which structurally guarantees zero re-notifications from any of the three.
    - The unnamed default environment (`environment.name` unset) omits the `Environment` field entirely (`omitempty` plus a nil pointer), so an unconfigured user's state file stays byte-for-byte identical to the pre-Environment format.
    - **A single state file still holds a single environment.** Consolidating multiple environments' history into one state file is out of scope for this phase and remains future work. If a future phase changes the key space itself to merge multiple environments into one state file, the "just add a field" approach used here will not be enough — an explicit format migration, plus a policy for behaving safely on downgrade at switchover, will need to be designed separately.
- **Notifications: Slack stays a summary, the webhook carries everything**
    - The Slack product header gets the environment name inserted once, right at the start of the message, only when one is configured (`🛡️ *KestreLynx* [prod] — ...`). The unnamed default renders exactly the pre-existing text. Renderers with no header line of their own (the thread report) are unaffected.
    - Workload and container information is not sent to Slack at all — only the generic webhook carries it, extending the existing "Slack summarizes, the webhook carries everything" policy.
    - The webhook payload was extended additively: a top-level `environment {kind, name}` (`kind` is always present; `name` is omitted only for the unnamed default), and a `containers` array (name plus workload) on every image entry. An unknown workload is still written out explicitly as `"kind": "unknown"` rather than omitted, so a receiver can tell "this payload doesn't carry workloads at all" (an older version) apart from "workload association could not be determined" (this cycle). No existing field was changed.

## Constraints

- Discovery remains read-only.
- Existing single-host Docker users must be able to keep the same basic setup and notification behavior without additional configuration.
- If an identifier is unavailable or a mapping is unknown, represent that state instead of guessing.
- Runtime-specific identifiers must not leak into the shared analysis model.
- The semantics of the image content identifier (the image config digest) do not change in this phase; environments and workloads are added as layers around it.

## Update history

### August 29, 2026

- Implemented the environment and workload model. The new `inventory` package defines the common vocabulary of Environment/Workload/Container/RunningImage, and the Docker adapter's observation unit switched from `RunningImages` to `RunningContainers`.
- Added an optional `environment.name` (DNS-1123 label) to configuration, and carried Environment and container information consistently through `analyze.Build`, state, and Slack/webhook notifications.
- State keeps its existing keys and version; `Environment` is recorded only as a self-descriptive additional field. A copy of the production state file was verified to load without conversion, and both Slack output and the state file's bytes were confirmed unchanged for the unnamed default environment, in tests and against that copy. Naming, renaming, and un-naming the environment were all confirmed to produce zero re-notifications.
- Consolidating multiple environments' history into one state file was not attempted; a single state file still holds a single environment, left as future work.

### August 25, 2026

- Organized the implementation scope of the environment and workload model.
