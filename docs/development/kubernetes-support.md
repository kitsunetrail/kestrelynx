# Developing Kubernetes Support

- **Status:** In development (identity model implemented; adapter design settled)
- **Started:** September 6, 2026
- **Last updated:** September 7, 2026

## Purpose

Connect Kubernetes workloads to the scan → prioritize → diff-notification pipeline already implemented for Docker hosts: scan running images with Trivy, prioritize findings using CISA KEV and EPSS, and notify changes through Slack and webhooks.

This page records the initial plan, settled adapter design, and implementation progress. Implementation findings, verified configurations, and remaining questions will be added as development proceeds.

The preceding [Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md) records the research behind this work. This log focuses on the implementation plan and progress.

## Planned scope

| Area | Planned behavior |
| --- | --- |
| Discovery | Retrieve Pods and Workloads through read-only access to `kube-apiserver`. Cover Deployment, StatefulSet, DaemonSet, Job, and CronJob. Pods whose owners cannot be determined remain `unknown`; ownership is not guessed. |
| Observed information | Collect Pod `imageID` and `OwnerReference` information to associate running images with their Workloads. |
| Deployment owners | Cover plain manifests and marker-based detection of Helm, Argo CD, and Flux, resolving deployment-owner candidates using the common relation model. Supported methods will be documented as they are verified. |
| Image processing | Normalize and validate `imageID`, then suppress duplicate scans of the same digest under the identity rules below. |
| Installation | Use an in-cluster deployment with a read-only ServiceAccount as the first-choice installation method. |
| Prioritization and notifications | Connect the discovered images and Workloads to the existing KEV/EPSS prioritization and diff notifications for new, worsened, and resolved findings. |

**Correction to the initial plan (September 7):** Kustomize is removed from the deployment-owner detection list. It is client-side templating and leaves no marker on applied objects, so there is no detection basis. Helm, Argo CD, and Flux remain as marker-based detection targets.

## Non-goals for this stage

- Mutating Workloads. Discovery remains read-only.
- Observing runtime behavior on nodes or deploying privileged agents.
- Adding direct registry access to KestreLynx itself. This remains outside the scope, consistent with existing behavior; Trivy handles image fetching for the adapter's remote scanning path.

## Image identity

- Digest kinds remain distinct and are not mixed in one untyped identifier. The typed `Digest` defined in the [remediation relations model](remediation-relations-model.md) is now implemented in the common inventory model.
    - `config` — the **OCI image config digest** used by the existing Docker path to identify image content.
    - `registry` — the **registry-side digest** reported by a Kubernetes Pod's `imageID`.
- `Platform`, `EntityKey`, and `ImageSubject` are also implemented in the common inventory model: `Platform` represents OS, architecture, and variant; `EntityKey` is the identity key; and `ImageSubject` is the observation subject consisting of a reference and an optional key.
- Identity comparison using a registry digest requires both the digest and the platform (OS and architecture), because a registry digest may identify a multi-platform index. Platform participates in `EntityKey` only for registry digests; config digests identify an entity on their own.
    - If the platform is unknown, no identity key is constructed, and deduplication and result sharing are not performed on that basis.
- The running-image type, `RunningImage`, now carries a typed config digest instead of an untyped string, and Docker boundary validation is centralized in `ParseDigest`. Existing tests verify that behavior for Docker users is unchanged.
- The linked model describes the full comparison rules and the requirements for confirming that a scan matches the observed image.

This is the first implementation step. Connecting these types through scanning, deduplication, and notifications is next; Kubernetes discovery and scanning are not yet implemented.

## Initial supported configurations (planned)

The first formally supported target will be **K3s + containerd**, because we can continuously verify this configuration ourselves in real environments. The table below describes the verification plan; it is not a list of configurations already supported.

| Item | Initial plan |
| --- | --- |
| OS and CPU | Limit initial verified support to linux/amd64, with Ubuntu LTS as the baseline candidate. Fix exact versions during verification. Other platforms use the same code path but are labeled unverified. Add arm64 to verified support only if continuous verification on real hardware is possible. |
| Kubernetes | Target Kubernetes 1.29 or later for initial verified support. Fix exact component versions during verification. |
| Workload kinds | Deployment, StatefulSet, DaemonSet, Job, and CronJob. Pods with unknown owners remain `unknown`. |
| Installation | In-cluster deployment with a read-only ServiceAccount. |
| Registries | Verify public images and images from at least one authenticated private registry. |
| Owner mapping | Keep the common relation model and build a support table from methods actually verified, for example starting with Helm. |
| Verification | Use kind clusters as the source for recorded API fixtures, and run CI regression tests against those fixtures without a live cluster. Use a real K3s environment for operational checks. Success in a test environment alone does not establish formal support for another distribution. |

**Correction to the initial plan (September 7):** “Use kind for regression tests” meant using kind as the source of API fixtures, not running kind directly in CI. The verification strategy above makes this distinction explicit.

EKS, GKE, and AKS are not in the initial support list because we cannot continuously verify them yet. The implementation will use the common Kubernetes API so these services can be added once continuous verification of authentication, permissions, registry access, and scanning in real environments becomes sustainable.

CRI-O remains an unverified follow-up candidate. Exact versions and verification results will be recorded during implementation.

## Settled decisions for the adapter design

The adapter design is settled; implementation is upcoming. The following decisions define the planned behavior and initial-support conditions.

- **Kubernetes API client** — Implement a minimal read-only HTTP client that connects to `kube-apiserver` using a ServiceAccount token and CA.
    - Make only paginated LIST requests, since the required API surface is limited to paginated LISTs of GA resources.
    - Do not add a client-go dependency: a measured minimal client-go Pod-list program is about 26.6 MB, compared with the current full binary at about 7.7 MB.
- **Scanning path** — Have Trivy fetch image content from the registry with `--image-src remote`.
    - Pin the image by digest and specify an explicit `--platform`.
    - Do not scan through the containerd socket, because it requires privileged host access and a per-node agent, both non-goals.
- **Registry conditions** — Require registry reachability and authentication from the scanner Pod.
    - Initial support excludes K3s `registries.yaml` mirrors and rewrites.
    - Initial support excludes images that exist only preloaded on nodes.
    - Initial support excludes digests deleted from the registry.
    - Air-gapped clusters are outside the initial scope.
- **Bare imageID** — Treat a bare `sha256:...` imageID without a repository part as unresolved but normal, not an error, since it can occur for preloaded or imported images.
    - Scan such images by reference and report them as “identity unconfirmed”.
    - Never use these results as a false basis for marking findings resolved.
    - This fallback does not add support for images available only on nodes.
- **Resolution correctness** — Never report previously recorded findings as resolved based on results from a scan with unconfirmed image identity.
    - Apply existing conservative retention.
    - Have notifications state that previous findings are being retained instead of claiming “all clear”.
- **Container targets** — Include native sidecars, meaning init containers with `restartPolicy: Always`, in scan targets.
    - Exclude ordinary init containers.
- **Verified support** — Limit initial verified support to linux/amd64 and Kubernetes 1.29 or later.
    - Other platforms use the same code path but are labeled unverified.
- **Configuration** — Add a `kubernetes` section with an explicit `enabled` opt-in.
    - The Kubernetes and Docker adapters are mutually exclusive; explicitly configuring both is a startup error.

## Questions to validate during implementation

The following questions carry over from the [landscape research](kubernetes-scanning-landscape.md). They remain implementation and verification items.

| Area | Open question |
| --- | --- |
| Tracking image content | How should we track image content when tags change, including when an unchanged tag points to different content? |
| Workload correlation | How should multiple Workloads using the same digest be associated with the image while retaining each affected Workload? |
| Deduplication | How should duplicate scans and duplicate notifications each be suppressed when multiple Workloads or image names refer to the same confirmed image identity? |
| Resolution | How should a finding be judged `resolved` when the Workload set changes, such as during a rolling update? How do we distinguish a confirmed fix from an image or Workload no longer being observable? The design now requires retention of previous findings when scan identity is unconfirmed; actual behavior remains to be verified. |

## Next steps

1. Establish the K3s + containerd verification environment and fix the initial OS and component versions.
2. Implement read-only discovery and deployment-owner mapping, then connect the implemented identity types through scanning, deduplication, prioritization, and diff notifications.
3. Verify the open questions with regression tests using API fixtures recorded from kind and operational checks in the real K3s environment. Record supported configurations, owner-mapping methods, and limitations here as they are confirmed.

## Update history

### September 7, 2026

- Implemented the common inventory identity model, settled the adapter design, and corrected the owner-detection plan by removing Kustomize and the test strategy by clarifying kind's role as the source of API fixtures.

### September 6, 2026

- Created the initial plan, including the implementation scope, image identity approach, initial support target, and questions to validate.

---

This article is a KestreLynx development record. [About KestreLynx](../index.md)
