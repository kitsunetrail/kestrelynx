# Developing Kubernetes Support

- **Status:** In development (verified end to end against a real K3s + containerd cluster).
- **Started:** September 6, 2026.
- **Last updated:** September 7, 2026.

## Purpose

Connect Kubernetes workloads to the scan → prioritize → diff-notification pipeline already implemented for Docker hosts. Scan running images with Trivy, prioritize findings using CISA KEV and EPSS, and notify changes through Slack and webhooks.

This page records the initial plan, settled adapter design, and real-environment verification results. It also lists findings from verification and configurations that remain unverified.

The preceding research is documented in the [Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md). This log covers the implementation plan and verification results.

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

- Do not mutate Workloads; discovery remains read-only.
- Do not observe runtime behavior on nodes or deploy privileged agents.
- Do not add direct registry access to KestreLynx itself. This remains outside the scope, consistent with existing behavior; Trivy handles image fetching for the adapter's remote scanning path.

## Image identity

- Digest kinds remain distinct and are not mixed in one untyped identifier.
- The typed `Digest` defined in the [remediation relations model](remediation-relations-model.md) is now implemented in the common inventory model.
    - **`config`**
        - `config` is the **OCI image config digest** used by the existing Docker path to identify image content.
    - **`registry`**
        - `registry` is the **registry-side digest** reported by a Kubernetes Pod's `imageID`.
- `Platform`, `EntityKey`, and `ImageSubject` are also implemented in the common inventory model: `Platform` represents OS, architecture, and variant; `EntityKey` is the identity key; and `ImageSubject` is the observation subject consisting of a reference and an optional key.
- Identity comparison using a registry digest requires both the digest and the platform (OS and architecture), because a registry digest may identify a multi-platform index.
    - Platform participates in `EntityKey` only for registry digests; config digests identify an entity on their own.
    - If the platform is unknown, no identity key is constructed, and deduplication and result sharing are not performed on that basis.
- The running-image type, `RunningImage`, now carries a typed config digest instead of an untyped string, and Docker boundary validation is centralized in `ParseDigest`.
    - Existing tests verify that behavior for Docker users is unchanged.
- The linked model describes the full comparison rules and the requirements for confirming that a scan matches the observed image.

## Initial supported configurations (planned)

The first formally supported target will be **K3s + containerd**, chosen as a configuration we can provision and verify ourselves. The table below preserves the initial verification plan; what has actually been confirmed is recorded in the verification results below. This plan does not guarantee support for unverified configurations.

| Item | Initial plan |
| --- | --- |
| OS and CPU | Limit initial verified support to linux/amd64, with Ubuntu LTS as the baseline candidate. Fix exact versions during verification. Other platforms use the same code path but are labeled unverified. Add arm64 to verified support only if continuous verification on real hardware is possible. |
| Kubernetes | Target Kubernetes 1.29 or later for initial verified support. Fix exact component versions during verification. |
| Workload kinds | Cover Deployment, StatefulSet, DaemonSet, Job, and CronJob. Pods with unknown owners remain `unknown`. |
| Installation | Use an in-cluster deployment with a read-only ServiceAccount. |
| Registries | Verify public images and images from at least one authenticated private registry. |
| Owner mapping | Keep the common relation model and build a support table from methods actually verified, for example starting with Helm. |
| Verification | Use kind clusters as the source for recorded API fixtures, and run CI regression tests against those fixtures without a live cluster. Use a real K3s environment for operational checks. Success in a test environment alone does not establish formal support for another distribution. |

**Correction to the initial plan (September 7):** “Use kind for regression tests” meant using kind as the source of API fixtures, not running kind directly in CI. The verification strategy above makes this role explicit.

EKS, GKE, and AKS are not in the initial support list because we cannot continuously verify them yet. The implementation will use the common Kubernetes API so these services can be added once continuous verification of authentication, permissions, registry access, and scanning in real environments becomes sustainable.

CRI-O remains an unverified follow-up candidate. Versions and verification results will be recorded as verification proceeds.

## Settled decisions for the adapter design

The following records the settled decisions that define the adapter's behavior and initial support conditions. Real-cluster verification results are recorded below.

- **Kubernetes API client**
    - Implement a minimal read-only HTTP client that connects to `kube-apiserver` using a ServiceAccount token and CA.
    - Make only paginated LIST requests, since the required API surface is limited to paginated LISTs of GA resources.
    - Do not add a client-go dependency: a measured minimal client-go Pod-list program is about 26.6 MB, compared with the current full binary at about 7.7 MB.
- **Scanning path**
    - Have Trivy fetch image content from the registry with `--image-src remote`.
    - Pin the image by digest and specify an explicit `--platform`.
    - Do not scan through the containerd socket, because it requires privileged host access and a per-node agent, both non-goals.
- **Registry conditions**
    - Require registry reachability and authentication from the scanner Pod.
    - Initial support excludes K3s `registries.yaml` mirrors and rewrites.
    - Initial support excludes images that exist only preloaded on nodes.
    - Initial support excludes digests deleted from the registry.
    - Air-gapped clusters are outside the initial scope.
- **imageID without a repository part**
    - Treat a bare `sha256:...` imageID without a repository part as a normal configuration with unresolved identity, rather than an error, since it can occur for preloaded or imported images.
    - Scan such images by reference and report them as “image identity unconfirmed”.
    - Never use these results as a false basis for marking findings resolved.
    - This fallback does not add support for images available only on nodes.
- **Resolution correctness**
    - Never report previously recorded findings as resolved based on results from a scan with unconfirmed image identity.
    - Apply existing conservative retention.
    - Have notifications state that previous findings are being retained instead of claiming “all clear”.
- **Container targets**
    - Include native sidecars, meaning init containers with `restartPolicy: Always`, in scan targets.
    - Exclude ordinary init containers.
- **Initial support target**
    - Target linux/amd64 and Kubernetes 1.29 or later; Kubernetes 1.36 is currently the only version verified in a real environment.
    - Other platforms use the same code path but are labeled unverified.
- **Configuration**
    - Add a `kubernetes` section with an explicit `enabled` opt-in.
    - The Kubernetes and Docker adapters are mutually exclusive; explicitly configuring both is a startup error.

## Verification on a real K3s cluster

### Verification environment

- The cluster consisted of a single node running K3s v1.36 (Kubernetes 1.36).
- The container runtime was containerd 2.3.
- The OS was Ubuntu, and the platform was linux/amd64.
- The workloads deployed for verification included a Deployment, StatefulSet, DaemonSet, standalone Pod, digest-pinned Pod, Helm release, and Flux Kustomization-managed Deployment.

### Verified

- **Node platform notation**
    - Node `status.nodeInfo` reported `architecture: amd64` and `operatingSystem: linux`, confirming the assumed vocabulary match with the scan-side platform comparison.
- **Pod imageID format**
    - Both tag-specified and digest-specified pulls reported `<normalized repository>@sha256:<hex>`, for example `docker.io/library/nginx@sha256:…`, which the implemented parser accepts unchanged.
    - No `docker-pullable://` prefix was observed on containerd 2.x.
- **Registry-digest scanning and identity confirmation**
    - Trivy fetched and scanned a digest-pinned image from the registry using `--image-src remote --platform linux/amd64 repo@sha256:…`.
    - The report's `RepoDigests` may shorten the repository name to `nginx@…` for `docker.io/library/nginx`; comparison of the digest's hex portion absorbs this difference by design.
    - `ImageConfig.{os,architecture}` matched the requested platform, so scan-result verification (pinning) succeeded against a real registry.
- **ServiceAccount and RBAC**
    - The provided `deploy/kubernetes/` ServiceAccount and read-only RBAC manifests applied and worked as-is.
- **End-to-end behavior**
    - Discovery → registry-digest scans → prioritized notification succeeded for 7 images, with every identity confirmed and zero scan errors.
    - Notification output carried environment kind `kubernetes`, resolved Workload kinds (Deployment through its ReplicaSet ownership chain, StatefulSet, standalone Pod, and Flux-managed Deployment), and `<namespace>/<pod>/<container>` container names.
- **Helm markers**
    - A real Helm 3.19 release carried the label `app.kubernetes.io/managed-by: Helm` and the two `meta.helm.sh/*` annotations, matching the three conditions used by detection.
- **Flux Kustomization markers**
    - Flux's kustomize-controller added the name/namespace pair as labels, confirming the label-based detection approach.
    - Annotations were empty on the real object.

### Findings

- **Digest-pinned Pod display reference**
    - The Pod's `status` image field was a bare `sha256:…` string, while `imageID` retained the full `repo@sha256:…`.
    - Identity resolution and scanning worked through `imageID`; the bare string appeared only as the display name and history key for that Pod.
    - This is recorded as a known behavior.
- **Wiring defect found and fixed**
    - Verification caught a defect in which the adapter's fetch location and source kind were not passed from the scan pipeline to the scanner.
    - Registry-digest entities consequently fell back to reference-based scans, and previous findings were not being retained for scans with unconfirmed identity.
    - Isolated package unit tests could not catch this defect because it existed at the boundary between packages.
    - The defect was fixed and covered by a cross-package regression test.
    - This is the kind of defect real-environment verification should uncover.

### Still unverified

- Argo CD's actual marker keys and tracking-id format remain unverified (Argo CD was not installed).
- Flux's HelmRelease-side markers remain unverified (helm-controller was not installed).
- Authenticated private registries remain unverified.
- ServiceAccount token rotation in a long-running process remains unverified.
- Images preloaded or imported directly into containerd, and the `imageID` format after local reference deletion, remain unverified.
- Multi-node and mixed-architecture clusters, and platforms other than linux/amd64, remain unverified.

## Questions to validate during implementation

The following four questions carry over from the [landscape research](kubernetes-scanning-landscape.md), with confirmation results from real-cluster verification added.

- How should we track image content when tags change or when an unchanged tag points to different content?
    - Registry digests could be parsed for both tag-specified and digest-specified pulls, and registry-digest scans were confirmed to match the observed image identity on the real cluster.
- How should multiple Workloads using the same digest be associated with the image while retaining information about each affected Workload?
    - End-to-end notifications confirmed the resolved Workload kinds and container names in `<namespace>/<pod>/<container>` format.
- How should duplicate scans and duplicate notifications each be suppressed when multiple Workloads or image names refer to the same confirmed image identity?
- How should a finding be judged `resolved` when the Workload set changes, such as during a rolling update, and how do we distinguish a confirmed fix from an image or Workload no longer being observable?
    - The design retains previous findings when a scan's image identity is unconfirmed; actual behavior remains to be verified.

## Next steps

1. Verify the remaining environment-dependent behavior.
    - Verify Argo CD marker keys and tracking-id format.
    - Verify Flux HelmRelease-side markers.
    - Verify access to authenticated private registries.
    - Verify ServiceAccount token rotation in a long-running process.
    - Verify images preloaded or imported into containerd and the `imageID` format after local reference deletion.
2. Broaden verified support to multi-node and mixed-architecture clusters and additional platforms as continuous real-environment verification becomes possible.
3. Validate the remaining questions through regression tests using API fixtures recorded from kind and operational checks in the real K3s environment, recording confirmed configurations, owner-mapping methods, and limitations on this page.

## Update history

### September 7, 2026

- Completed implementation through deployment-owner marker detection.
- Verified end-to-end behavior on a real K3s + containerd cluster.
- Found and fixed the scan-pipeline wiring defect during verification and added a cross-package regression test.
- Implemented the common inventory identity model, settled the adapter design, removed Kustomize from owner detection, and corrected the verification strategy to use kind as the source of API fixtures.

### September 6, 2026

- Created the initial plan, including the implementation scope, image identity approach, initial support target, and questions to validate.

---

This article is a KestreLynx development record. [About KestreLynx](../index.md)
