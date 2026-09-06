# Developing Kubernetes Support

- **Status:** In development (planning published, implementation starting)
- **Started:** September 6, 2026
- **Last updated:** September 6, 2026

## Purpose

Connect Kubernetes workloads to the scan → prioritize → diff-notification pipeline already implemented for Docker hosts: scan running images with Trivy, prioritize findings using CISA KEV and EPSS, and notify changes through Slack and webhooks.

This page records the initial plan and design decisions. Implementation findings, verified configurations, and remaining questions will be added as development proceeds.

The preceding [Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md) records the research behind this work. This log focuses on the implementation plan.

## Planned scope

| Area | Planned behavior |
| --- | --- |
| Discovery | Retrieve Pods and Workloads through read-only access to `kube-apiserver`. Cover Deployment, StatefulSet, DaemonSet, Job, and CronJob. Pods whose owners cannot be determined remain `unknown`; ownership is not guessed. |
| Observed information | Collect Pod `imageID` and `OwnerReference` information to associate running images with their Workloads. |
| Deployment owners | Resolve deployment-owner candidates for Helm, Kustomize, Argo CD, Flux, and plain manifests using the common relation model. Supported methods will be documented as they are verified. |
| Image processing | Normalize and validate `imageID`, then suppress duplicate scans of the same digest under the identity rules below. |
| Installation | Use an in-cluster deployment with a read-only ServiceAccount as the first-choice installation method. |
| Prioritization and notifications | Connect the discovered images and Workloads to the existing KEV/EPSS prioritization and diff notifications for new, worsened, and resolved findings. |

## Non-goals for this stage

- Mutating Workloads. Discovery remains read-only.
- Observing runtime behavior on nodes or deploying privileged agents.
- Adding registry access to KestreLynx. This remains outside the scope, consistent with existing behavior.

## Image identity

- Digest kinds will remain distinct and will not be mixed in one untyped identifier. This implementation will introduce the typed `Digest` defined in the [remediation relations model](remediation-relations-model.md).
    - `config` — the **OCI image config digest** used by the existing Docker path to identify image content.
    - `registry` — the **registry-side digest** reported by a Kubernetes Pod's `imageID`.
- Identity comparison using a registry digest requires both the digest and the platform (OS and architecture), because a registry digest may identify a multi-platform index.
    - If the platform is unknown, no identity key is constructed, and deduplication and result sharing are not performed on that basis.
- The linked model describes the full comparison rules and the requirements for confirming that a scan matches the observed image.

## Initial supported configurations (planned)

The first formally supported target will be **K3s + containerd**, because we can continuously verify this configuration ourselves in real environments. The table below describes the verification plan; it is not a list of configurations already supported.

| Item | Initial plan |
| --- | --- |
| OS and CPU | Use Ubuntu LTS + amd64 as the baseline candidate. Fix exact versions during verification. Add arm64 only if continuous verification on real hardware is possible. |
| Workload kinds | Deployment, StatefulSet, DaemonSet, Job, and CronJob. Pods with unknown owners remain `unknown`. |
| Installation | In-cluster deployment with a read-only ServiceAccount. |
| Registries | Verify public images and images from at least one authenticated private registry. |
| Owner mapping | Keep the common relation model and build a support table from methods actually verified, for example starting with Helm. |
| Verification | Use kind for regression tests and a real K3s environment for operational checks. Success in a test environment alone does not establish formal support for another distribution. |

EKS, GKE, and AKS are not in the initial support list because we cannot continuously verify them yet. The implementation will use the common Kubernetes API so these services can be added once continuous verification of authentication, permissions, registry access, and scanning in real environments becomes sustainable.

CRI-O remains an unverified follow-up candidate. Exact versions and verification results will be recorded during implementation.

## Questions to validate during implementation

The following questions carry over from the [landscape research](kubernetes-scanning-landscape.md). They remain implementation and verification items.

| Area | Open question |
| --- | --- |
| Tracking image content | How should we track image content when tags change, including when an unchanged tag points to different content? |
| Workload correlation | How should multiple Workloads using the same digest be associated with the image while retaining each affected Workload? |
| Deduplication | How should duplicate scans and duplicate notifications each be suppressed when multiple Workloads or image names refer to the same confirmed image identity? |
| Resolution | How should a finding be judged `resolved` when the Workload set changes, such as during a rolling update? How do we distinguish a confirmed fix from an image or Workload no longer being observable? |

## Next steps

1. Establish the K3s + containerd verification environment and fix the initial OS and component versions.
2. Implement read-only discovery, typed image identity, and deployment-owner mapping, then connect them to scanning, prioritization, and diff notifications.
3. Verify the open questions with kind regression tests and operational checks in the real K3s environment. Record supported configurations, owner-mapping methods, and limitations here as they are confirmed.

## Update history

### September 6, 2026

- Created the initial plan, including the implementation scope, image identity approach, initial support target, and questions to validate.

---

This article is a KestreLynx development record. [About KestreLynx](../index.md)
