# Designing the Remediation Relations Model

- **Status:** Models defined
- **Started:** August 31, 2026
- **Last updated:** September 2, 2026

## Purpose

This work defines only the data model: its vocabulary and relations.

KestreLynx can already detect and report fixable, high-priority vulnerabilities in running images.
After a notification arrives, however, users must still determine **where to make a change so that the CVE disappears**.

Before KestreLynx can present fix targets, support Kubernetes, or verify fix candidates, it needs relations that connect a detection result to the target of its fix.

- Which repository and file was the image built from?
- Is the vulnerability in an OS package or an application dependency?
- What manages the running workload: a Compose file or a manifest in Git?
- Did the candidate fix actually resolve the target CVE?

This work defines the relation models needed to answer those questions.
The features that use the models will be implemented in future development.

## Model overview

The path from a detection result to verification of a fix is divided into four areas.

Unless otherwise noted, PascalCase code names in this document, such as `Digest`, `EntityKey`, and `PackageRef`, are **types and model names defined by KestreLynx**.

| Area | Main KestreLynx types and models | What they represent |
| --- | --- | --- |
| Image entities | `Digest`, `EntityKey`, `ImageSubject`, `ImageEntity` | The identity of an observed and scanned image |
| Fix targets | `PackageRef`, `FixClass`, `FixTarget`, `RuntimeEvidence` | A vulnerable package and the files in which to fix it |
| Build and deployment origins | `SourceRef`, `SourceBinding`, `RepoFileRef`, `DeployBinding` | Where an image was built and what manages the running entity |
| Fixes and verification | `Derivation`, `VerificationResult` | The entities before and after a fix, and whether the CVE was resolved |

### Main KestreLynx-specific types and models

The main types defined by this design are listed below.
`ContentID` is defined by the [image entity identity model](image-identity-model.md), while `Environment`, `Workload`, and `Container` are existing types from the [environment and workload model](environment-workload-model.md).

#### Image entities

| Type or model | What it represents |
| --- | --- |
| `Digest` | A typed digest value that distinguishes config digests from registry digests |
| `Platform` | The image OS, architecture, and variant |
| `EntityKey` | The minimal key used to decide whether two observations refer to the same image entity |
| `ImageSubject` | An observation and scan target centered on an image name; its `EntityKey` may be unresolved |
| `ImageEntity` | The identity information confirmed together for one entity |

#### Fix targets

| Type or model | What it represents |
| --- | --- |
| `PackageRef` | Package identity containing the ecosystem, class, name, and installed version |
| `FixClass` | A classification of one detection result as an OS update, application dependency update, upstream wait, and so on |
| `FixTarget` | The relation between a package in a specific image entity and its candidate fix locations |
| `RuntimeEvidence` | Evidence about package execution observed in a specific Environment, Workload, and Container |

#### Build origins and deployment owners

| Type or model | What it represents |
| --- | --- |
| `Attribution` | The origin, confidence, and observation time of a piece of information |
| `SourceRef` | One candidate build origin, including a Git repository, revision, build context, and Dockerfile |
| `RepoFileRef` | The location of one file in a Git repository |
| `SourceBinding` | The relation between an image entity and zero or more candidate build origins and files |
| `DeployOwner` | One owner, such as Compose, Kubernetes, Helm, or Argo CD |
| `OwnerChain` | One path from the direct owner to the final owner, together with the image declared by that path |
| `DeployBinding` | The relation connecting a Container in a Workload, its running image, and zero or more `OwnerChain` values |

#### Fixes and verification

| Type or model | What it represents |
| --- | --- |
| `Mode` | Whether the fix path is a permanent `rebuild` or an emergency `patch` |
| `Derivation` | The relation between the image entities before and after a fix |
| `ScanConditions` | Conditions required for comparison, such as the scanner, vulnerability database, and severity filter |
| `VulnVerdict` | The before and after states and verdict for one CVE and package |
| `VerificationResult` | The overall result of comparing the scans before and after a fix |

These are not independent synonyms. Smaller types are combined to express relations.

The relations flow as follows.

1. Observe a running image as an `ImageSubject` and resolve its `EntityKey` when possible.
2. Identify the package in a detection result with `PackageRef`, then classify the fix with `FixClass`.
3. Use `FixTarget` and `SourceBinding` to obtain candidate repositories and files to change.
4. Use `DeployBinding` to find the Compose or Kubernetes definition that manages the running entity.
5. Connect the entities before and after the fix with `Derivation`, then verify the rescan with `VerificationResult`.

## Model definitions

### Image entities

Image identity is processed as follows.

1. Convert a digest obtained from Docker or Kubernetes into a `Digest`.
2. Construct an `EntityKey` when the entity can be identified.
3. Create an `ImageSubject` from the image name and optional `EntityKey`, then observe and scan it.
4. Collect identity information confirmed by a pinned scan into an `ImageEntity`.

`EntityKey` is the minimal key used for identity comparison.
`ImageEntity`, by contrast, is a record containing the multiple identifiers and image names associated with that key; it is not itself a key.

#### Identifying image entities (identity type)

While Docker Engine was the only target, [defining `ContentID`, the canonical identifier of an image entity, as the OCI image config digest](image-identity-model.md) was sufficient. Kubernetes breaks that premise.

- The image identifier reported by Kubernetes, a Pod's `imageID`, is a **registry-side digest**, not a config digest.
- Only the registry digest is available through the Kubernetes API; the config digest is not.

A Kubernetes image entity cannot be stored in the same field as `ContentID`. KestreLynx therefore defines its own `Digest` type with a digest **kind**.

- `config` — an OCI image config digest, preserving the current meaning of `ContentID`
- `registry` — a digest that can be referenced through a registry
- unresolved — validation failed or no digest was available

A registry-side digest can point to either of the following.

- An image definition for one platform (a manifest)
- A reference grouping images for multiple platforms (an index)

These are represented by the single `registry` kind for two reasons.

- Both appear as `repo@sha256:...`; the reference alone does not reveal which object it identifies.
- Distinguishing them requires a registry query, and KestreLynx does not access registries.

#### Entity keys and platforms

`EntityKey` is a KestreLynx-specific type used to decide whether two observations refer to the same image entity.

- Config digest: the digest alone
- Registry digest: the digest and platform (OS and architecture)

A registry digest may refer to multiple platforms, so the digest alone may not identify an entity.
When the platform is unknown, no key is created, and neither deduplication nor result sharing is performed.

When both config and registry digests are valid, the config digest is used as the key.
The repository name describes where content was obtained and is not part of `EntityKey`.

#### Identified and pinned

- **Identified:** An `EntityKey` was derived from the observation.
- **Pinned:** A scan against that key succeeded, and the entity reported by the result matched the key.

Identification does not guarantee that the scanner can handle that digest.
Caching and replication of results to other image names are therefore permitted only for pinned scans.
An unpinned result is not replicated and is reported as unconfirmed against the running entity.

`ImageSubject` is a KestreLynx-specific type representing an observation and scan target.
It combines an image name, which is always available, with an optional `EntityKey`.
This allows observation to continue per image name even when the entity cannot be identified.

`Pinned` is true only when all three conditions hold.

1. The `EntityKey` was resolved.
2. The scan succeeded.
3. The entity in the scan result matched the requested `EntityKey`.

Creating a `Derivation`, `SourceBinding`, `FixTarget`, or `VerificationResult` requires a **pinned** result, not merely an identified entity.

#### Correlating config and registry digests

`ImageEntity` is a KestreLynx-specific record that groups the config digest, registry digest, platform, and image names obtained in one observation as one entity.
A correlation between a config digest and registry digest is recorded only when both were confirmed by the same pinned scan.
It is never inferred from a matching tag. If persisted in the future, the correlation must include its observation time; this design does not persist it.

### Fix targets

Detection results are connected to files to change through their packages.

#### Package identity (PackageRef)

`PackageRef` is a KestreLynx-specific type combining a package name, version, OS/application class, and **ecosystem**, such as Debian, npm, or python-pkg.
It is used to identify the manifest or lockfile that should be changed.

Ecosystems are normalized through an allowlist. Unknown values remain `unknown` rather than being inferred.

This design does not construct purl (Package URL) strings.
An incorrectly generated purl could cause a false match with another tool, so purl support must wait until ecosystem-specific generation rules are defined.

#### Fix classification (FixClass)

`FixClass` is a KestreLynx-specific classification type describing how to fix each detection result.

- `os_package` — update the base image or distribution
- `app_dependency` — update a manifest or lockfile
- `not_fixable` — upstream has declared that it will not fix the issue
- `not_yet_fixed` — no fixed version is confirmed yet; wait for upstream
- `unknown` — cannot be determined

`not_fixable` and `not_yet_fixed` are separate so that an upstream decision not to fix is not confused with waiting for a fixed version.
The classification belongs to each detection result rather than to a package because CVEs in the same package can have different statuses.

The first matching rule below determines the classification; otherwise the result is `unknown`.

1. `will_not_fix` → `not_fixable`
2. `affected` → `not_yet_fixed`
3. `fixed`, with a fixed version, for an OS package → `os_package`
4. `fixed`, with a fixed version, for an application dependency with a known ecosystem → `app_dependency`

#### Fix targets (FixTarget) and source candidates

`FixTarget` is a KestreLynx-specific relation model describing where to fix a package in a particular image entity.
Because the same package can have a different source in each image, its subject is the pair of `EntityKey` and `PackageRef`.

File candidates belong to their respective source candidates so their repository association is preserved.
The model distinguishes unresolved candidates from resolution that completed with no candidates, and it never presents a file path without a known source.
File roles are classified as manifest, lockfile, Dockerfile, or deployment manifest.

A detection result is not connected directly to a file. Instead, it reaches `FixTarget` through `EntityKey` and `PackageRef`.
Multiple CVEs in the same package share this fix target.

#### Runtime evidence

`RuntimeEvidence` is a KestreLynx-specific observation model.
Runtime evidence such as processes and listening ports is observed at the **Environment, Workload, and Container** scope rather than the image-entity scope.
Containers using the same image can have different runtime behavior.

`EntityKey` and `PackageRef` are used to join this evidence to `FixTarget`.
Rules for aggregating evidence from multiple containers and the concrete evidence fields are outside the scope of this design.

### Build origins and deployment owners

The origin from which an image was produced and the owner of a running entity are represented by separate relations.

#### Build origin (SourceBinding)

`SourceRef` is a KestreLynx-specific type describing an image's Git repository, revision, and Dockerfile.
Each candidate carries its origin, confidence, and observation time in `Attribution`.

`SourceBinding` is a relation model connecting one `EntityKey` to multiple candidate build origins.
Each candidate contains a `SourceRef` and file candidates within that repository.
`SourceRef` describes one candidate build origin, whereas `SourceBinding` describes the full candidate set and whether it conflicts.

Build-origin information may come from the following sources.

- Explicit user configuration
- Claims made by the image itself through OCI labels
- Provenance generated during the build

The path in `SourceRef` is a build context. It is separate from `RepoFileRef`, which points to one file in Git.

Confidence is an ordered enumeration that is not intended for composition.
For build origins, precedence is user configuration > provenance > OCI label.
For deployment ownership, it is user configuration > runtime information > OCI label.
Values that disagree at the same rank remain as conflicting candidates.

A revision must be a commit SHA. Tags and branch names are not guessed or substituted.
Repository URLs are checked for format only, not reachability.

Reading labels and provenance is outside the scope of this work.
Raw labels do not cross into the shared model; an adapter or parser converts them into `SourceRef` values.

#### Deployment owners (DeployBinding)

`DeployBinding` represents the owners of a running entity as an `OwnerChain` ordered from nearest to farthest.
For example, it can retain a path from a Pod through a Deployment and Helm to Argo CD.
Owners are classified as Compose, Kubernetes resources, Helm, Kustomize, Argo CD, Flux, and so on.

When several management paths exist, each remains a separate chain candidate.
Each chain carries the image declared by that owner path as intent.
The running entity is recorded alongside it as fact in the `ImageSubject` of `DeployBinding`; this model does not evaluate the difference.

`DeployOwner` represents one owner, `OwnerChain` represents one management path, and `DeployBinding` represents the complete relation including the running entity.

`DeployBinding` also carries the Workload and Container so the running entity is associated with a specific container.

Compose uses the same model. The Git location of a Compose file comes only from user configuration; an environment-specific absolute path is not used.
Kubernetes-specific UIDs, resourceVersion, and raw `apiVersion` values do not cross into the shared model. Only the normalized resource kind, name, namespace, and location in Git are retained.
An unknown custom resource retains a validated `<kind>.<group>` identifier. An owner that cannot be validated is omitted from the chain.

### Fixes and verification

#### Before and after a fix (Derivation)

`Derivation` connects the image entities before and after a fix. Its `Mode` distinguishes the fix path, and `Attribution` records the origin of the relation.

- `rebuild` (permanent fix) — change the source definition and rebuild through the normal build path
- `patch` (emergency fix) — produce a derived image by patching a running image directly

A `patch` does not fix the source and is therefore temporary; it is not equivalent to a `rebuild`.
The relation stores the before and after `EntityKey` values rather than mutable tags. No invalidation state is stored; validity is determined by comparing it with the current entity.

Target CVEs express the **intent** of the fix. Only `VerificationResult` establishes whether they were actually resolved.

#### Rescan verification (VerificationResult)

`VerificationResult` records a comparison of the scans before and after a fix.
It stores both `EntityKey` values, the target CVEs, and the verification time, and links the corresponding `Derivation` when one is available.

`ScanConditions` represents the comparison conditions, while `VulnVerdict` represents the verdict for each CVE and package.
`VerificationResult` combines them into the result of the verification as a whole.

Both sets of scan conditions, including the scanner, vulnerability database, and severity filter, are retained.
The scans are compared only when both sets are known and equal.
If the conditions are unknown or differ, the verdict is unknown and no change in CVEs is reported.

Resolution of target CVEs and appearance of new CVEs are recorded as separate facts; the model does not apply a value judgment such as "regressed."
The comparison key is the pair of CVE ID and package coordinates consisting of ecosystem, class, and name.
Versions, which change during an update, are excluded from the key and retained in the before and after `PackageRef` values.

`VerificationResult` has the following invariants.

- Comparability is derived from both sets of scan conditions and cannot be set independently.
- When scans are not comparable, every verdict is `unknown` and no newly introduced CVEs are recorded.
- Findings present before the fix and findings present only in the candidate form separate, non-overlapping sets.
- When a `Derivation` is attached, its before and after entities must match the entities under verification.
- For comparable scans, a CVE absent from the candidate is `resolved`; one present in the candidate `persists`.

`VerificationResult` is not stored in scan-history state.
Resolution in a periodic diff notification and resolution verified for a fix candidate have different meanings.

## Constraints

- Discovery remains read-only.
- This work defines models only; it makes no code changes.
- State keys, state formats, and notification output formats do not change.
- The meaning of the image entity identifier remains an image config digest.
- No network access to registries, Git, or provenance services is added.
- Unknown and conflicting values remain explicit rather than being filled by inference.
- Raw runtime-specific and tool-specific values do not cross into the shared model.

## Change history

### September 2, 2026

- Organized the models by area and clarified the roles of KestreLynx-specific types.

### September 1, 2026

- Finalized the remediation relations model design.

### August 31, 2026

- Began designing the remediation relations model.

---

This article is a KestreLynx development record. [About KestreLynx](../index.md)
