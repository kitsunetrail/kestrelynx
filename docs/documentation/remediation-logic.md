---
title: Remediation processing flow
---

# Remediation processing flow

This page explains how KestreLynx creates remediation plans, checks update results, manages remediation PRs, and sends notifications.
[Checked scope](#checked-scope) summarizes what KestreLynx checks and what users need to verify.

On Kubernetes, [work Pods](remediation-worker-logic.md#kubernetes-work-pods) are used when remediation PRs are enabled to update npm, pnpm, pip, uv, Go, or Gradle language packages.

The following pages explain the rules for each target.

| Topic | Page |
| --- | --- |
| Selecting distributed image candidates | [Image candidate selection](remediation-image-logic.md#image-selection) |
| Tag update PRs for Kubernetes | [Conditions for Kubernetes tag update PRs](remediation-kubernetes-logic.md) |
| Identifying and comparing base images | [Identifying the base image](remediation-base-image-logic.md#base-image-selection) |
| Common rules for selecting and accepting language package updates | [Language package selection](remediation-package-logic.md#package-selection) |
| Updates and checks for npm, pnpm, uv, and pip | [Node.js and Python packages](remediation-node-python-logic.md) |
| Resolving dependencies again by updating their dependents | [Dependent re-resolution](remediation-reresolution-logic.md#dependent-reresolution) |
| Go updates and checks | [Go package selection](remediation-go-logic.md#go-package-selection) |
| Maven updates and checks | [Maven](remediation-maven-logic.md) |
| Gradle updates and checks | [Gradle](remediation-gradle-logic.md) |
| Environments for running package managers | [Work container execution](remediation-worker-logic.md#worker-execution) |
| Managing PRs and their records | [PR management](remediation-pr-logic.md#pr-management) |

See [Supported input formats](remediation-reference.md#supported-inputs) for accepted inputs and [Reason codes](remediation-reason-codes.md#reason-codes) for codes attached to decisions.

See [Terms](remediation.md#terms) for the terminology used on this page.

## Processing flow {#processing-flow}

With remediation plans enabled, a cycle proceeds in this order.

1. Scan running images and collect findings
2. Select candidates, read the configured sources on GitHub, and create a plan that includes image candidate comparisons
3. If remediation PRs are enabled, update language packages and check the results
4. For eligible targets whose findings are not resolved by the regular candidates, check tags with a newer minor or major version
5. Where a floating tag's base layers do not match the running image, compare the current base with the running image by package location and CVE
6. Save the plan and the check results for any language package updates performed
7. If remediation PRs are enabled, match updates against existing PRs and create and manage PRs for eligible changes
8. Send results according to the notification conditions and record delivery after sending

The following table provides links to detailed explanations of each stage.

| Stage | Details |
| --- | --- |
| 1. Scan running images | [scan comparison conditions](#comparison-conditions) |
| 2. Select candidates and create a plan | [source verification](#source-verification), [image candidate selection](remediation-image-logic.md#image-selection), [identifying the base image](remediation-base-image-logic.md#base-image-selection), [language package selection](remediation-package-logic.md#package-selection) |
| 3. Update and check language packages | [accepting update results](remediation-package-logic.md#update-method-and-partial-pull-requests) |
| 4. Check newer series | [checking newer series](remediation-image-logic.md#newer-series-check) |
| 5. Compare floating-tag bases | [rebuild estimates for floating tags](remediation-base-image-logic.md#rebuild-check) |
| 6. Save the plan and check results | [recording order](remediation-pr-logic.md#record-order) |
| 7. Create and manage PRs | [PR management](remediation-pr-logic.md#pr-management) |
| 8. Notify results and record delivery | [scan notification conditions](notification-conditions.md#notification-conditions), [recording order](remediation-pr-logic.md#record-order) |

A cycle cannot proceed to PR processing if the plan could not be saved.
The plan is not saved again after PR processing; PR results are included in notifications and the PR records used for ongoing management.

### Plan and PR execution scope {#plan-and-pr-execution}

Whether remediation PRs are enabled determines whether updates are performed after planning.
The following table compares plans alone with plans plus remediation PRs.

| Execution scope | What KestreLynx does |
| --- | --- |
| Plans only | Select candidates from running image findings, read configured sources, and compare image candidates |
| Remediation PRs enabled | Perform planning, update and check language packages, and create and manage PRs for eligible changes |

PRs can update tags in Compose files, Kubernetes manifests, Kustomize, and Helm values, update Dockerfile base images, and update language packages.
See [Supported input formats](remediation-reference.md#supported-inputs) for supported targets and input requirements.

The following limits apply when only plans are enabled.

- No package managers are run and no work containers are created
- Nothing is written to GitHub, while plans and delivery records are saved locally

See [Basic settings](configuration.md#remediation-basics) for enablement and [Interpreting update results](remediation-update-results.md#interpreting-updates) for reading the results.

### Checked scope {#checked-scope}

KestreLynx checks the sources it reads, the images it compares, and dependency files before and after an update.
The following table separates what these checks establish from what users need to verify.

| Check | What is checked | What is not checked |
| --- | --- | --- |
| Source matching | Consistency with plan inputs and detected packages | Proof that the running image was built from the specified source |
| Base image comparison | Findings in the current and candidate base images | The final image built from the modified Dockerfile |
| Dependency file comparison | Findings in dependency files before and after the update | Actual dependency installation, application behavior, and running containers after deployment |

Even with remediation PRs enabled, KestreLynx does not merge PRs or build and deploy the final application image.
Users review changes, merge, build, test application behavior, and deploy.

### Source verification {#source-verification}

Source verification checks whether the target files can be used as plan inputs and whether those inputs are still valid when creating a PR.

KestreLynx makes the following checks when reading sources and creating PRs.

- Resolve the configured branch to a commit and read sources from that commit
- If the base branch has advanced before PR creation, recheck the files used for the update and the relevant configuration files
- For language package and Dockerfile updates, defer PR creation if a change is detected in a file checked during planning
- For tag updates in Compose files, Kubernetes manifests, Kustomize, and Helm values, use manual handling if the image reference in the file does not match the running image reference

For a deferred update, no commit or branch is created for its PR either.
Within the same repository and base branch, language package and Dockerfile changes are grouped into PRs as follows.

| Update type | Changes grouped into one PR |
| --- | --- |
| Language packages | Packages and files updated together by the same package manager in the same dependency directory |
| Dockerfile | Targets that change the same `FROM` in the same Dockerfile |

For example, when changed inputs defer an npm update in one dependency directory, changes to all packages in that PR stop.
An update in another dependency directory can proceed if its inputs are unchanged and it meets the other conditions.

A separate PR is also deferred if it uses the same changed file as an input.

For language packages, KestreLynx checks the following information.

- Package names and versions detected in the running image against the dependency file records
- File contents and version declarations reread during the update against those recorded during planning

Globally installed npm packages are left for manual handling without matching them against dependency files.
This applies when the image path is under `<prefix>/lib/node_modules` and the parent of the first `node_modules` is `lib`.

Packages included in npm and corepack in the official node images are also handled this way.

For example, a container named `example-api` uses `container/example-api` in its mapping.

For a `container/<name>` mapping, KestreLynx checks the following scope.

| Relationship | Handling |
| --- | --- |
| Scanned image and running image | Verify that the scanned image digest matches the running image ID |
| Dockerfile and running image | Match the base layers |
| Dependency files and running image | Match detected package names and versions |
| Container and configured repository | Trust the configured mapping without verifying that the container was built from that repository |

Mappings and matching package names and versions do not prove that an image was built from those sources ([Checked scope](#checked-scope)).

PRs for workload keys of the form `container/<name>` (PRs targeting containers started with `docker run`) include a note that the link to the target source is based on configuration and has not been verified by KestreLynx.
If the note cannot be retained within the PR body length limit, no PR is created.

See [Source mappings](configuration.md#remediation-mappings) for the configuration specification.

## Comparison and acceptance conditions {#comparison-and-adoption}

Comparisons identify resolved, remaining, and newly introduced findings, and updates that meet the acceptance conditions are proposed.

### Scan comparison conditions {#comparison-conditions}

Scans comparing before and after an update use the same scanner, vulnerability database content, severity range, and scan settings.
See [Verification scope by target](#verification-scope) for the images or files compared for each target.

A finding includes the vulnerability ID, package name, version, location, and other information.
Image comparisons use the package type (such as Alpine or npm), its classification as an OS or language package, and its name to decide whether to treat the same vulnerability separately.

The same CVE found in multiple packages or locations is counted as follows.

| Difference in detection | Handling in image comparisons |
| --- | --- |
| Package type, class, or name differs | Assess resolution or persistence separately |
| Type, class, and name match, but versions or locations differ | Distinguish occurrences and count resolution or persistence of the same CVE as one finding |
| The CVE remains in any occurrence of the same package | Count it as remaining rather than resolved |

KestreLynx makes the following checks to keep comparison conditions consistent.

- Do not reuse a running image scan whose database identity or other conditions cannot be verified, and rescan within the limits
- Verify the databases after comparison scans and reject the comparison if conditions changed
- For each image before and after the update, verify that the image actually scanned matches the digest specified for that scan
- Verify that the images before and after the update have matching OS and CPU architecture

Package analysis results are also needed to determine why a finding disappeared.
Resolution is not established under the following conditions.

| Scan result condition | Why resolution cannot be established |
| --- | --- |
| No package list | The packages analyzed cannot be verified |
| Truncated package list | The complete list of analyzed packages cannot be verified |
| Target package type not analyzed | A package list exists, but analysis results for the target type are missing |

A package analyzed without the vulnerability being detected is distinguished from a package type that could not be analyzed at all.
Without analysis results for the target type, an absent finding is not treated as resolved.

Dependency file comparisons receive only the files being checked and do not read repository-specific Trivy settings, ignore files, or VEX documents.
Findings outside the configured severity range are excluded from evaluations of resolution and newly introduced findings.

### Verification scope by target {#verification-scope}

The objects compared and the conditions for accepting an update depend on the target.
Target findings are selected from findings whose scan status is `fixed` and that include fixed-version information.

Findings not selected as targets and findings newly detected after the update are handled separately from resolved or remaining target findings ([Resolution in comparison results](remediation-pr-results.md#verification-results)).
The following table separates the findings targeted for remediation from the scope checked for new findings.

| Target | Objects compared | Findings targeted for remediation | Scope checked for new findings |
| --- | --- | --- | --- |
| Distributed image | Running image and candidate image | Target findings selected from the running image | The whole image within the configured severity range |
| Base image | Matched current base and candidate base | Target findings confirmed to belong to the base | The whole base within the configured severity range |
| Language package | Dependency files before and after the update | Target findings for packages whose updates are accepted | All compared dependency files within the configured severity range, including other packages |

Apply the following acceptance conditions according to the update type.

- For distributed and base images, propose an improvement if no target finding is unanalyzable and at least one is resolved, even if others remain
- For language packages, require target findings for accepted packages to be confirmed before the update and absent from every occurrence afterward
- For every update, require no new findings in the table's scope checked for new findings

The following rules also apply when deciding whether to accept an update.

- Verify that scans analyze the target package versions recorded in the updated dependency files
- Do not offset findings absent before the update and detected afterward against resolved findings
- Separately record findings newly detected after the update if they are listed in CISA's Known Exploited Vulnerabilities (KEV) catalog
- Verify that a shared Dockerfile change can be accepted for all running images that use it

See [Checked scope](#checked-scope) for the distinction from validating the final image or application, and [Resolution in comparison results](remediation-pr-results.md#verification-results) for interpreting comparisons.
