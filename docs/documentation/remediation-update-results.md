---
title: Reading update results and re-pull and rebuild guidance
---

# Reading update results and re-pull and rebuild guidance

This page explains version displays and re-pull and rebuild guidance in Slack remediation plans.
See [Reading remediation plan notifications](remediation-results.md) for line labels and counts, and [Terms](index.md#terms) for terminology.

## Interpreting update results {#interpreting-updates}

The following sections explain package version displays in “Update,” “Update candidate,” and “Needs a decision” lines.

### Versions to the right of `→` {#target-and-adopted-version}

KestreLynx displays an update as “Update” when it has confirmed PR creation, and as “Update candidate” when it has not.
The meaning of the version to the right of `→` also differs by display.

The following example shows an update for which a PR was created.

```text
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
```

The following example shows an update for which PR creation was prevented by the limit on new PRs.

```text
Update candidate: package-b 2.1.1 → 2.3.0
Deferred: the limit on pull requests of a run was reached
```

The relationship between the display and PR, version meanings, and actions to take are as follows.

| Display | PR | Version to the right of `→` | What to do |
| --- | --- | --- | --- |
| `Update` | Created | Adopted version (the version confirmed in the dependency files after an update) | Review and merge the PR ([Pull request contents](remediation-pr-results.md#pr-body-and-checks)) |
| `Update candidate` (`remediation.pull_requests.enabled` is `false`) | Not created by configuration | Update target (the minimum version used when selecting an update), with the update not yet run | Change `remediation.pull_requests.enabled` to `true` to enable PR creation |
| `Update candidate` (`remediation.pull_requests.enabled` is `true`) | Creation not confirmed | Adopted version (the version confirmed in the dependency files after an update) | [Address](remediation-troubleshooting.md#check-missing-pr) the reason shown immediately below or in a notification warning |

When the reason is “the result of a write to GitHub is unknown”, a PR may already exist on GitHub, and the result of checking GitHub again in the next cycle is displayed.

See [Fixed-version lower bounds](remediation-package-logic.md#fix-lower-bound) for version selection, and [Package results](webhook-remediation-language-reference.md#language-package-fields) for webhook fields.

### Packages left out of a PR {#partial-pull-requests}

A PR containing only some of the planned package updates that passed the checks is called a partial PR.
Packages left out of the PR appear under “Needs a decision.”

The following example includes only the `package-a` update in the PR, while `package-b` did not reach a fixed version.

```text
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
Needs a decision: package-b 2.1.1 cannot be raised to the fixed 2.3.0 (the cause could not be determined)
```

Updates included in the PR and packages left out are handled as follows.

| Display | Meaning | What to do |
| --- | --- | --- |
| `Update` | An update included in the PR | Review and merge the PR ([Pull request contents](remediation-pr-results.md#pr-body-and-checks)) |
| `Needs a decision: … left out because …` | A package left out of the PR's updates | Take the [action for the displayed reason](remediation-troubleshooting.md#check-update-failure) |
| `Needs a decision: … cannot be raised to the fixed … (the dependent … limits the version of …)` or another cause in parentheses | A package with an identified cause for not reaching a fixed version | Follow [Guidance when a package cannot reach a fixed version](remediation-fix-hints.md#fix-hints) |
| `Needs a decision: … cannot be raised to the fixed … (the cause could not be determined)` | A package that did not reach a fixed version for a reason KestreLynx could not identify | — |

Merging the PR leaves the findings for packages under “Needs a decision” unresolved.
“Left out” does not mean that the package was removed from the image.

No guidance accompanies “the cause could not be determined,” so users need to use their package manager to investigate which dependencies determine the target package's version.

See [Conditions for partial PRs](remediation-package-logic.md#partial-pr-selection) for the conditions.

### Results of updating dependent packages as well {#dependent-reresolution-results}

Reaching a fixed version may also require updating the packages that use the target package (dependent packages).
The result is displayed as follows.

```text
Update: minimist 0.0.8 → 1.2.8 (with mkdirp 0.5.1 → 0.5.6)
```

Dependent update results and actions to take are as follows.

| Display | Meaning | What to do |
| --- | --- | --- |
| `(with …)` | Dependent packages were also updated to bring the target to a fixed version | Review the dependent changes in the PR and merge it |
| `the dependent … limits the version of …` or `did not reach the fixed version this time` | Updating dependent packages did not reach a fixed version | Follow [When dependent packages are the cause](remediation-fix-hints.md#fix-hints-dependents) |
| `that update was not adopted because …` | The dependent update was not adopted because of failed checks or another reason | Follow [When dependent packages are the cause](remediation-fix-hints.md#fix-hints-dependents) |
| `updating … was not tried` | The dependent update was skipped because it exceeded the supported scope or limits | — |
| `it is tried again after …` | A version the update brings in is less than 72 hours old | Wait for a cycle at or after the displayed time |

See [Supported scope and limits](remediation-reresolution-logic.md#dependent-reresolution-limits) for reasons an update was skipped.

See [Re-resolution through dependent packages](remediation-reresolution-logic.md#dependent-reresolution) for the logic, and [Notification lines](remediation-reresolution-logic.md#dependent-reresolution-notification) for display conditions.
See [Pull request contents](remediation-pr-results.md#pr-body-and-checks) for the PR body.

### Re-pull guidance {#repull-guidance}

“Re-pull” means that the running image's tag points to newer content and pulling it again reduces findings.
No PR is created because the tag does not change.

The following example recommends restarting Pods on Kubernetes.

```text
Re-pull: resolves 2 finding(s)
Pull policy: Always: restarting the Pods pulls the new content (deployment/shop/api/app)
```

Take the following action for your environment and pull policy.

| Environment | What to do |
| --- | --- |
| Compose or `docker run` | Pull the image again using the running image's tag and recreate the containers |
| Kubernetes (`Pull policy` is `Always`) | Restart the Pods |
| Kubernetes (`IfNotPresent`) | Change the image reference to a fixed tag or digest |
| Kubernetes (`Never`) | Import the new image onto the node |

“Resolves” describes a comparison result and does not mean that running containers have been replaced with the new content.

See [Kubernetes image references and pulling images again](remediation-kubernetes-logic.md#kubernetes-image-references) for guidance by pull policy.

### Rebuild guidance {#rebuild-guidance}

A “Rebuild” line recommends rebuilding the image and can appear even when a reduction in findings could not be confirmed.

The meanings and actions for each display are as follows.

| Display | Meaning | What to do |
| --- | --- | --- |
| `a rebuild is expected to pick up … or later` | The pip dependency declarations allow a fixed version | Rebuild and deploy the image |
| `PR #… (base image … … → …) is merged, but the running image is still built from …` | The base image update PR is not reflected in the running image | Rebuild the image from the merged Dockerfile and deploy it |
| `the first layers of the running image do not match the current …` | The current base image does not match the first layers of the running image | Use the indicated command to pull the base again and rebuild, then recreate the containers |
| `Needs a decision: … fixed by building with a newer Go, not by go.mod` | Go standard library findings cannot be fixed by a PR | If a fixed Go version is displayed, rebuild with that version or later and deploy |

The following example recommends rebuilding an image that uses the floating tag `node:24-alpine`.

```text
Rebuild: the first layers of the running image do not match the current node:24-alpine; pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again
  • gone if the current base's version carries over: package-a 1.0.0 → 1.0.1
  • also in the current base: package-b 2.0.0
  • new in the current base: package-c 3.0.0
```

The lines and notes accompanying rebuild guidance have the following meanings.

| Line | Meaning |
| --- | --- |
| `gone if the current base's version carries over` | The current base contains a different version without the target findings, so rebuilding is expected to remove those findings |
| `also in the current base` | The current base also contains the target findings, so they are expected to remain after rebuilding |
| `not in the current base` | The package is absent from the corresponding location in the current base, so whether rebuilding changes the findings is unknown |
| `new in the current base` | The current base contains findings absent from the corresponding location in the running image, so rebuilding is expected to introduce those findings |
| `Node.js in the current … is …; if the rebuild takes over this version` | Expected findings if the current base's runtime version carries over |
| `(some findings could not be confirmed)` or `(which findings disappear could not be confirmed)` | Some findings or the findings expected to disappear could not be confirmed |

Estimates are not results from checking the rebuilt image.
See [Estimate limitations](remediation-base-image-logic.md#rebuild-check-limits) for cases where the estimates do not apply.

See [Notification contents](remediation-base-image-logic.md#rebuild-check-notification) for display conditions, and [Rebuild command guidance](remediation-base-image-logic.md#rebuild-commands) for commands by build method.
If no fixed Go version is displayed, see [Standard library rebuild guidance](remediation-go-logic.md#go-stdlib-rebuild).
