---
title: Fix pull request management and records
---

# Fix pull request management and records

This page explains how KestreLynx prevents duplicate fix PRs, handles closed PRs, and replaces older PRs.
It also explains record files, recovery, and the conditions that stop writes to GitHub.

For terms used on this page, see [Terms](remediation.md#terms).

## PR management {#pr-management}

KestreLynx compares its PR processing records with the state on GitHub to decide whether to create or replace PRs.
Handling in the next cycle depends on the PR's state.

| PR state | Handling in the next cycle | Details |
| --- | --- | --- |
| Open PR | Link the same update to the existing PR and prevent duplicate creation | [Matching existing PRs](#existing-pr-matching) |
| Merged PR | Prevent the same update from being proposed again without assuming it has been deployed | [Closed PRs](#closed-prs) |
| PR closed without merging | Prevent the same update from being proposed again even after branch deletion | [Closed PRs](#closed-prs) |
| User-modified PR | Use PRs with detected modifications to prevent duplicates, but not for automatic replacement | [Matching existing PRs](#existing-pr-matching) and [Replacing older PRs](#pr-replacement) |
| PR recovered solely from an identification marker | Use it to prevent duplicates, but not as evidence for skipping reruns or for automatic replacement | [Record recovery](#record-recovery) |

### Matching existing PRs {#existing-pr-matching}

Matching existing PRs prevents duplicate PRs for the same update.
It uses records of open, merged, and closed PRs.

Re-resolution through dependent packages also updates direct dependencies to select new versions of transitive dependencies.
For details, see [Re-resolution through dependent packages](remediation-reresolution-logic.md#dependent-reresolution).

The update type, edit destination, and update content determine whether an update is the same.

| Category | Information compared |
| --- | --- |
| Update type | Compose, Dockerfile, language packages, Kubernetes manifests, Kustomize, or Helm values |
| Edit destination | Repository, base branch, file, and edit locations |
| Image update content | Image reference before the update, destination tag, and digest |
| Kubernetes manifest, Kustomize, and Helm values update content | Containers affected by the tag change |
| Language package update content | Packages and their positions in dependency files, adopted versions, and changes to version declarations |
| Changes involving re-resolution through direct dependencies | Names and before-and-after versions of direct dependencies updated together, and the direct dependencies through which target packages were updated |

An update involving re-resolution through direct dependencies is matched separately from a regular update, even if the adopted versions are the same.

The decision to skip rerunning a language package update uses the edit destination, package manager, and matching inputs.
Skipping reruns requires a record saved by KestreLynx after creating the PR, or a record whose inputs were verified by rerunning the update.

If inputs such as file contents and package versions match a record that meets these conditions, KestreLynx links the update to the existing PR without rerunning it.
For how this differs from records recovered solely from identification markers, see [Record recovery](#record-recovery).

The base commit and file contents before and after the edit are recorded separately as inputs to PR creation.
Matching base commits is not required to prevent duplicate creation or to skip rerunning a language package update.

For language package updates, targets without an open PR for the same lockfile take priority.
New updates get new PRs, without overwriting existing branches or force-updating them.

If a PR managed by KestreLynx is open for the same lockfile, KestreLynx compares the findings resolved by the older PR and the new update.
If the new update cannot resolve every finding that the older PR claimed to resolve, the new PR is deferred (`deferred`).

For the conditions for covering the older PR's fixes, see [Replacing older PRs](#pr-replacement).

KestreLynx detects user modifications by comparing the PR on GitHub with its creation record.
During routine reconciliation, it checks the following values.

| Modification detected | Value compared with the creation record |
| --- | --- |
| Commits added to or rewritten on the PR branch | PR head commit SHA |
| PR base branch changed | Base branch name |
| PR destination repository changed | Destination repository ID |

The PR body contains information in an HTML comment indicating that KestreLynx created the PR.
This information is called the identification marker.

During routine reconciliation, editing only the PR body does not count as a user modification.
An unsettled creation outcome includes cases where the result of a PR creation request to GitHub could not be confirmed, leaving it unclear whether the PR was created.

When checking a PR whose creation outcome is unsettled, a missing or mismatched identification marker, or multiple PRs on the same branch, also counts as a modification.

Another PR found on a branch created by KestreLynx also counts as user-modified if KestreLynx cannot confirm that it created that PR.
For validation of identification markers used in recovery, see [Record recovery](#record-recovery).

PRs with detected modifications and PRs recovered solely from identification markers do not cause a different update to the same lockfile to be deferred.
Their records still prevent duplicate creation of the same update.

### Closed PRs {#closed-prs}

Records of PRs closed without merging prevent the same update from being proposed again.
This suppression remains after the branch is deleted.

The following policies apply to suppression.

- If the update content is unchanged, advancing the base branch does not allow the update to be proposed again
- Merged PRs also prevent duplicate creation of the same update
- PR records and suppression records do not expire

A PR reopened on GitHub is recorded as open during the next reconciliation.
A merged state does not establish that the change has been deployed to the running environment.

### Replacing older PRs {#pr-replacement}

Replacement closes an older PR when a new PR covers its fixes.
KestreLynx does not close an older PR solely to make room under the PR count limit.

The following common conditions apply to every update.

- The destination repository, base branch, file, and edit locations match
- The containers affected by the tag change match between the two PRs
- The new PR resolves every finding that the older PR claimed to resolve
- Both PRs are open
- Neither PR has detected user modifications or was recovered solely from an identification marker

The values compared with each PR's creation record are the same as those used to detect user modifications in [Matching existing PRs](#existing-pr-matching).
Adding commits to the base branch alone does not create a mismatch with the creation record.

The following conditions depend on the update type.

| Update type | Type-specific conditions |
| --- | --- |
| Image update | A newer patch in the same image repository and tag series |
| Base image update | The image update conditions, plus coverage of the fixes for each running image targeted by the older PR |
| Language package update | The common conditions |

For image updates, KestreLynx also checks during replacement that the candidate tag still points to the content used in the comparison.

PRs that meet the conditions are replaced in the following order.

1. Recheck both PRs and add a comment to the older PR identifying its replacement
2. Recheck both PRs and close the older PR

If the conditions no longer hold during a check before either write, replacement stops.
Once a user modification is detected on a PR, that PR is excluded from automatic replacement even if it returns to its original state.

## Records {#pr-records}

Fix plans, notification delivery status, and PR processing records are stored separately by purpose.

### Stored files {#stored-records}

Record files and tool caches are stored under `remediation.storage_dir`.
Their contents are as follows.

| File or directory | Contents |
| --- | --- |
| `plan.json` | Latest plan, source locations, scans used for comparison, and validation results from executed dependency updates (excluding results after PR processing) |
| `delivered.json` | Information separately identifying the delivered plan and the content displayed in Slack and email |
| `prs.json` | PR identity, state, creation attempts, suppression of repeated proposals, and GitHub operation records |
| `tools` | Cache of fetched and verified npm, pnpm, and uv tools |

For re-resolution through dependent packages, `prs.json` also stores the following records.

| Recorded information | Handling in the next cycle |
| --- | --- |
| End of the waiting period after release | Wait until the recorded time before retrying |
| Consecutive deferrals by reason type, such as release waiting periods or reached limits | Determine whether to continue retrying re-resolution or stop |
| Inputs for which re-resolution stopped, and the reason | Do not retry re-resolution through dependent packages for the same inputs |

Waiting, deferral, and stop records are kept separately for each repository, base branch, and dependency file.
Inputs are compared using information such as file contents and the target packages' running versions and update targets.

When inputs change, stop records for the previous inputs no longer apply.
For detailed retry and stop conditions, see [Release waiting periods and retries](remediation-reresolution-logic.md#dependent-reresolution-waits).

Check notifications for the latest plan's PR processing results, and `prs.json` for records maintained across cycles.

For the storage location setting, see [Basic settings](configuration.md#remediation-basics).

### Record save order {#record-order}

KestreLynx saves the plan and dependency update validation results before creating PRs or matching existing PRs.
If saving the plan fails, the cycle does not proceed to PR processing.

Records are saved at the following points.

| When saved | Destination and information saved |
| --- | --- |
| After dependency update processing | Waiting, deferral, and stop records in `prs.json` |
| Before PR processing | Plan and dependency update validation results in `plan.json` |
| During PR processing and reconciliation | PR state and related records in `prs.json` |
| Before each GitHub write | Intended operation in `prs.json` |
| After each GitHub write | Operation result in `prs.json` |
| After notification delivery | Delivered information in `delivered.json` and operation history delivery status in `prs.json` |
| When tools are fetched and at related points | Cache in `tools` |

For how to read PR operation events, see [PR operation event fields](webhook-remediation-pr-reference.md#remediation-operation-fields).

### Record recovery {#record-recovery}

Record recovery rebuilds PR processing records from PRs on GitHub when `prs.json` is missing.
Before writing, KestreLynx examines open and closed PRs in the configured repositories.

It reads identification markers from the bodies of PRs on `kestrelynx/` branches in the same repository.
It recomputes the marker's identifiers and verifies the repository and branch associations.

PRs for Kubernetes manifests, Kustomize, and Helm values are distinguished by the following information.

| PR type | Branch name prefix | Identification marker kind |
| --- | --- | --- |
| Kubernetes manifest tag update | `kestrelynx/kubernetes/` | `kubernetes` |
| Kustomize tag update | `kestrelynx/kustomize/` | `kustomize` |
| Helm values tag update | `kestrelynx/helm/` | `helm_values` |

A version of KestreLynx that does not support a PR type cannot recognize existing PRs of that type.

The following policies apply to checks before writing.

- When recovering without `prs.json`, no writes are made to GitHub until all target repositories have been checked
- Newly configured repositories are also checked for existing PRs before the first write
- Records recovered solely from identification markers prevent duplicates but are not used for automatic replacement

An identification marker alone is not evidence that a language package update was executed and validated.
Skipping reruns requires records created by KestreLynx, or records whose inputs were verified by rerunning the update.

## Stopping writes {#write-stops}

If records or the state on GitHub cannot be verified, KestreLynx stops GitHub writes within the scope of the problem.
It does not replace corrupt plan or PR records, or records with unsupported versions, with empty records to continue processing.

The stop conditions and their scope are as follows.

| Stop condition | Scope or handling |
| --- | --- |
| Plan save failure | All PR processing in the cycle |
| PR record read or save failure, or failure to acquire the record lock | Writes to all repositories in the cycle |
| Existing PR lists, recorded PRs, or unsettled operation outcomes cannot be read | Writes to the entire affected repository |
| A PR creation branch points to a commit different from the record, or multiple PRs exist on the same branch | New creation and replacement for the same repository, base branch, update type, file, and edit locations |
| A GitHub write has an unknown outcome | All subsequent writes to all repositories in the cycle |
| Repository name or identity differs from the configuration or records | Writes to the affected repository |
| Operation history has no room for new events | New GitHub operations across all repositories in the cycle |
| A request, processing time, or similar limit is reached | Remaining affected processing is deferred |

A stop limited to an edit destination does not stop writes to the entire file.
For example, even if a PR creation branch points to a commit different from the record, other edit destinations and repositories can continue unless another stop condition applies.

If recovery cannot finish while `prs.json` is missing, writes stop for all target repositories as described in [Record recovery](#record-recovery).
A repository name or identity mismatch does not automatically redirect writes to a transferred repository or another destination.

An unknown write outcome is checked by reading during the next cycle.
The same write is not resent without checking.

Operation history is retained to check GitHub operation outcomes later and to deliver operation events in notifications.
Before starting a new operation, KestreLynx checks whether the required events fit within the retention limit of 1,000 operation events.

Cleanup removes only delivered events that are no longer needed for unsettled operations or replacements in progress.
For example, if undelivered events alone reach 1,000, no events can be removed and no new operation can start.

For stop reports, see [Write-blocking problem fields](webhook-remediation-pr-reference.md#remediation-problem-fields); for reason codes, see [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) and [Storage reasons](remediation-update-reason-codes.md#storage-reasons).
For limit settings, see [Processing limits](configuration.md#remediation-limits); for checks and actions, see [Checking record reconciliation failures](remediation-troubleshooting.md#check-record-failure).
