---
title: Remediation result values and reason codes
---

# Remediation result values and reason codes

Use remediation values and reason codes to look up candidate decisions and reasons processing could not proceed.
Webhooks carry these values in fields such as `category`, `status`, `action`, and `reason`; Slack notifications use sentences in the notification language to explain reasons.

Webhook field paths below start directly under `remediation`.

Choose a section according to the value you want to look up.

| What to look up | Reference |
| --- | --- |
| The decision for an entire plan item | [Plan category values](#category-values) |
| Results for candidates in newer series | [Newer series status values](#newer-series-status-values) |
| How an individual package is handled | [Package action values](#action-values) |
| PR processing results and the state of a PR | [PR status values](#pr-status-values) |
| Why a candidate was selected or processing stopped | [Reason codes](#reason-codes) |

See [Terms](remediation.md#terms) for the terminology used on this page.

## Result values {#result-values}

Result values describe the state of plan items, candidates, packages, and PR processing separately.

### Plan category values {#category-values}

`category` classifies an entire plan item, such as an image or dependency directory.

Webhooks carry category values in the following fields.

| Target | Field |
| --- | --- |
| Published image | `items[].category` |
| Entire base-image item | `dockerfile_items[].category` |
| Base-image result for each running image | `dockerfile_items[].entities[].category` |
| Dependency directory for language packages | `language_items[].category` |

Category values have the following meanings.

| Value | Meaning |
| --- | --- |
| `pr_candidate` | A candidate that passed checks and can be proposed as a PR |
| `dependency_update_candidate` | A dependency update candidate selected from source and fixed-version information, with update results not yet verified |
| `pull_again` | A compared candidate expected to improve findings by retrieving new content under the same tag |
| `rebuild_expected` | The current dependency range is expected to install a fixed version on rebuild |
| `manual` | Manual handling that leaves the decision to the user without updating automatically |
| `not_comparable` | Information or conditions are missing for comparing the scans before and after the update |
| `deferred` | Processing is deferred to a later cycle because of limits, waiting periods, retrieval problems, or similar conditions |
| `no_candidate` | No newer candidate exists, content is unchanged, or the candidate does not resolve the target findings |
| `excluded` | Outside automatic candidate selection |
| `failed` | Processing failed |

`not_comparable` means a comparison cannot be made, `deferred` means processing is postponed, and `failed` means processing failed.
Check the same item's `reason` for the specific cause.

Slack sometimes uses a display label different from the category value.

| Slack section | Content shown |
| --- | --- |
| "Rebuild" | Shows `rebuild_expected` items and guidance for a floating-tag base image classified as `not_comparable` |
| "Manual" | Shows items requiring manual handling |

See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for interpreting the notification as a whole.

### Newer series status values {#newer-series-status-values}

Newer series status values describe whether another group of versions resolves the target findings.
Relative to `1.24.1`, `1.27.3` is a newer minor series and `2.0.1` is a newer major series.

Webhooks carry these results in `items[].newer_series`, `dockerfile_items[].newer_series`, and `dockerfile_items[].entities[].newer_series`.
Within each object, `candidates[].status` describes each candidate, while `status` summarizes the candidate results.

When a resolving candidate is displayed, `newer_series.shown` contains the tag of the candidate used for the overall decision.
The overall `status` is the status of the candidate whose `tag` matches `shown` in the same `newer_series.candidates[]`.

Newer series results do not change the plan item's overall `category`.

The following field values show an example where a published image displays candidate `2.0.1`.

| Webhook field | Example value |
| --- | --- |
| `items[].newer_series.shown` | `2.0.1` |
| `items[].newer_series.status` | `resolves` |
| `items[].newer_series.candidates[].tag` | `2.0.1` |
| `items[].newer_series.candidates[].status` | `resolves` |

KEV is CISA's Known Exploited Vulnerabilities catalog of vulnerabilities confirmed to have been exploited.
Status values have the following meanings.

| Value | Meaning |
| --- | --- |
| `resolves` | All target findings are resolved without added findings |
| `resolves_partially` | Some target findings are resolved, some remain, and no findings are added |
| `resolves_with_new` | At least one target finding is resolved, but new findings or KEV-listed findings are added |
| `not_resolving` | No target findings are resolved |
| `not_checked` | Checking could not be completed |
| `no_newer_series` | No newer-series tag meets the conditions |

`no_newer_series` is used only for the overall `status`.
For `not_checked`, check the overall or candidate `reason` for the cause.

Possible causes include retrieval or scan failures, candidate-count or other limits, the execution deadline, indeterminate targets, and targets not detected in the baseline.
See [Newer series check](remediation-image-logic.md#newer-series-check) for candidate selection and comparison scope.

### Package action values {#action-values}

`action` describes how an individual package is handled and appears in `language_items[].packages[].action` in webhooks.
Check it separately from the plan item's overall `category`.

Action values have the following meanings.

| Value | Meaning |
| --- | --- |
| `update` | Target for a dependency-file update |
| `rebuild_expected` | The current dependency range allows a fixed version, with resolution expected through rebuilding |
| `manual` | Target requiring manual handling |

`update` alone does not mean that update execution or verification is complete.
Check the following fields together to distinguish execution from validation.

| Field and value | What it confirms |
| --- | --- |
| `language_items[].update_executed: true` | Dependency update operations ran to completion during processing of the latest remediation plan |
| `language_items[].post_update_check_executed: true` | Update results were received and checked during processing of the latest remediation plan |
| `language_items[].source_check.passed: true` | The before-and-after dependency-file check passed |

An executed check can still fail.
See [Target and adopted versions](remediation-update-results.md#target-and-adopted-version) for distinguishing version values.

### PR status values {#pr-status-values}

PR status values describe the result of PR processing for a remediation plan and the state of the corresponding PR itself.
Webhook field `pull_requests[].status` carries the following processing results.

| Value | Meaning |
| --- | --- |
| `pr_created` | A PR was created during processing of the latest remediation plan |
| `pr_open` | A PR proposing the same update is open |
| `pr_merged` | A PR for the same update was merged, without confirmation of deployment |
| `pr_suppressed` | Recreation was suppressed because the update was closed without merging |
| `manual` | Automatic editing is unavailable and manual handling is required |
| `deferred` | Processing was deferred to a later cycle because of limits, candidate changes, or similar conditions |
| `failed` | A GitHub write or another operation failed |
| `write_blocked` | Writes stopped because of problems with PR processing records, GitHub state, or similar conditions |
| `write_disabled` | Indicates that PR creation is disabled; not generated during normal PR processing |

Webhook field `pull_requests[].state` is the state recorded for the corresponding PR in `prs.json`.
Read the following values separately from the processing result in `status`.

| Value | Meaning |
| --- | --- |
| `open` | The PR is open |
| `closed` | The PR was closed without merging |
| `merged` | The PR was merged |
| `replaced` | KestreLynx closed the PR to replace it with a newer PR |

## Reason codes {#reason-codes}

A reason code is a value in a result's `reason` field explaining why a candidate was selected or why processing could not proceed.
In webhooks, check it on plan items, candidates, `language_items[].packages[]`, update results, `pull_requests[]`, and other results.

Choose a reason category to open the page and section listing its codes.

| Reason category | When to use it | Page and section |
| --- | --- | --- |
| Image candidates | Checking image comparisons or candidate adoption | [Image candidate reasons](remediation-image-reason-codes.md#image-reasons) |
| Source | Checking file retrieval, parsing, editing, or matching to running images | [Source reasons](remediation-image-reason-codes.md#source-reasons) |
| Runtime | When a language runtime or work container cannot be used | [Runtime reasons](remediation-update-reason-codes.md#runtime-reasons) |
| Tool retrieval | Checking package manager retrieval, verification, or waiting periods | [Tool retrieval reasons](remediation-update-reason-codes.md#tool-reasons) |
| Update results | Checking dependency update selection, execution, or validation results | [Update result reasons](remediation-update-reason-codes.md#update-reasons) |
| PR processing | Checking PR creation, reconciliation, replacement, or stopped writes | [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| Storage | When PR processing records cannot be read or saved | [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |
