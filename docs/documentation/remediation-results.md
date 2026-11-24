---
title: Reading remediation plan notifications
---

# Reading remediation plan notifications

This page explains the lines and counts in Slack remediation plans, including which updates a PR contains and which packages still need attention.
See [Interpreting update results](remediation-update-results.md#interpreting-updates) for version interpretation and re-pull and rebuild guidance.

See [Fix pull request contents](remediation-pr-results.md) for PR bodies and [Overview of the hints](remediation-fix-hints.md#fix-hints) for explanations of blocked updates.

See [Terms](index.md#terms) for the terminology used on this page.

## Remediation plans in Slack {#reading-results-in-slack-and-webhooks}

Slack remediation plans show proposed changes, PR states, and reasons processing could not proceed, grouped by the affected images and files.

### Example {#slack-example}

The following example proposes a package update and a base image update.
In Slack, image names are bold and PR numbers are links.

```text
🔧 Fix plan
Pull requests: 1 created · 1 open

Image: example/app:latest
File to change: pnpm-lock.yaml in example/application
Pull request: #12 (opened now)
Update: package-a 1.2.3 → 1.2.4
Needs a decision: package-b 2.1.1 cannot be raised to the fixed 2.3.0 (the cause could not be determined)

Image: example/service:latest
File to change: docker/Dockerfile in example/application
Pull request: #13 (open)
Update: base image python 3.12.3-slim → 3.12.4-slim
```

Read the changes included in each PR and the remaining work as follows.

| Line | What this example tells you |
| --- | --- |
| `Pull request: #12 (opened now)` and the following `Update` | PR #12, created in this cycle, includes the update of `package-a` to `1.2.4` |
| `Needs a decision: package-b …` | The update of `package-b` is not included in PR #12 and still needs attention |
| `Pull request: #13 (open)` and the following `Update` | PR #13, which raises the base image to `3.12.4-slim`, is open |

See [Overview of the hints](remediation-fix-hints.md#fix-hints) for how to investigate when “the cause could not be determined” is displayed.

### Displayed fields {#slack-fields}

Remediation plans use lines written as “label: content,” such as `Image:` or `Update:`, to show targets and update details.

Opening count lines such as `Pull requests: … created` are covered separately in [Reading counts](#reading-counts).

The meanings of the `Image`, `Service`, `File to change`, and `Pull request` lines are as follows.

| Display | Meaning |
| --- | --- |
| Image | The running image that produced the findings |
| Service | A name derived from the target workload key when no image name can be used as the heading |
| File to change | The mapped repository and file to change |
| Pull request | A PR link and its status: opened now, open, merged, or closed without merging |

The name displayed under “Service” depends on the environment.
The following shows where names come from, with display examples.

| Environment | Source of the name | Example |
| --- | --- | --- |
| Compose | The `<service>` part of `compose/<project>/<service>` | `Service: web` |
| Containers outside Compose | The `<name>` part of `container/<name>` | `Service: api` |

Read the `Update`, `Update candidate`, `Newer series`, `Re-pull`, and `Rebuild` lines according to their relationship to a PR as follows.

| Display | Meaning | Relationship to a PR |
| --- | --- | --- |
| Update | An image tag or package change proposed by a PR | A change included in the displayed PR |
| Update candidate | A proposed image tag or package change | A candidate that does not necessarily have a PR yet |
| Newer series | A version with a different minor or major number resolves all or some findings without adding findings | Guidance that does not create an update PR |
| Re-pull | A comparison supports updating to new content under the same tag | Guidance that does not create a tag update PR |
| Rebuild | Expected resolution based on dependency constraints, or guidance to pull the base again and build | Guidance rather than a PR that performs the rebuild |

You can check why there is no PR despite an available fix on the card's [`Action:` line](slack-package-display.md#base-image-wait) in the vulnerability notification.

See [Newer-series lines](#newer-series-lines) for how to read the “Newer series” lines.

For the `Needs a decision`, `Deferred`, `Not comparable`, and `Failed` lines, check the reason following the label.

| Display | Meaning | First place to check |
| --- | --- | --- |
| Needs a decision | Manual handling is needed for the source, version constraints, update method, comparison results, or similar issues | The displayed reason and [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| Deferred | Processing postponed to a later cycle because of limits, waiting periods, retrieval problems, or similar issues (`deferred`) | The displayed limit, waiting time, or retrieval problem |
| Not comparable | A result for which information or conditions needed for comparison were missing | [Scan comparison conditions](remediation-logic.md#comparison-conditions) |
| Failed | A failed scan, retrieval, update, or other operation | [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics) |

“Needs a decision” also includes newer-series candidates that resolve findings but add new findings or CISA KEV-listed findings.

CISA KEV is a catalog of vulnerabilities known to have been exploited.
The total finding count does not show whether it includes exploited vulnerabilities, so KEV-listed findings are also checked separately.

Lines beginning with `⚠️` indicate the size of a version change or a stop on PR writes.

| Display | Meaning |
| --- | --- |
| ⚠️ Major version change | An update changing the major version, or the minor version for a 0.x package |
| ⚠️ Pull request writes are stopped | A stop on PR writes because of problems with records, GitHub state, or similar issues |

See [Kubernetes display](#kubernetes-display) for how Kubernetes notifications differ from the common display.

#### Newer-series lines {#newer-series-lines}

The newer-series check examines newer minor and major versions when a newer version in the same series does not resolve findings for a fixed tag.

Depending on the result, the notification shows one of the following lines or no line.
The status values are available in fields such as the webhook's `newer_series.status`.

| Check result | Status value | Line shown |
| --- | --- | --- |
| All resolved without new findings | `resolves` | Newer series |
| Partly resolved without new findings | `resolves_partially` | Newer series |
| All resolved in a base comparison without new findings | `resolves` | Newer series |
| Some findings resolved, but new findings or KEV-listed findings added | `resolves_with_new` | Needs a decision |
| No targets resolved | `not_resolving` | No line |
| The check or assessment could not be completed | `not_checked` | No line |
| No eligible newer series | `no_newer_series` | No line |

The examples below follow the order of the first four results in the table.

```text
Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 finding(s), compatibility not checked)
Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 of 2 findings, compatibility not checked)
Newer series: base image python 3.11.9-slim → 3.13.1-slim (minor update, resolves 2 finding(s), base images compared, the rebuilt image not checked, compatibility not checked)
Needs a decision: nginx 1.24.1 → 2.0.1 in a newer series resolves 1 finding(s) and adds 2 (major update, compatibility not checked)
```

A change to the newer-series line causes the remediation plan message to be sent as a change.
See [Checking newer series](remediation-image-logic.md#newer-series-check) for scope and candidate selection, and [Newer series status values](remediation-reason-codes.md#newer-series-status-values) for value definitions.

### Kubernetes display {#kubernetes-display}

In addition to the common lines ([Displayed fields](#slack-fields)), Kubernetes notifications differ in the following ways.

| Difference | Details |
| --- | --- |
| The name under “Service” | Displays the entire workload key (for example, `Service: deployment/shop/web/app`) |
| The `Pull policy` line | Shows the image pull policy and retrieval guidance for each workload affected by a re-pull |
| The `Managed by (from markers)` line | Shows management relationships inferred from labels and annotations on Kubernetes resources |

The “Service” example identifies a container in a Deployment, not a Kubernetes Service resource.

The following example shows a notification proposing an image tag update and a re-pull.

```text
🔧 Fix plan
Pull requests: 1 created

Image: docker.io/library/nginx:1.25.3
File to change: apps/web.yaml in ex/deploy
Pull request: #4 (opened now)
Update: docker.io/library/nginx 1.25.3 → 1.25.5
Managed by (from markers): deployment shop/web → Argo CD app web-app

Image: ghcr.io/example/api:latest
Re-pull: resolves 2 finding(s)
Pull policy: Always: restarting the Pods pulls the new content (deployment/shop/api/app)
Managed by (from markers): deployment shop/api → Helm release api (shop)
```

Read the retrieval guidance and management relationships as follows.

| Line | What this example tells you |
| --- | --- |
| The `Pull policy: Always: …` line | The pull policy for `deployment/shop/api/app` is `Always`, so restarting the Pods pulls the new content |
| The first `Managed by (from markers)` line | Deployment `shop/web` is inferred to be managed by the Argo CD app `web-app` |
| The second `Managed by (from markers)` line | Deployment `shop/api` is inferred to be managed by the Helm release `api` in namespace `shop` |

See [Kubernetes image references and pulling images again](remediation-kubernetes-logic.md#kubernetes-image-references) for retrieval guidance for each pull policy.
See [Management inference](remediation-kubernetes-logic.md#management-markers) for the labels and annotations used to infer management relationships.

### Reading counts {#reading-counts}

The opening count line uses different counting rules depending on whether the notification contains a PR number.

| Notification contents | Example opening line | Unit counted as one |
| --- | --- | --- |
| Contains a PR number | `Pull requests: 1 created · 1 open` | One update intended for a single PR, counted by processing state |
| Contains no PR number | `1 update candidate(s) · 1 need a decision` | A group of changes to a file or image to re-pull (an item), counted once per result category |

Keep the following points in mind when reading counts.

- Updating several packages together in one dependency file does not count each package separately
- An update grouped into one PR does not gain extra counts merely because it affects several images
- Notifications containing a PR number also count updates without a PR as “need a decision,” “deferred,” or “blocked or failed,” so the count does not necessarily match the number of existing PRs
- In notifications containing a PR number, `Re-pull`, `Rebuild`, and `Newer series` guidance that does not create a PR is excluded from the opening counts
- In notifications containing no PR number, an “Update candidate” line displayed alongside a reason under “Needs a decision,” “Deferred,” or “Failed” is not counted as a separate entry

Read counts related to newer series and findings as follows.

| Count display | What it counts |
| --- | --- |
| `… resolved in a newer series` | Items with status `resolves` or `resolves_partially` |
| `resolves … finding(s)` | Target findings no longer detected in the comparison |
| `… KEV` | Counts related to CISA KEV-listed vulnerabilities included in the displayed results |

States without a PR appear in the body as follows.

| Opening summary | Display in the body |
| --- | --- |
| need a decision | Needs a decision |
| deferred | Deferred |
| blocked or failed | Failed |

The [example](#slack-example) counts PR #12 as one created PR and PR #13 as one open PR.
The opening PR summary does not count `package-b`, which was left out of PR #12, as a separate entry.

The following example has an updatable `package-a` and a `package-b` requiring manual handling in the same file.
It shows how counts change with PR availability in a notification containing no other items.

| State | Opening summary | Treatment of `package-b` |
| --- | --- | --- |
| No PR, with `package-a` as an update candidate | `1 update candidate(s) · 1 need a decision` | One decision entry for the same item |
| A PR containing only `package-a` is created in this cycle | `Pull requests: 1 created` | Still shown as needing a decision in the body, without a separate PR summary entry |

PR processing counts also differ from the number of vulnerabilities.
Several packages needing a decision within one item do not produce a separate “need a decision” count for each package.

Resolved-finding counts for image candidates merge detections with the same CVE ID, package name, package type, and classification into one.
Detecting the same CVE at several versions or locations does not directly turn the number of locations into the finding count.

The following rules determine which packages appear under “Needs a decision.”

- Packages left out of a PR still need attention, but their individual lines are omitted when another package's line explains the reason
- Packages identified as requiring manual handling before an update is attempted show their reasons separately from candidates or PRs for the same file

The following example attempts to update `A` and `B` together, but failure to update `A` also leaves `B` out of the PR's updates.
If `B` has no blocker of its own, the notification groups the explanation as follows.

| Package | Display in the notification |
| --- | --- |
| `A`, which could not be updated | A “Needs a decision” line showing why the update failed |
| `B`, left out because updating `A` failed | No separate line, because the reason is explained by the line for `A` |

Packages with an update target appear on individual lines.
Packages without a target are grouped by reason, with a list below each reason.

### Finding omitted details {#omitted-details}

Slack may shorten long package lists and similar content with “and … more.”
See [Finding detailed results](#detailed-results) for where to find omitted information.

## Finding detailed results {#detailed-results}

Detailed results are available in received webhook notification data and in `plan.json` and `prs.json` saved by KestreLynx.
Notifications and files differ in the information they contain and when it was recorded.

Without webhooks, inspect the PR diff for proposed changes, `plan.json` for planning-time source information and checks, and `prs.json` for PR processing records.
See [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics) for details of retrieval or execution failures.

See [Reason codes](remediation-reason-codes.md#reason-codes) for reason definitions and [When no candidate or pull request appears](remediation-troubleshooting.md) for troubleshooting.

### Webhook details {#webhook-details}

Inspect the actual data in the program that receives the webhook, and use the following links to interpret its fields.

| Information needed | Field specification |
| --- | --- |
| Plan state, comparison conditions, processing limits, and usage | [Common remediation plan fields](webhook-remediation-reference.md#remediation-fields) |
| Published image candidates and comparison results | [Published image fields](webhook-remediation-image-reference.md#remediation-image-fields) |
| Base image candidates and layer check results | [Base image fields](webhook-remediation-dockerfile-reference.md#remediation-dockerfile-fields) |
| Per-package versions, actions, exclusion reasons, runtimes, tools, and update checks | [Language package fields](webhook-remediation-language-reference.md#remediation-language-fields) |
| PR states and packages left out of PRs that still need attention | [PR processing fields](webhook-remediation-pr-reference.md#remediation-pr-fields) |
| Results of operations such as creating and reconciling PRs | [PR operation event fields](webhook-remediation-pr-reference.md#remediation-operation-fields) |
| Problems that stopped PR writes | [Write-blocking problem fields](webhook-remediation-pr-reference.md#remediation-problem-fields) |
| Notification data including a partial PR | [Partial PR example](webhook-remediation-pr-reference.md#remediation-json-example) |

### Saved file details {#saved-details}

`plan.json` contains planning-time information, while `prs.json` contains ongoing PR processing records.
They are stored under `remediation.storage_dir`, which defaults to `/var/lib/kestrelynx/remediation`.

Check the [Basic settings](configuration.md#remediation-basics) in the configuration used by KestreLynx to identify the actual directory.
Read `plan.json` and `prs.json` in that directory with the following recording sequence in mind.

1. After planning and dependency updates, save the pre-PR-processing information in `plan.json`
2. Record PR processing, reconciliation, and operation results in `prs.json`
3. Send the remediation plan results after PR processing

`plan.json` saves `pull_requests_enabled`, which records whether PR creation was enabled for that run.
It does not save the post-processing `pr_items` or `pull_requests`, and is not saved again with post-PR-processing results.

Use notifications for the latest plan's PR processing results and `prs.json` for ongoing PR information.

See [Stored files](remediation-pr-logic.md#stored-records) for contents and recording times, and [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics) for information to gather during investigation.
