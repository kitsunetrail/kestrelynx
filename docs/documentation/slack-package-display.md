---
title: Slack package cards and change labels
---

# Slack package cards and change labels

This page explains how to read each part of a package card and how changes appear in diff reports.
See [Slack report structure and counts](slack-display.md) for the overall report structure and counts.

## Reading package cards {#package-card}

Package cards show the package name followed by the installed version, fixed version, finding counts, and other details.
Act now findings in the channel use detailed cards like this.

```text
◆ openssl
Installed: 3.0.7
Fixed in: 3.0.11
Upgrade risk: 🟢 distro security patch
Findings: CRITICAL 1 / HIGH 0
CVEs:
• CVE-2031-0001 · CRITICAL · EPSS 94% · CISA KEV (exploited in the wild) · 🧨 ransomware campaign · openssl: buffer overread · vendor advisory
```

Watch findings in the channel use compact cards like this.

```text
◆ e2fsprogs
Installed: 1.47.0-2 · Fixed in: none
Findings: CRITICAL 1 / HIGH 0
CVEs: CVE-2031-0003 (EPSS 3%)
```

The following table shows which card format is used.
Full channel reports include the full report added to weekly notifications.

“Fixes needing attention” in the table means packages with an available fix that contain CRITICAL findings or require a major version increase.

| Location | Detailed cards | Compact cards | No cards (counts or summaries) |
| --- | --- | --- | --- |
| Full channel report (triage enabled) | Act now | Watch and EOL | Low |
| Full channel report (triage disabled) | — | Fixes needing attention, no fix available, no fix planned, and EOL | Other available fixes |
| Thread (triage enabled) | Act now, Watch, and EOL | Pointers in the EOL section | Low |
| Thread (triage disabled) | All fix statuses | — | — |
| Channel diff | Act now with triage enabled | Other individually displayed packages | — |

The following exceptions apply to EOL and muted findings.

- When the base OS is EOL, its EOL packages are summarized in the base OS display
- If triage is enabled and an EOL package has Act now priority, its detailed card appears in the Act now section
- When `Details: 🚨 see Act now` appears in the EOL section of a full report or thread, see the Act now section for that package's details
- [Muted](slack-runtime-display.md#muted-display) packages have no individual cards

The following table shows the format used when each item appears.
This comparison applies to both channel and thread cards.

| Item | Detailed card | Compact card |
| --- | --- | --- |
| Installed and fixed versions | Separate lines | Same line |
| Upgrade risk | `Upgrade risk:` line | In parentheses after the fixed version |
| Finding counts | CVE counts by severity | CVE counts by severity |
| Action | [Card action line](#base-image-wait) | [Card action line](#base-image-wait) |
| CVEs | One line per CVE | CVE IDs on one line |
| Runtime usage | Display including observation evidence | Short in-use display |

`Findings:` counts distinct CVE IDs included in that card.
See [Priority line counts](slack-display.md#priority-counts) for how findings are separated into cards and [CVE details](#cve-details) for CVE content and ordering.

Channel cards show observed use, while detailed thread cards also show when use was not observed or could not be determined.
See [Usage labels](slack-runtime-display.md#usage-labels) for details.

When no fixed version is available, `Fixed in: none` appears.
Detailed cards add the following guidance according to fix status.

| Fix status | Display |
| --- | --- |
| No fix available | `Fixed in: none — consider mitigation` |
| No fix planned for this OS release | `Fixed in: none — no fix planned for this OS release, consider replacing` |

See [EOL display](#eol-display) for the guidance added to EOL cards.

The image heading before the cards identifies the image where the following packages were found.
Here is an example heading.

```text
Image: api:2.0
```

When the same image name has multiple digests, a short digest distinguishes them.
The OS and CPU architecture are also included when needed.

### CVE details {#cve-details}

Cards list their CVEs under `CVEs:`, with one CVE per line on detailed cards and all IDs on one line on compact cards.
Detailed cards list CVEs below the `CVEs:` line as follows.

```text
CVEs:
• CVE-2031-0001 · CRITICAL · EPSS 94% · CISA KEV (exploited in the wild) · 🧨 ransomware campaign · openssl: buffer overread · vendor advisory
• CVE-2031-0006 · HIGH · EPSS 20% · libxml2: use-after-free
```

The following table lists each line's items from left to right.
Items without information are omitted.

| Item | Display example | Meaning |
| --- | --- | --- |
| CVE ID | `CVE-2031-0001` | Vulnerability ID; see the final table in this section for link destinations |
| Severity | `CRITICAL` | Severity of the CVE |
| EPSS | `EPSS 94%` | Score indicating the likelihood of exploitation |
| KEV | `CISA KEV (exploited in the wild)` | Listed in CISA KEV as exploited in actual attacks |
| Ransomware | `🧨 ransomware campaign` | Information indicates use in ransomware attacks |
| Description | `openssl: buffer overread` | Trivy findings use Trivy's description; Node.js and Python runtime findings use the runtime's vulnerability information |
| Vendor information | `vendor advisory` | Link to vendor or CISA information from KEV notes |

`EPSS n/a` on a detailed card means no score is available; very small values appear as `<0.1%`, and very large values as `>99%`.

EPSS, KEV, and ransomware information appears when triage is enabled and KEV or EPSS is available.
When triage is enabled and neither KEV nor EPSS is available, the `CVEs:` line indicates this.

```text
CVEs: severity only (intel unavailable)
• CVE-2031-0003 · CRITICAL · e2fsprogs: out-of-bounds write
```

Compact cards list CVE IDs on one line as follows.

```text
CVEs: CVE-2031-0007 (EPSS 0.4%), CVE-2031-0008, CVE-2031-0009
```

- CVEs with an EPSS score show the score after the ID in the form `(EPSS 3%)`
- When triage is disabled or neither KEV nor EPSS is available, severity appears instead of the score in the form `(HIGH)`

All cards list CVEs in the following order.
Each criterion is used only when the preceding criteria do not distinguish the CVEs.

1. Priority in the order Act now → Watch → Low
2. CVEs with an EPSS score before CVEs without one
3. Higher EPSS scores first
4. CVE IDs in ascending string order

Up to 20 CVEs are listed, with the remaining CVEs shown as a count.

- Compact cards show `(+N more)` at the end of the line
- Detailed cards show `• +N more` on the last line

Cards for previously detected packages with added CVEs show the added CVE IDs on the `Change:` line and include them in the `CVEs:` list.
Only cards showing `Details: 🚨 see Act now` omit CVEs.

CVE IDs under `CVEs:` and `Change:` use the following link destinations.

| Condition | Link destination |
| --- | --- |
| Trivy or the runtime's vulnerability information provides an advisory URL | That advisory |
| No URL is available and the ID has the CVE format | NVD |
| No URL is available and the ID is not a CVE ID, such as GHSA or DLA | Plain text without a link |

See [Vulnerability fields](webhook-reference.md#vulnerability-fields) for complete CVE data without omissions.

### Card action line {#base-image-wait}

The card's `Action:` line shows image or dependency-file updates, expected resolution through repulling or rebuilding, PR status, and reasons a decision is needed or an update or check cannot be completed.
It appears after `Findings:` in detailed and compact channel cards, thread cards, and diff cards, and also appears on cards included in email.

A series groups versions by their first two numbers, so 3.11 and 3.13 are different series.

#### Resolution in a newer series and waiting for a version

When updating the base image to a newer series resolves the vulnerabilities, the line looks like this.

```text
Action: base image python 3.11.9 → 3.13.1 resolves it (minor update, no newer tag in the same series, base images compared)
```

The following table explains each part of the line and the notes added for different results.
Vulnerabilities in this table mean the findings with an available fix on that card.

| Part of the display | Meaning |
| --- | --- |
| `base image` | The image specified in the Dockerfile as the starting point for building the image |
| `image` | The published image itself |
| `python` | The last part of the image name being checked for updates, omitting the registry hostname and preceding path |
| `3.11.9 → 3.13.1` | The current image version on the left and the candidate version compared on the right |
| `resolves it` | All target vulnerabilities on the card disappear in the candidate |
| `resolves part of it` | Some target vulnerabilities on the card disappear in the candidate, while others remain |
| `waiting for a newer` | No version resolving the card's target vulnerabilities has been found within the checks performed |
| `1 of 2` | One of the card's two vulnerabilities with an available fix is resolved in the candidate, counting each vulnerability ID once |
| `minor update` | An update that keeps the first version number and increases the second |
| `major update` | An update that increases the first version number |
| `no newer tag in the same series` | No newer version exists in the current series |
| `not resolved by the newer tag of the same series` | The newer version in the current series does not resolve the target vulnerabilities |
| `the newer tag of the same series has the same content` | The newer tag in the current series points to the same content as the running image |
| `base images compared` | The current and candidate base images were compared; the rebuilt final image has not been checked |
| `with new findings` | Updating to the candidate also brings new findings |
| `not resolved in the checked tag(s) 1.27.3 and 2.0.1 either` | The target vulnerabilities remain in the named candidates; resolution in other versions has not been checked |

The following examples show the line for each result.

| Result | Example |
| --- | --- |
| Resolved in a base image | `Action: base image python 3.11.9 → 3.13.1 resolves it (minor update, no newer tag in the same series, base images compared)` |
| Partly resolved in an image | `Action: image nginx 1.24.1 → 1.27.3 resolves part of it (1 of 2, minor update, no newer tag in the same series)` |
| Still unresolved in the newer series checked | `Action: waiting for a newer image of nginx 1.24.1 (not resolved in the checked tag(s) 1.27.3 and 2.0.1 either)` |
| Unresolved in the same and newer series | `Action: waiting for a newer image of nginx (not resolved by the newer tag of the same series or the checked tag(s) 2.0.1)` |
| Still unresolved in the newer version of the same series, no matching newer series | `Action: waiting for a newer image of nginx (not resolved by the newer tag of the same series)` |
| No matching newer version | `Action: waiting for a newer base image of python 3.11.9 (no newer tag in the same series or in a newer series of the same form)` |
| No newer version in the same series | `Action: waiting for a newer base image of python 3.11.9 (no newer tag in the same series)` |
| Newer tag in the same series, same content as the current tag | `Action: waiting for a newer base image of python 3.11.9 (the newer tag of the same series has the same content)` |
| Base image: still unresolved in the newer version of the same series, no matching newer series | `Action: waiting for a newer base image of python (not resolved by the newer tag of the same series, base images compared)` |

The `Action:` line may be omitted for cards containing findings whose resolution cannot be determined, among other cases.
However, when the base image is known to have no newer version in the same series, the line may show only that information.

#### Update candidates in the same series {#action-same-series}

When a published image has an update candidate in the same series and its remediation category is `pr_candidate`, the line shows comparison results for findings with an available fix on that card.

The following examples show each result.

| Result | Example |
| --- | --- |
| All resolved | `Action: image nginx 1.27.2 → 1.27.3 resolves it` |
| Partly resolved | `Action: image nginx 1.27.2 → 1.27.3 resolves part of it (1 of 2)` |
| All remain | `Action: waiting for a newer image of nginx 1.27.2 (not resolved in 1.27.3 of the same series)` |
| Includes findings that cannot be assessed | `Action: whether image nginx 1.27.2 → 1.27.3 resolves it could not be confirmed` |

When PR creation is enabled, the PR status is added in parentheses at the end of resolved and partly resolved lines.
It is omitted when all findings remain, resolution cannot be assessed, or PR creation is disabled.

| Result | Example |
| --- | --- |
| All resolved | `Action: image nginx 1.27.2 → 1.27.3 resolves it (Pull Request #12)` |
| Partly resolved | `Action: image nginx 1.27.2 → 1.27.3 resolves part of it (1 of 2, Pull Request #12)` |

The following table shows display examples for each PR status.

| Status | PR status display example |
| --- | --- |
| Created or open | `Pull Request #12` |
| Merged | `Pull Request #12 is merged; the running image has not been updated` |
| Closed without merging | `Pull Request #12 was closed without merging` |
| Replaced by another PR | `Pull Request #12 was closed without merging and replaced by #13` |
| Content changed by a user | `Pull Request #12 differs from its original content` |
| Not created or processing not started | `Pull Request not created: the pull request records could not be saved` |
| Write outcome unknown | `Pull Request creation is unconfirmed: the result of a write to GitHub is unknown` |
| No mapping | `Pull Request will not be created: no source mapping is configured` |
| Container started with `docker run` | `Pull Request will not be created: image tags of containers started with docker run are not supported by pull requests` |

PR numbers link to their PRs, and multiple open PRs appear as `Pull Request #12, #14`.
For a PR changed by a user, the content-change message takes precedence even after merging.

The reason appears after `Pull Request not created:`, `Pull Request creation is unconfirmed:`, or `Pull Request will not be created:`.
See [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) for the list of reasons.

#### Base image update candidates in the same series {#action-base-candidate}

The following examples apply to images with a Dockerfile mapping when the findings are in the layers of a base image with a pinned tag.

| Result | Example |
| --- | --- |
| All resolved | `Action: base image python 3.11.9 → 3.11.10 resolves it (base images compared)` |
| Partly resolved | `Action: base image python 3.11.9 → 3.11.10 resolves part of it (1 of 2, base images compared)` |
| All remain | `Action: waiting for a newer base image of python 3.11.9 (not resolved in 3.11.10 of the same series, base images compared)` |
| Includes findings that cannot be assessed | `Action: whether base image python 3.11.9 → 3.11.10 resolves it could not be confirmed (base images compared)` |
| All resolved, with a PR created | `Action: base image python 3.11.9 → 3.11.10 resolves it (Pull Request #12, base images compared)` |
| PR merged, waiting for the image to be rebuilt | `Action: Pull Request #13 is merged; waiting for the image to be rebuilt` |

When PR creation is enabled, resolved and partly resolved lines include the PR status under the same rules as [Update candidates in the same series](#action-same-series).
For a merged base image PR, the PR status shows `Pull Request #12 is merged; waiting for the image to be rebuilt`.

#### Pulling the same tag again {#action-pull-again}

For an image with a tag that does not pin a version, such as `latest`, the line shows whether pulling the same tag again resolves the findings.

| Result | Example |
| --- | --- |
| All resolved | `Action: pulling image nginx latest again resolves it` |
| Partly resolved | `Action: pulling image nginx latest again resolves part of it (1 of 2)` |
| All remain | `Action: waiting for new content of image nginx latest (pulling again does not resolve it)` |
| The tag has the same content as the running image | `Action: waiting for new content of image nginx latest (the tag has the same content as the running image)` |
| Includes findings that cannot be assessed | `Action: whether pulling image nginx latest again resolves it could not be confirmed` |

#### Rebuilding with the same base image tag {#action-base-floating}

For images with a Dockerfile mapping whose base image uses a tag that does not pin a version, such as `node:24-alpine`, the following lines describe findings in the base image's layers.

| Example | Meaning | What to do |
| --- | --- | --- |
| `Action: waiting for new content of base image node 24-alpine (the tag's content has not changed since the image was built)` | The content referenced by the tag has not changed since the image was built | Wait for the publisher to update the tag's content |
| `Action: a rebuild is expected to resolve it (fixed in the current base image node 24-alpine)` | The tag's content has been updated, and the findings are fixed in its current content | Rebuild and deploy the image |
| `Action: a rebuild is expected to resolve part of it (1 of 2, compared with the current base image node 24-alpine)` | Only some findings are fixed in the current content | Rebuild and deploy the image, then wait for the publisher to fix the remaining findings |
| `Action: waiting for new content of base image node 24-alpine (still present in its current content)` | The tag's content has been updated, but the findings remain in its current content | Wait for the publisher to release an update |
| `Action: whether a rebuild resolves it could not be confirmed (the current base image has no package at the same location)` | The current base image has no package at the same location | Check whether the package is installed by Dockerfile instructions |

The estimate compares scan results for the running image and the current base image; the image after rebuilding has not been checked.
See [Estimate limitations](remediation-base-image-logic.md#rebuild-check-limits) for details.

#### Updates needing a decision {#action-decision}

When a version to update to or new content for the same tag has been found, the line includes `decision needed:` if switching would cause another problem or KestreLynx cannot confirm whether it is OK to switch.
The reason that follows describes the problem or what cannot be confirmed.

| Case | Example |
| --- | --- |
| The candidate resolves it | `Action: image nginx 1.27.2 → 1.27.3 resolves it (decision needed: the candidate brings new findings)` |
| The candidate resolves part of it | `Action: image nginx 1.27.2 → 1.27.3 resolves part of it (1 of 2, decision needed: the candidate brings new findings)` |
| Pulling again resolves it | `Action: pulling image nginx latest again resolves it (decision needed: the candidate brings new findings)` |
| Resolution is unknown | `Action: updating image nginx needs a decision (how the service is built cannot be determined)` |
| The base image candidate resolves it | `Action: base image python 3.11.9 → 3.11.10 resolves it (decision needed: the candidate brings new findings, base images compared)` |
| Resolution through a base image update is unknown | `Action: updating the base image needs a decision (the workloads sharing the Dockerfile do not agree on one candidate)` |

No PR is created for the update shown on this line, so review the reason and decide whether to update.
See [Tags and candidate decisions](remediation-image-reason-codes.md#image-candidate-reasons) and [Compose](remediation-image-reason-codes.md#source-compose-reasons) for the list of reasons.

#### When a newer version cannot be checked {#action-not-checked}

When a newer image version has not been checked or could not be checked, the line shows the reason.

| Example | Meaning | What to do |
| --- | --- | --- |
| `Action: a newer image has not been checked (the reference has a digest and no tag)` | The image reference format is outside the scope of newer-version checks | Review the reason in parentheses |
| `Action: a newer image could not be checked (the registry requires a login)` | Retrieving or comparing a newer version failed | Address the cause given in parentheses |
| `Action: a newer image will be checked in a later run (the time limit of the run was reached)` | A limit or timeout prevented the check in this run | Wait for the next scan |
| `Action: a newer base image could not be checked (the analysis of the image was incomplete)` | Incomplete image analysis prevented checking a newer version | Address the cause given in parentheses |
| `Action: a newer base image will be checked in a later run (the limit on candidate scans of a run was reached)` | The candidate scan limit prevented the check in this run | Wait for the next scan |

See [Image and source reason codes](remediation-image-reason-codes.md) for the list of reasons shown in parentheses.

#### Language package updates through dependency files {#action-dependency-files}

For images with a dependency-file mapping, the following lines describe language packages matched against the dependency files.

| Example | Meaning | What to do |
| --- | --- | --- |
| `Action: updated to 2.0.4 in Pull Request #12` | A PR updates the dependency files to raise this package to 2.0.4 | Merge the PR, then rebuild and deploy the image |
| `Action: updated to 2.0.4 in Pull Request #12; merged, but not yet in the running image` | The PR is merged, but the running image still contains the older version | Rebuild and deploy the image |
| `Action: the update to 2.0.4 in Pull Request #12 was closed without merging` | The PR was closed without merging | Decide whether to update the package yourself |
| `Action: the update to 2.0.4 in Pull Request #12 was closed without merging and replaced by #13` | #12 was closed, and the new PR #13 carries the same fix | Review #13 |
| `Action: candidate to update to 2.0.4 through pnpm-lock.yaml (Pull Request not created: the files of the update cannot be written as they are)` | Updating the dependency files confirmed that the package reaches 2.0.4, but no PR has been created | Review the reason in parentheses |
| `Action: candidate to update to 2.0.3 or later through pnpm-lock.yaml (Pull Request not created: the dependency-file update has not been verified)` | The dependency files list this package and the minimum fixed version is known to be 2.0.3, but the update has not been run | Update the dependency files yourself or enable language package updates |
| `Action: a rebuild is expected to install 2.0.3 or later` | The dependency files specify a version range that includes a fixed version | Rebuild and deploy the image |
| `Action: it could not be fixed automatically through pnpm-lock.yaml (the candidate or the updated version does not satisfy the dependency constraints)` | This package could not be updated automatically | Review the reason in parentheses and decide whether to fix the dependency files yourself |
| `Action: pnpm-lock.yaml could not be updated (the update job failed)` | The dependency-file update as a whole did not succeed | Address the cause given in parentheses |
| `Action: updating pnpm-lock.yaml is deferred to a later run (the time limit of the run was reached)` | A limit or timeout prevented the update in this run | Wait for the next scan |
| `Action: the update to pnpm-lock.yaml could not be confirmed (the pull request is not as it was created)` | A PR exists, but whether its contents update this package cannot be confirmed | Review the PR contents |
| `Action: updating pnpm-lock.yaml cannot fix it (the dependency files do not list the package at the running version)` | Updating the dependency files does not reach this package | Review the reason in parentheses |

- When PR creation is disabled, the parenthetical text is omitted from candidate lines
- The filename in the line is `package-lock.json`, `pnpm-lock.yaml`, `uv.lock`, `requirements.txt`, `go.mod`, `pom.xml`, or `gradle.lockfile`, depending on the mapped package manager
- See [Update and PR processing reason codes](remediation-update-reason-codes.md) for the list of reasons shown in parentheses

#### Global node_modules {#action-global-node-modules}

Packages whose remediation reason is `global_node_modules` show that dependency-file updates will not fix them.
The owner is a package such as npm or pnpm installed directly under global `node_modules`.

The following examples distinguish the relationship between the package and its owner.

| Relationship | Example |
| --- | --- |
| Bundled, with a known owner version | `Action: bundled with pnpm 10.34.4 (/usr/local/lib/node_modules); updating pnpm-lock.yaml will not fix it` |
| Bundled, with an unknown owner version | `Action: bundled with npm (/usr/local/lib/node_modules); updating pnpm-lock.yaml will not fix it` |
| The globally installed package itself | `Action: pnpm itself in /usr/local/lib/node_modules; updating pnpm-lock.yaml will not fix it` |

The examples above use a pnpm dependency-file mapping.
For npm, the filename is `package-lock.json`.

Packages showing this line cannot be fixed by updating dependency files; update the owner (npm or pnpm) to a newer version to fix them.

- If the owner is installed in the Dockerfile, change its version there
- If the owner is included in the base image, update the base image

The line does not show which owner version fixes the package.

A change to the card's `Action:` line alone does not resend the full report in the thread.
See [Slack thread delivery conditions](notification-conditions.md#slack-thread-delivery) for when another report is posted.

See [Lines shown on Slack cards](remediation-image-logic.md#newer-series-slack-cards) for detailed image display conditions and [Versions checked](remediation-image-logic.md#newer-series-versions) for candidate selection.
See [Card action line](remediation-package-logic.md#card-action-line) for how language package lines are determined.

See [Displayed fields](remediation-results.md#slack-fields) for reading remediation plan messages.

### Upgrade risk {#upgrade-risk}

Upgrade risk describes the type of version change from the installed version to the fixed version.
Detailed cards display it as follows.

```text
Upgrade risk: 🟢 distro security patch
```

The following table explains each display.

| Display | Meaning |
| --- | --- |
| `🟢 distro security patch` | Fixed version of an OS package; “distro” means the OS distribution |
| `🟢 low-risk` | Language-package change without a major version increase |
| `🟠 major version bump — needs care` | Language-package change that increases the major version |
| `⚪ risk unknown` | Change whose versions cannot be compared |

Green indicators do not guarantee update safety or compatibility.

### Ecosystem labels {#ecosystem-labels}

Ecosystem labels identify the type of language package in square brackets after its name.
Here is an example for a Python package.

```text
◆ setuptools [python-pkg]
```

The following table lists the bracketed labels and what they identify.

| Display | Applies to |
| --- | --- |
| `[python-pkg]` | Python package |
| `[node-pkg]` | Node.js package |
| `[gobinary]` | Package included in a Go binary |
| `[jar]` | Package included in a Java JAR file |
| `[node-runtime]` | Findings for the Node.js runtime itself |
| `[python-runtime]` | Findings for the Python runtime itself |
| `[lang]` | Language package whose type cannot be identified |
| No bracketed label | OS package |

Language packages identified by Trivy can also display types not listed in this table.
Node.js and Python runtime findings come from each runtime's vulnerability information.

Labels for the Node.js and Python runtimes identify the package type and do not mean that use was observed in a running container.
See [Usage labels](slack-runtime-display.md#usage-labels) for observed usage.

## Change labels {#change-labels}

Diff notifications show image, package, and EOL changes separately.
See [Change and history decisions](diff-logic.md#comparison-baseline) for the rules that establish a change.

### Image changes {#image-change-labels}

Image changes have two displays: content changes under the same image name, and updates to the image name.
A digest identifies an image's content.

When the digest changes under the same image name, the following heading is followed by the image name and the shortened digests before and after the change.

```text
🔄 Image content changed (1)
```

The line below the heading uses the following format.
The placeholders show where the image name and shortened digests appear.

```text
• image name: image updated (previous shortened digest → current shortened digest)
```

The heading counts image names whose content changed.
If either side has multiple digests, they are separated by commas.

When an image name is updated and its detection history is carried over, the display looks like this.
In the first line, `sha-aaaa` and `sha-bbbb` are tags; in the second, `0123456789ab` is a shortened digest.

```text
🔄 Image reference updated: ghcr.io/acme/web sha-aaaa → sha-bbbb (history carried over)
🔄 Image reference updated: registry.example:5000/team/api 0123456789ab → 1.4 (history carried over)
```

The values on either side of the arrow depend on how the previous and updated image names are specified, as shown below.

| Image name specification | Value shown on either side of the arrow |
| --- | --- |
| Has a tag | Tag |
| Pinned by digest, with no tag | Shortened digest |
| Has neither a tag nor a digest | `latest` |

See [Image name updates](diff-logic.md#reference-changes) for the conditions for carrying over history.

### Package changes {#package-change-labels}

Package changes appear in section headings and on the `Change:` line within a card.
The latest scan results are compared with saved history for the same pair of image name and package.

The following example is a diff card for a package whose fix became available.

```text
◆ dpkg
Change: fix now available
Installed: 1.21.22 · Fixed in: 1.21.23 (🟢 distro security patch)
Findings: CRITICAL 0 / HIGH 1
CVEs: CVE-2031-0004 (EPSS <0.1%)
```

Section headings group the following content.
The new-findings section includes changes to previously detected packages as well as packages detected for the first time.

| Heading display | Included content |
| --- | --- |
| `🆕 New since last scan (N)` | First detections, priority increases, added CVEs, newly available fixes, and resumed notifications |
| `✅ Resolved since last scan (N)` | Resolved package findings and EOL clearances for packages and base operating systems |

The N in each heading is counted as follows.

- New findings count each displayed pair of image name and package once
- Resolutions count each resolved or EOL-cleared pair of image name and package once, plus the number of image names whose base OS EOL cleared

In the new-findings section, a pair can have separate cards for findings with and without a fix, so the heading count may differ from the number of cards.

The `Change:` line within a card describes the following changes.

| Display | When it appears |
| --- | --- |
| `Change: ⬆️ escalated to ACT NOW` | A pair previously classified as Watch or Low is now Act now |
| `Change: ⬆️ escalated to WATCH` | A pair previously classified as Low is now Watch |
| `Change: new CVEs: CVE-2031-0007` | A CVE absent from saved history is detected for that pair |
| `Change: fix now available` | A pair previously without a fix now has findings with an available fix |

Cards for pairs detected for the first time, with no saved history, have no `Change:` line.
When added CVEs produce multiple cards, this line is also omitted from cards that contain none of the added CVEs.

See [Ordinary package changes](diff-logic.md#normal-changes) for the decision order when multiple changes apply.
See [Muted findings](slack-runtime-display.md#muted-display) for labels when notifications resume after muting.

### EOL display {#eol-display}

End-of-life (EOL) displays cover both images with an EOL base OS and EOL packages.
Package EOL indicates findings for CVEs considered outside the support scope of the installed release (see [Package EOL](scan-logic.md#eol-package)).

The following example shows an image with an EOL base OS in a full report.

```text
⛔ Base OS end-of-life (top priority)
Image: legacy:1
Status: base OS is EOL (no more security updates coming)
includes 2 end-of-life package(s)
```

Full reports and threads display images with an EOL base OS as follows.

- EOL packages in the image are summarized as a count on the base-OS line instead of individual cards
- With triage enabled, only the Act now packages among them also have detailed cards in the Act now section

Full reports use the following phrases for EOL package counts and directions to details.

| Display | Meaning |
| --- | --- |
| `includes N end-of-life package(s)` | Number of EOL packages summarized on this image's base-OS line |
| `Details: 🚨 see Act now` | This package's details appear in the Act now section |

Diff notifications use the following phrases for newly detected EOL findings, added CVEs, and EOL clearances.

| Display | Meaning |
| --- | --- |
| `includes N newly end-of-life package(s)` | Number of newly detected EOL packages summarized on a newly detected EOL base-OS line |
| `N package(s) newly end-of-life` | Newly detected EOL packages summarized as a count under an EOL base OS |
| `N end-of-life package(s) with new CVEs` | EOL packages with added CVEs summarized as a count under an EOL base OS |
| `base OS no longer EOL` | That image name no longer has a base-OS EOL record |
| `no longer end-of-life` | That package no longer has EOL findings, but ordinary findings remain |

The N in `⛔ New: package end-of-life (N) — vendor reports these CVEs as out of support for this release` counts changed pairs of image name and package.
It includes escalations to Act now and added CVEs as well as newly detected EOL findings.

The following rules determine what this heading counts.

- EOL package changes displayed as individual cards are counted
- For images whose base OS was already EOL, newly detected EOL findings and added CVEs summarized as counts are also counted
- For images whose base OS is newly detected as EOL, added CVEs in previously detected EOL packages are also counted
- When both the base OS and a package are newly detected as EOL, packages other than Act now are summarized on the base-OS line and excluded from this heading's count

A card's fix guidance differs by package type and location as follows.
“Ordinary EOL package” in the table means an EOL package other than the Node.js or Python runtime itself.

| Card type and location | Fix display |
| --- | --- |
| Compact ordinary EOL package card (channel; thread pointer to Act now) | `Fixed in: none — end-of-life: no fix planned for this release` |
| Detailed ordinary EOL package card (Act now in the channel; thread) | `Fixed in: none — end-of-life: no fix planned for this release, consider a supported version` |
| Node.js or Python runtime card (channel; thread) | `Fixed in: none — end-of-life: no fix will be released for this series, so the series has to be upgraded (manual)` |

Vulnerabilities may remain as ordinary findings after EOL clears.
See [Finding classification](scan-logic.md#finding-classification) for EOL meanings and [Resolution decisions](diff-logic.md#resolved-findings) for clearance rules.
