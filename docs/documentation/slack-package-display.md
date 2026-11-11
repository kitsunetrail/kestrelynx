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
Top CVE: CVE-2031-0001 · CRITICAL · EPSS 94%
Exploitation: CISA KEV (exploited in the wild) · 🧨 ransomware campaign
References: advisory · vendor advisory
```

Watch findings in the channel use compact cards like this.

```text
◆ e2fsprogs
Installed: 1.47.0-2 · Fixed in: none
Findings: CRITICAL 1 / HIGH 0
Top CVE: CVE-2031-0003 · EPSS 3%
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
| Action | [Resolution through image updates and waiting for newer versions](#base-image-wait) | [Resolution through image updates and waiting for newer versions](#base-image-wait) |
| CVEs | Top CVE, exploitation information, and references | Short top CVE display |
| Runtime usage | Display including observation evidence | Short in-use display |

`Findings:` counts distinct CVE IDs included in that card.
See [Priority line counts](slack-display.md#priority-counts) for how findings are separated into cards and [CVE details](#cve-details) for when the top CVE appears.

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

`Top CVE:` identifies one CVE from the card, selected using priority and EPSS.
The following detailed-card example has one additional CVE besides the top CVE.

```text
Top CVE: CVE-2031-0006 · HIGH · EPSS 20% (+1 more CVE(s) in this package)
```

The top CVE is selected using the following comparison order.
Each criterion is used only when the preceding criteria do not distinguish the CVEs.

1. Priority in the order Act now → Watch → Low
2. CVEs with an EPSS score before CVEs without one
3. Higher EPSS scores first
4. CVE IDs in ascending string order

The following rules apply to top CVE displays on compact cards.

- Compact Watch and EOL cards in full reports show the top CVE when triage is enabled and KEV or EPSS is available
- Compact cards in full reports omit the top CVE when triage is disabled or both KEV and EPSS are unavailable
- Compact diff cards omit the top CVE when newly added CVE IDs are displayed, and show it otherwise

Other CVEs are displayed as follows, depending on location.

| Location | Other CVEs |
| --- | --- |
| Detailed channel card | Adds `(+N more CVE(s) in this package)` to `Top CVE:` |
| Detailed thread card | Lists IDs under `Other CVEs:` and shows omitted IDs as `(+N more)` |
| Channel diff card | Shows newly added CVE IDs under `Change:` |

Other-CVE counts cover the CVEs included in that card.
`EPSS n/a` on a detailed card means no score is available; very small values appear as `<0.1%`, and very large values as `>99%`.

`Exploitation:` shows available exploitation information for the top CVE.
The following example has information about exploitation in actual attacks and ransomware campaigns.

```text
Exploitation: CISA KEV (exploited in the wild) · 🧨 ransomware campaign
```

The exploitation labels have the following meanings.

| Display | Meaning |
| --- | --- |
| `CISA KEV (exploited in the wild)` | The top CVE is listed in CISA KEV as exploited in actual attacks |
| `🧨 ransomware campaign` | Information indicates use of the top CVE in ransomware attacks |

See [Exploitation-based priority](scan-logic.md#triage) for priority decisions.

`Summary:` in the thread shows the description of the top CVE.
Descriptions come from the following sources.

| Finding | Description source |
| --- | --- |
| Trivy finding | Trivy's description |
| Node.js or Python runtime finding | The runtime's vulnerability information |

See [Vulnerability fields](webhook-reference.md#vulnerability-fields) for complete CVE data without omissions.

### Resolution through image updates and waiting for newer versions {#base-image-wait}

The card's `Action:` line reports whether updating the image or its base image to a newer version removes that package's vulnerabilities.
It appears after `Findings:` in detailed and compact channel cards, thread cards, and diff cards.

A series groups versions by their first two numbers, so 3.11 and 3.13 are different series.

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
| No matching newer version | `Action: waiting for a newer base image of python 3.11.9 (no newer tag in the same series or in a newer series of the same form)` |
| No newer version in the same series | `Action: waiting for a newer base image of python 3.11.9 (no newer tag in the same series)` |

The `Action:` line may be omitted for cards containing findings whose resolution cannot be determined, among other cases.
However, when the base image is known to have no newer version in the same series, the line may show only that information.

A change to the card's `Action:` line alone does not resend the full report in the thread.
See [Slack thread delivery conditions](notification-conditions.md#slack-thread-delivery) for when another report is posted.

See [Lines shown on Slack cards](remediation-logic.md#newer-series-slack-cards) for detailed display conditions and [Versions checked](remediation-logic.md#newer-series-versions) for candidate selection.
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

### Reference links {#reference-links}

`References:` shows links related to the top CVE.
The following example provides links to a vulnerability advisory and vendor information.

```text
References: advisory · vendor advisory
```

The following table lists the link displays and destinations.

| Display | Destination |
| --- | --- |
| `advisory` | Primary advisory from Trivy or the runtime's vulnerability information |
| `vendor advisory` | Vendor or CISA information from KEV notes |
| `💬 HN (N pts)` | Related Hacker News discussion (N is its points) |

CVE IDs on the `Top CVE:`, `Other CVEs:`, and `Change:` lines link to NVD.
Non-CVE identifiers such as GHSA and DLA IDs appear as plain text.

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
Top CVE: CVE-2031-0004 · EPSS <0.1%
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
