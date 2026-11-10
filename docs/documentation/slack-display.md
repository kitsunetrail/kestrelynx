# Reading Slack notifications

## Where to find reports {#slack-display}

Slack channel notifications show changes and unresolved state, while Bot threads provide details.
See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for the remediation plan display.

### Channel reports {#channel-display}

The following table shows the headings and content of channel reports.

| Report | Heading | Content |
| --- | --- | --- |
| `diff` mode (with changes) | `Changes since the last scan.` | Changes since the previous scan and the current unresolved state |
| `diff` mode (without changes) | `No changes since last scan.` | Confirmation that nothing has changed and the current unresolved state |
| `full` mode | `Everything currently open.` | Unresolved findings confirmed by the latest scan |
| Weekly report | `📋 Weekly full report — everything currently open` | A full report of unresolved findings confirmed by the latest scan, added to the diff notification |

A full report is the notification in `full` mode headed `Everything currently open.` or the part added to a weekly diff notification headed `📋 Weekly full report — everything currently open`.

The following display rules apply to all reports.

- Empty sections are omitted
- With triage enabled, Low remains count-only even in a full report

The following notices appear only when a generic webhook is configured.

| Display | Location | Condition |
| --- | --- | --- |
| `Details in the generic webhook payload.` | Below the current unresolved line in diff mode (excluding weekly reports) | The report from the latest scan contains findings |
| `Details in the generic webhook payload.` | Below the Low count line in full mode and weekly reports | Triage is enabled and Low findings are present |
| `N lower-risk fix(es) summarized — full list in the generic webhook payload.` | Full mode and weekly reports | Triage is disabled and lower-risk fixes are summarized |

Complete details of all Low findings are available in the [generic webhook](webhook-reference.md#generic-webhook).

See [Scan notification conditions](notification-conditions.md#notification-conditions) for when notifications are sent.

### Thread reports {#thread-display}

Bot threads show details as of that report under the heading `📊 Everything open now — YYYY-MM-DD HH:MM`.

The following notices appear in the footer of the first channel message.

| Footer of the first channel message | Destination |
| --- | --- |
| `📊 Everything open now is in this message's thread ↓` | The thread containing the report from the latest scan |
| `🔗 Everything open as of the last report → thread` | The previously posted report thread |

The footer is omitted when no valid link exists or the link cannot be displayed.

The following rules apply to posting and reading thread reports.

- The thread attaches to the first channel message, even when the channel report spans multiple messages
- The previous report link points to the content as it was when that report was created
- See the channel's [current unresolved counts](#open-now) for the unresolved state after the latest scan

Long notifications are split into multiple messages, with the following continuation markers.

| Split message | Added display |
| --- | --- |
| Thread continuation | `(cont.)` on the heading |
| Channel continuation | A marker such as `(cont. 2/3)` |

See [Slack thread delivery conditions](notification-conditions.md#slack-thread-delivery) for when all unresolved findings are posted as a reply.

## Notification language {#notification-language}

Slack's standard text uses the configured notification language.
See [Configuration](configuration.md) for language settings and their scope.

When notifications are set to Japanese, severities (such as `CRITICAL` and `HIGH`), vulnerability descriptions, and discussion link labels remain in their original English.

## Section order {#section-order}

Depending on the report type, changes appear first or current unresolved findings appear by section.

### Diff report order {#diff-order}

The following example shows a diff report with changes.

```text
🛡️ KestreLynx — scan results for 2026-06-24 09:00
3 images scanned, 2 affected
Changes since the last scan.

🆕 New since last scan (4)
Image: api:2.0
◆ libxml2
…

✅ Resolved since last scan (1)
• web:1.0: old-pkg

⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)
• The cause could not be determined (see the log)
…

📌 Open now: 🚨 3 act-now / 👀 1 watch / 🔕 3 low
⏰ oldest act-now/watch unresolved 20 day(s)
📊 Everything open now is in this message's thread ↓
```

Cycles with changes and weekly reports use the following order.
Sections without applicable content are omitted.

| Order | Content | Heading display |
| --- | --- | --- |
| Beginning | Header, image counts, and Sensor warnings | `🛡️ KestreLynx — scan results for YYYY-MM-DD HH:MM`, etc. |
| Before changes | Warnings about unavailable threat intelligence sources | `⚠️ EPSS data unavailable — triage is using KEV and severity only`, etc. |
| Image changes | Digest changes and image name updates | `🔄 Image content changed (N)`, etc. |
| EOL changes | New EOL base operating systems and EOL package changes | `⛔ New: base OS end-of-life (top priority)`, etc. |
| Package changes | Ordinary new or changed findings, resolutions, and EOL clearances | `🆕 New since last scan (N)`, `✅ Resolved since last scan (N)` |
| End | Weekly full report, or scan failures and current unresolved state | `📋 Weekly full report — everything currently open`, `⚠️ N image(s) could not be scanned (vulnerabilities not checked)`, etc. |

Unchanged notifications outside the weekly report day show `No changes since last scan.` followed by scan failures and the current unresolved state.
Holding annotations follow the unresolved state or full report.

With triage enabled, ordinary new or changed findings are ordered by priority, image name, and package name.

### Full report order {#current-order}

The following example shows a full report with triage enabled.

```text
Everything currently open.
Priority: ⛔ 1 EOL base · 🚨 3 act now · 👀 1 watch · 🔕 4 low

⛔ Base OS end-of-life (top priority)
Image: web:1.0
Status: base OS is EOL (no more security updates coming)

🚨 Act now (3) — exploited or likely to be
◆ openssl
…

👀 Watch (1) — not urgent, keep an eye on
◆ e2fsprogs
…

🔕 Low priority (4) — 4 finding(s) across 2 image(s), no exploitation signal (not in KEV, EPSS below threshold).

⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)
…
📊 Everything open now is in this message's thread ↓
```

With triage enabled, channel reports display unresolved findings with the following headings and in the following order.
Bot threads use the same section order.

| Order | Heading display |
| --- | --- |
| First | `⛔ Base OS end-of-life (top priority)` |
| Next | `⛔ Package end-of-life (N) — …` |
| By priority | `🚨 Act now (N) — …` → `👀 Watch (N) — …` → `🔕 Low priority (N) — …` |

Warnings that threat intelligence sources such as CISA KEV or EPSS are unavailable appear immediately after the `Priority:` line, before the EOL sections, in `full` mode.
In weekly reports, these warnings appear once, immediately after the opening header (the header line, image counts, and Sensor warnings), and do not appear after `Priority:` in the later `📋 Weekly full report — everything currently open` portion.

In full channel reports with triage enabled, only applicable lines appear after the EOL, Act now, and Watch sections, in the following order.

| Order | Display |
| --- | --- |
| 1 | `🔕 Low priority (N) — …` |
| 2 | `🔇 Muted — no fix available and not in use for 7+ days: N` |
| 3 | `⚠️ N image(s) could not be scanned (vulnerabilities not checked)` |
| 4 | `Intel data is N day(s) old (feeds unreachable).` |
| 5 | `🔎 Runtime: ▶ N in use · …` |

When fetching KEV or EPSS data fails, KestreLynx uses previously fetched data up to seven days old to determine priority.
With triage enabled, the note `Intel data is N day(s) old (feeds unreachable).` appears if the data used is at least one day old.
`N` is the number of days since the oldest dataset used was fetched.
If neither dataset can be used, the unavailable threat intelligence warning appears in the position described above instead of this note.

### Order with triage disabled {#triage-disabled-display}

The following example shows a full report with triage disabled.

```text
Everything currently open.
Priority: 🔴 3 CRITICAL · 🟠 1 need care · 🟢 1 safe

✅ Actionable now (fixed)
◆ openssl
…

ℹ️ No fix yet (affected / waiting on upstream)
◆ e2fsprogs
…

🔕 No fix planned for this OS release (will_not_fix)
◆ gcc-12-base
…

⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)
…
1 lower-risk fix(es) summarized.
📊 Everything open now is in this message's thread ↓
```

With triage disabled, findings appear by fix status after the EOL sections.

| Order | Displayed section |
| --- | --- |
| Fix available | `✅ Actionable now (fixed)` |
| No fix available | `ℹ️ No fix yet (affected / waiting on upstream)` |
| No fix planned | `🔕 No fix planned for this OS release (will_not_fix)` |

`Actionable now` means a fix is available and differs from the triage priority `Act now`.
See [Fix status](scan-logic.md#status) for status meanings.

In the channel, fixed findings that need attention appear individually, and the remaining findings are summarized by image.

### Order within a section {#within-section-order}

Full reports and threads order images within each section and packages within each image in the following base order, whether triage is enabled or disabled.
Images are compared in pairs, as are packages, using the next criterion only when the preceding criteria do not distinguish the pair.

Images are compared in the following order.

1. More CRITICAL findings first
2. Images containing HIGH findings first
3. Higher CVE count across all severities (Total) first
4. Image name order

Packages within each image are compared in the following order.

1. Packages containing CRITICAL findings → packages containing HIGH findings → all others
2. Higher CVE count across all severities (Total) first
3. Package name order

The following example shows four images in one section before reordering based on Sensor information.

| Order | Image | CRITICAL | HIGH | MEDIUM or lower | Total | Reason for appearing earlier |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `api:2.0` | 2 | 0 | 0 | 2 | Most CRITICAL findings |
| 2 | `web:1.0` | 1 | 1 | 0 | 2 | Only remaining image with HIGH |
| 3 | `worker:1.0` | 1 | 0 | 4 | 5 | Higher total than batch |
| 4 | `batch:1.0` | 1 | 0 | 2 | 3 | — |

When triage is enabled and Sensor information is available, the following criteria take precedence within the same priority section, with ties retaining the base order.

Images are compared in the following order.

1. Images containing packages in use first
2. Base order

Packages within each image are compared in the following order.

1. Packages in use first
2. Among packages in use, broader port exposure first
    - published on all interfaces
    - published on loopback only
    - listening (not published)
3. Packages in containers running with elevated privileges first
4. Base order

Packages that are not in use retain the base order relative to each other.

`▶ in use` indicates that Sensor observed execution, loading, or other evidence of package use in a running container (see [Usage labels](#usage-labels)).
Port exposure and privileges belong to the container using the package; see [Runtime evidence](#runtime-evidence) for their display.
This reordering never moves items between priority sections and does not apply when triage is disabled.

## Reading counts {#counts}

Images, packages, and CVEs use different counting units.
Counts within the same notification may therefore differ.

Counts are grouped by severity, with unrecognized severities counted as `UNKNOWN`.
Counts for `MEDIUM`, `LOW`, and `UNKNOWN` appear only when `scan.severity` selects the corresponding levels.
The default `[HIGH, CRITICAL]` excludes these severities from detection, so their counts are not displayed.
Package card finding counts, image headings, collapsed summary lines, and the current unresolved line with triage disabled append nonzero counts after `HIGH` in the order `MEDIUM`, `LOW`, `UNKNOWN` (for example, `CRITICAL 1 / HIGH 2 / MEDIUM 3`).

### Image counts {#image-counts}

The header's `N images scanned, M affected` uses the following counting units.

| Japanese display | English | Counting unit |
| --- | --- | --- |
| スキャンした件数 | images scanned | Distinct combinations of image name, digest, and platform where applicable, including failures |
| 影響ありの件数 | affected | Image names with a selected vulnerability or an EOL base OS |

When a registry digest identifies an image, the same image name and digest count separately if the OS or architecture differs.
Separate image names count separately in the scanned count, even when they share the same scan result.
Image names with only scan failures are excluded from the affected count.

### Current unresolved counts {#open-now}

`📌 Open now:` shows the unresolved counts remaining after the latest scan.
With triage enabled, the line looks like this.

```text
📌 Open now: ⛔ 2 EOL base / ⛔ 4 EOL package / 🚨 2 act-now / 👀 1 watch / 🔕 1 low
```

EOL base counts each image name once; the other items count each pair of image name and package once.
Items with a count of zero are omitted.

Each item counts the following.

| Display | What is counted |
| --- | --- |
| `⛔ N EOL base` | Images whose base OS is recorded as EOL |
| `⛔ N EOL package` | Pairs with EOL findings |
| `🚨 N act-now` | Act now pairs |
| `👀 N watch` · `🔕 N low` | Watch and Low pairs |

The following counting rules apply.

- If an image's base OS is EOL, apply the following counting rules
    - Count that image once in `⛔ N EOL base`
    - Do not count EOL packages found in that image in `⛔ N EOL package`
- Priority counts include each pair of image name and package only once
- A pair is counted as Act now if either its ordinary findings or its EOL findings have Act now priority
- Other pairs are counted as Watch or Low according to the priority of their ordinary findings
- If a pair has only EOL findings and its priority is Watch or Low, exclude that pair from priority counts
- A pair counted as EOL package is also counted as Act now if it has Act now priority
- [Muted](#muted-display) pairs are excluded from priority counts

EOL and priority counts come from saved history, so they also include previous records for images whose scans failed and other images with retained records (see [Retained findings](diff-logic.md#retained-findings)).
See [Package EOL](scan-logic.md#eol-package) for the distinction between ordinary findings and EOL findings.

With triage disabled, the line looks like this.

```text
📌 Open now: ⛔ 1 EOL base / CRITICAL 3 / HIGH 6 across 2 image(s)
```

With triage disabled, counts follow these rules.

- EOL items use the same counting rules as with triage enabled
- Severity counts sum the CVE counts for each package in the report from the latest scan separately for each severity
- The same CVE is counted separately if it appears in different packages
- The image count is the number of images with findings
- When included in `scan.severity`, nonzero counts for `MEDIUM`, `LOW`, and `UNKNOWN` follow `HIGH` in that order

When the report from the latest scan contains no findings, the following states appear instead of counts.

| State | Display |
| --- | --- |
| Package history retained because Kubernetes digests are unconfirmed | `📌 Open now: unconfirmed — holding previous findings until re-confirmed` |
| Previous history retained for another reason | `📌 Open now: not re-scanned — holding previous findings until the next successful scan` |
| No retained history either | `🎉 Open now: none — all clear` |

### Priority line counts {#priority-counts}

`Priority:` in a full report shows counts for EOL findings and response priorities in the report from the latest scan.
With triage enabled, the line looks like this.

```text
Priority: ⛔ 1 EOL base · 🚨 3 act now · 👀 1 watch · 🔕 4 low
```

The `Priority:` line counts packages in units corresponding to one package card.
The same unit applies when cards are not displayed individually, including Low findings.

CVEs found in the same package in the same image are combined into one card per fix status.
The following examples use openssl in api:2.0 to show the number of cards and the resulting count.

| Findings | Number of cards | Count |
| --- | --- | --- |
| Three CVEs with an available fix | 1 card | 1 |
| Two CVEs with an available fix and one CVE without a fix | 2 cards because the fix statuses differ | 2 |

Even with the same package name, different ecosystems or installed versions produce separate cards.
See [Reading package cards](#package-card) for details.

Different digests under the same image name count separately.
EOL base counts each image name once instead.

With triage enabled, each item counts the following.
Items with a count of zero are omitted.

| Display | What is counted |
| --- | --- |
| `⛔ N EOL base` | Images whose base OS is identified as EOL |
| `⛔ N EOL package` | Cards with EOL findings |
| `🚨 N act now` | Act now cards, including EOL findings with Act now priority |
| `👀 N watch` · `🔕 N low` | Cards for ordinary findings (Watch or Low) |

The following rules apply to EOL and muted findings.

- If an image's base OS is EOL, exclude that image's EOL packages from the EOL package count
- Act now EOL packages also count as Act now, regardless of whether the base OS is EOL
- [Muted](#muted-display) cards are excluded from priority counts

With triage disabled, the line looks like this.

```text
Priority: 🔴 3 CRITICAL · 🟠 1 need care · 🟢 1 safe
```

EOL counts include the same items as with triage enabled; the other counts use the following rules.

| Display | What is counted |
| --- | --- |
| `🔴 N CRITICAL` | CRITICAL CVE counts excluding muted findings |
| `🟠 N need care` | Cards whose fixed version increases the major version |
| `🟢 N safe` | Cards with an available fix, no CRITICAL findings, and no major version increase |

The following rules apply to CRITICAL and safe counts.

- CRITICAL sums counts from the sections for available fixes, unavailable fixes, no planned fixes, and EOL packages
- Safe includes cards whose upgrade risk is unknown

The safe classification does not guarantee update safety or compatibility.
See also [Upgrade risk](#upgrade-risk) for the display meanings.

The following table compares Act now, Watch, and Low counts with the [current unresolved line](#open-now) when triage is enabled.

| Line | Source | Counting unit |
| --- | --- | --- |
| Priority line | Report from the latest scan | Card separated by fix status |
| Current unresolved line | Saved history | Pair of image name and package |

### Unresolved age {#unresolved-age}

Unresolved age shows the oldest age across included records in the channel and the age for that pair of image name and package on a thread card.

The following table shows how the display varies by location and age.
N represents the number of elapsed days.

| Location and condition | Display | Meaning |
| --- | --- | --- |
| Channel, triage enabled, 1–13 days | `oldest act-now/watch unresolved N day(s)` | Oldest age across included records, including EOL |
| Channel, triage disabled, 1–13 days | `oldest unresolved N day(s)` | Oldest age across all priorities |
| Channel, triage enabled, 14 days or more | `⏰ oldest act-now/watch unresolved N day(s)` | Highlights findings that have remained unresolved for a long time |
| Channel, triage disabled, 14 days or more | `⏰ oldest unresolved N day(s)` | Highlights findings that have remained unresolved for a long time |
| Thread card, at least one day | `⏱ open N day(s) · first seen 2026-06-04` | Elapsed days and first-seen date for that pair |
| Thread card, zero days | `⏱ first seen today` | Less than one day since first detection |

The channel's oldest age is measured from the earliest first-seen timestamp among the included records.
It appears after one day, with `⏰` added at 14 days or more.

The records included in the oldest age depend on the triage setting.

| Triage | Included in the oldest age |
| --- | --- |
| Enabled | Ordinary Act now and Watch findings, plus EOL base operating systems and packages |
| Disabled | All ordinary findings, plus EOL base operating systems and packages |

The following rules apply to EOL and historical records.

- If an image's base OS is EOL, measure EOL package ages from the base OS's first-seen-as-EOL date
- If an EOL package has Act now priority, also include the package's own first-seen-as-EOL date, regardless of whether the base OS is EOL
- If an image's base OS is not EOL, use each EOL package's own first-seen-as-EOL date
- [Retained history](diff-logic.md#retained-findings), including records retained after scan failures, is included
- With triage enabled, ordinary findings determined to be [muted](#muted-display) during the latest scan are excluded

Thread cards use the first detection date for ordinary findings and the first EOL detection date for EOL findings.
Cards without a recorded first-seen date omit the age.

The generic webhook includes Low and muted findings, so its included records differ from Slack with triage enabled (see [Oldest unresolved age](webhook-reference.md#oldest-open-days)).

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
- [Muted](#muted-display) packages have no individual cards

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
See [Priority line counts](#priority-counts) for how findings are separated into cards and [CVE details](#cve-details) for when the top CVE appears.

Channel cards show observed use, while detailed thread cards also show when use was not observed or could not be determined.
See [Usage labels](#usage-labels) for details.

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
See [Usage labels](#usage-labels) for observed usage.

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
See [Muted findings](#muted-display) for labels when notifications resume after muting.

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

## Runtime usage display {#runtime-display}

When Sensor information is available, packages show runtime usage.
Sensor observes whether packages are being used in running containers.

See [Runtime usage](runtime-usage.md) for usage decisions and observation limits.

### Usage labels {#usage-labels}

Usage labels indicate the following states for the package shown on a card.

| Display | Meaning |
| --- | --- |
| `▶ in use` | Package with confirmed use |
| `▷ not observed` | Package with no use confirmed during the observation window |
| `▷ runtime evidence unavailable` | Package without the information needed to determine usage |

Not observed does not mean unused.
When usage cannot be determined, the reason appears in parentheses.

The following examples show usage lines taken from separate package cards.

```text
Runtime: ▶ in use (running)
Runtime: ▷ not observed
Runtime: ▷ runtime evidence unavailable (sensor not reporting)
```

Usage displays differ by notification location and card type.

| Location | Content |
| --- | --- |
| Detailed channel card | Usage and evidence appear when the package is in use |
| Compact channel card | A short activity description appears in parentheses when the package is in use |
| Detailed thread card | Shows in use, not observed, or unavailable |
| Low priority in full reports and threads | Shows the in-use count alongside the section count, without individual cards |
| Low priority in channel changes | New findings and added CVEs appear as compact cards |

In full channel reports, the number of Low packages in use appears at the end of the heading.
In this example, one of the two Low entries is in use.

```text
🔕 Low priority (2) — 2 finding(s) across 2 image(s), no exploitation signal (not in KEV, EPSS below threshold). · ▶ 1 in use
```

In the thread, the same count appears on a separate line.
Both locations omit the in-use count when it is zero.

```text
🔕 LOW (2) — no exploitation signal
▶ in use among low: 1
```

The following reasons concern receiving Sensor information and preparing or continuing observations.

| Reason text | Meaning |
| --- | --- |
| `sensor not reporting` | The file containing Sensor observations is not available yet |
| `sensor report is stale` | Too much time has passed since the Sensor report or container verification to conclude that use was not observed |
| `evidence invalid` | Reading and validating the Sensor observations failed |
| `sensor isolation failed` | Sensor could not restrict operations other than reading, so observation did not start |
| `permission denied` | Sensor is being denied access to container process information or files |
| `index not built yet` | Preparation for matching files to packages is not complete |
| `worker stalled` | The operation examining the container did not finish within its time limit |
| `evidence truncated` | A limit such as the amount of data read was reached, leaving some information unavailable |
| `evidence incomplete` | Some observations cannot be used, so use in that missing portion cannot be checked |

The following reasons concern matching observations to a container.

| Reason text | Meaning |
| --- | --- |
| `container generation unverified` | The observations cannot be confirmed to match the container's current start and the scanned image |
| `container not observed` | No usable observations are available for the target container |

The following reasons concern package management information and matching files to packages.

| Reason text | Meaning |
| --- | --- |
| `package database parse failed` | The container's package management information could not be parsed |
| `package database absent` | No usable package management information has been found in the container |
| `package database error` | Reading or parsing the package management information failed |
| `package database unsupported` | The container's package management information uses a format Sensor does not support |
| `no file list for this package` | The package management information cannot provide a list of files belonging to this package |
| `multiple owners` | The observed file belongs to multiple packages, so its use cannot be attributed to one package |
| `file replaced` | The observed file was deleted or replaced, preventing a reliable match to its package |
| `version mismatch` | The package version Sensor observed in use differs from the version detected by the scan |

The following reasons concern language-package matching or an unidentified reason.

| Reason text | Meaning |
| --- | --- |
| `ecosystem not mapped` | No runtime is mapped to this language-package type for determining usage |
| `binary path unknown` | The scan result does not identify the executable path needed to determine package usage |
| `unknown` | The reason usage cannot be determined is unidentified |

### Runtime evidence {#runtime-evidence}

Detailed cards for packages in use show the observed activity and information about that observation.
In this example, nginx running is the evidence for the in-use verdict.

```text
Runtime: ▶ in use
Evidence: running as /usr/sbin/nginx
Exposure: published on all interfaces · runs with elevated privilege · last confirmed 06-24 09:00
```

Each line in the example means the following.

| Line | Meaning |
| --- | --- |
| `Runtime:` | The verdict that the package on the card is in use |
| `Evidence:` | The activity and program that established use |
| `Exposure:` | Port exposure, execution privileges, and the observation's last confirmation time |

These facts come from observations of one container using the package.
When multiple containers use it, the display prefers broader exposure, then higher privileges when exposure is equal.

Evidence distinguishes running states found by periodic checks from activity captured as execution or loading events.
The phrases before program paths have the following meanings.

| Display | Meaning |
| --- | --- |
| `running as` | A periodic check found the package's file running |
| `loaded by` | A periodic check found a running program with the package's library loaded |
| `executed` | An event captured execution of the package's file |
| `library loaded` | An event captured loading of the package's library |
| `in running binary` | A periodic check found an executable containing the language package running |
| `binary executed` | An event captured execution of a binary containing the language package |
| `runtime is running` | A periodic check found the runtime associated with the language package running |
| `runtime executed` | An event captured execution of the runtime associated with the language package |

Runtime-based evidence means that all language packages associated with that runtime are treated as in use.
It does not confirm that each individual package was loaded (see [Usage decisions](runtime-usage.md)).

`running as` also describes the state when observed, so the program may no longer be running when you read the notification.
Check `last confirmed` for the observation time.

When different activities were observed across multiple programs and cannot be matched to individual programs, they appear as separate lists.

```text
Evidence: running; loaded as a library; processes: /usr/bin/helper, /app/server
```

This example indicates that execution and library loading were observed.
`processes:` lists the observed programs; its entries do not correspond in order to the preceding activities.

Available exposure, privilege, and last-confirmed information appears together on one `Exposure:` line.
The individual phrases mean the following.

| Display | Meaning |
| --- | --- |
| `published on all interfaces` | The observed program's port is published on all host interfaces |
| `published on loopback only` | The observed program's port is published only on addresses reached from the host itself |
| `listening (not published)` | The observed program is listening without publishing its port to the host |
| `runs with elevated privilege` | The observed program has at least one of the elevated privileges listed below |
| `last confirmed` | The time the displayed observation was last confirmed |

`runs with elevated privilege` appears when any of the following applies.

- Runs in a privileged container
- Holds a powerful permission such as system administration or bypassing file access restrictions
- Runs as root without user-identity isolation from the host

When exposure is unknown but elevated privilege is known, a `Privilege:` line shows privilege and the last confirmation time.
When neither can be displayed, a `Last seen:` line shows only the time.

### Muted findings {#muted-display}

Muting suppresses individual notifications for packages with no available fix and no observed use for at least seven days.
It applies when the feature is enabled and excludes Act now and EOL packages.

Muted packages are omitted from individual channel, thread, and diff cards and represented by a count.
The count corresponds to the hidden cards; the same pair of image name and package can count separately for different versions or fix statuses.

In this example, the one muted entry is also included in the one “not observed” runtime entry.

```text
🔇 Muted — no fix available and not in use for 7+ days: 1
🔎 Runtime: ▶ 1 in use · 1 not observed · 0 unavailable
```

Packages determined to be muted during the current scan affect other counts as follows.

- Excluded from `Priority:` counts and current unresolved priority counts
- Excluded from current unresolved severity counts when triage is disabled
- Included in “not observed” runtime counts, so those counts overlap with the muted count

When a scan fails, records from the previous scan may be used.
If muting cannot be assessed for those records during the current scan, they remain included in current unresolved priority counts.

A scan failure alone does not produce an unmuted notice.

When notifications resume for a package, a change line appears as follows.

```text
Change: ↩️ Unmuted (now in use)
```

The following table lists the reasons notifications resume and their displays.

| Reason notifications resume | Display |
| --- | --- |
| Package use was confirmed | `Change: ↩️ Unmuted (now in use)` |
| The package qualifies as Act now | `Change: ↩️ Unmuted (act now)` |
| A fix is available for the package | `Change: ↩️ Unmuted (fix available)` |
| The package reached end of life | `Change: ↩️ Unmuted (now end-of-life)` |
| Usage cannot be determined or the required observation period has not elapsed | `Change: ↩️ Unmuted (insufficient observation)` |
| The package's fix status no longer qualifies for muting | `Change: ↩️ Unmuted (not an eligible status)` |

When a package's notifications resume alongside another change, such as a newly available fix or increased priority, KestreLynx gives precedence to [that change's display](#package-change-labels).

See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions and reasons notifications resume.

## Reading warnings {#warnings}

Warnings identify information that was unavailable when checking vulnerabilities, determining priority, or observing runtime usage.
The following table lists their scope and location.

| Type | What it reports | Location |
| --- | --- | --- |
| [Scan](#scan-warnings) | Images or runtimes whose vulnerabilities could not be checked | Later in the full report, or at the end of the diff report |
| [Threat intelligence](#intel-warnings) | Missing or old information used to determine priority | Source warnings before findings; the age note later in the full report |
| [Sensor](#sensor-warnings) | Problems with runtime usage observation | Immediately after the channel notification header |

### Scan warnings {#scan-warnings}

Scan warnings indicate that vulnerabilities in an image or its Node.js or Python runtime could not be checked.
When an image could not be scanned, the notification includes a heading such as this.

```text
⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)
```

The following table explains each display.

| Display | Meaning |
| --- | --- |
| `⚠️ N image(s) could not be scanned (vulnerabilities not checked)` | Scanning or image identity verification failed |
| `⏳ unconfirmed this cycle, holding previous findings — image name list` | The running image could not be confirmed, so previous findings are retained |
| `ℹ️ Advisories for Node.js could not be fetched, so the runtime of N image(s) was not checked.` | Runtime matching was skipped because vulnerability information was unavailable |

The count and details for images that could not be scanned follow these rules.

- N counts distinct image names with failed scans
- See [Images that could not be scanned](#scan-failure-causes) for causes and affected images

The note about retaining previous findings appears when the digest, which identifies image content, could not be confirmed for an image running in Kubernetes.
Even if scanning by image name succeeds, KestreLynx cannot confirm that it checked the content currently running, so it retains previous findings if any exist.

The following rules apply to this retention note.

- It appears even without previous findings to indicate that the image could not be confirmed this time
- If every scan for an image name failed, that name appears in the scan failure warning instead of this list
- To check whether scanning used an image name, see `identity_resolved` and `scan_target_kind` under the webhook's [Image digest](webhook-reference.md#image-identity)

An image absent from this list may still have previous findings retained because its scan failed.
See [Failed scans](scan-logic.md#scan-failures) for how results are retained.

The unchecked-runtime note identifies the skipped targets as follows.

- The name is `Node.js` or `Python runtime` as applicable, or `Node.js, Python runtime` when both are affected
- N counts distinct image names whose runtimes were not checked

See [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable) for when matching is skipped and how previous findings are handled.

#### Images that could not be scanned {#scan-failure-causes}

Images that could not be scanned appear below their cause, with the workloads using them and their image names.
The following example shows an image name alone because its workload is unknown.

```text
⚠️ 1 image(s) could not be scanned (vulnerabilities not checked)
• The cause could not be determined (see the log)
  • broken:1
```

A workload is an application or task running with that image.
The display uses the following grouping rules.

- Images with the same cause are grouped together, with registry-related causes separated by registry host
- Below each cause, the workload and image name are separated by “ — ”
- If multiple workloads use the same image, each workload appears on its own line
- Images with unknown workloads appear by image name alone, last within the same cause and registry host group

Workloads use the following notation for each environment.

| Environment | Workload notation |
| --- | --- |
| Kubernetes | kind namespace/name |
| Compose | Compose project/service |
| Container name is known | container name |

The following table lists cause messages and when they appear.
Here, “host” identifies the source registry; a local registry uses an address such as localhost that refers to the environment where KestreLynx runs.

| Cause display | When this appears |
| --- | --- |
| `Images in the local registry (host) cannot be fetched by KestreLynx` | Connection to a local registry failed |
| `No valid login for the registry (host), so the images could not be fetched` | An authentication requirement, access denial, or similar problem prevented fetching |
| `The images were not found in the registry (host)` | The registry reported that the image was missing |
| `The registry (host) refused too many requests, so the images could not be fetched` | The registry rejected the request because its request limit was reached |
| `Could not connect to the registry (host), so the images could not be fetched` | Connection to a non-local registry failed, for example through a refused connection or timeout |
| `Could not get the vulnerability database` | Downloading or initializing the vulnerability database failed |
| `The image scanned did not match the one running` | The digest, OS, or CPU architecture did not match the running image, or the match could not be confirmed |
| `The cause could not be determined (see the log)` | The cause could not be classified, or the registry host was unknown |

When an error matches multiple causes, the following order takes precedence.
Registry-related causes are checked for scans that fetch images from a registry.

1. Vulnerability database errors
2. Authentication errors
3. Missing images
4. Request limits
5. Connection failures

The original error text is available in the log and the webhook's [`scan_errors`](webhook-reference.md#scan-errors).

### Threat intelligence warnings {#intel-warnings}

Threat intelligence warnings indicate that KEV or EPSS information used to determine priority is unavailable, or that older saved information is being used.
When neither source is available, the following warning appears.

```text
⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low
```

The following table explains each display.

| Display | Meaning |
| --- | --- |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | Neither KEV nor EPSS is available |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | KEV is unavailable, so priority uses EPSS and severity |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | EPSS is unavailable, so priority uses KEV and severity |
| `Intel data is N day(s) old (feeds unreachable).` | Triage is enabled and the data used is at least one day old |

Read the age note as follows.

- If fetching fails, priority is determined using previously fetched data up to seven days old
- N is the number of days since the oldest dataset used was fetched
- A source warning and the age note can both appear when one source is unavailable and older data is used for the other
- If neither source is available, the warning about both sources appears without the age note

See [Full report order](#current-order) for placement and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for the effect on decisions.

### Sensor warnings {#sensor-warnings}

Sensor warnings indicate problems with runtime usage observation or its results.
In channel notifications, they appear immediately after the header containing the date, image counts, and report type.

When the Sensor has not supplied observation results, the warning looks like this.

```text
⚠️ Runtime evidence unavailable: the Sensor has not reported yet
```

The following table explains the reasons appended to this warning.
The “evidence file” stores the Sensor's observations; the “sandbox” restricts the Sensor's operations beyond reading.

| Reason text | Meaning |
| --- | --- |
| `the Sensor has not reported yet` | The file containing the Sensor's observations does not exist yet |
| `the evidence file failed validation` | KestreLynx could not read the observation file, or its contents failed validation |
| `the Sensor's last report is stale` | Too much time has passed since the last report to confirm that observations are fresh |
| `the Sensor's reads are being denied` | The Sensor lacks usable permission to read container process information or similar data |
| `the Sensor's sandbox failed to start` | The Sensor could not confirm its operation restrictions and has not started observing |
| `the Sensor's sandbox is running degraded` | Some restrictions on the Sensor's operations are not effective |
| `the Sensor is degraded` | Stalled processing or another problem is affecting observation or saving results |

Alongside periodic checks, the Sensor uses a kernel facility called eBPF to observe events such as program execution.
Even when the Sensor status is healthy, unavailable event observation produces a warning such as this.

```text
⚠️ Short-lived programs are not observed (eBPF unavailable: BTF missing); using sampling only
```

`using sampling only` means observations rely on periodic checks, which can miss programs that run only briefly.

The following table explains why eBPF observation is unavailable.

| Reason text | Meaning |
| --- | --- |
| `kernel unsupported` | The kernel does not support event observation |
| `BTF missing` | Kernel type information required for event observation cannot be read |
| `permission denied` | Permissions required for eBPF observation are unavailable |
| `attach failed` | Preparing or starting event observation failed |
| `cgroup v1` | The host's container management mechanism is not cgroup v2, which observation requires |
| `unknown` | The reason event observation is unavailable could not be classified |

During a warning, `▶ in use` still indicates observed use.
Unobserved or indeterminate usage does not establish that a package is unused.

See [Usage labels](#usage-labels) for individual package displays and [Runtime usage](runtime-usage.md) for observation methods and limits.
