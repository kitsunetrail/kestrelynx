---
title: Slack report structure and counts
---

# Slack report structure and counts

Four pages explain how to read reports delivered to Slack; this page covers where to find reports, notification language, section order, and how to read counts.

See the following pages for individual package displays, runtime usage, and warnings.

| Contents | Page |
| --- | --- |
| Individual package displays and changes since the previous scan | [Slack package cards and change labels](slack-package-display.md) |
| Runtime usage displays when using Sensor | [Slack runtime usage display](slack-runtime-display.md) |
| Warnings | [Reading Slack warnings](slack-warnings-display.md) |

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

`▶ in use` indicates that Sensor observed execution, loading, or other evidence of package use in a running container (see [Usage labels](slack-runtime-display.md#usage-labels)).
Port exposure and privileges belong to the container using the package; see [Runtime evidence](slack-runtime-display.md#runtime-evidence) for their display.
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
- [Muted](slack-runtime-display.md#muted-display) pairs are excluded from priority counts

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
See [Reading package cards](slack-package-display.md#package-card) for details.

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
- [Muted](slack-runtime-display.md#muted-display) cards are excluded from priority counts

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
See also [Upgrade risk](slack-package-display.md#upgrade-risk) for the display meanings.

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
- With triage enabled, ordinary findings determined to be [muted](slack-runtime-display.md#muted-display) during the latest scan are excluded

Thread cards use the first detection date for ordinary findings and the first EOL detection date for EOL findings.
Cards without a recorded first-seen date omit the age.

The generic webhook includes Low and muted findings, so its included records differ from Slack with triage enabled (see [Oldest unresolved age](webhook-diff-reference.md#oldest-open-days)).
