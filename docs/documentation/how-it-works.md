# How KestreLynx works

KestreLynx turns point-in-time Trivy scan results into notifications organized
around two views:

- **Changes since the previous scan** — posted to the Slack channel in the
  default `diff` mode.
- **Vulnerabilities that remain unresolved** — available in a Slack thread when
  bot delivery is configured and in the generic webhook payload.

Repeating every CVE every day makes new risk easy to miss, while reporting only
changes makes it hard to see what remains unresolved. KestreLynx handles these
two views separately.

```text
Docker host
    │
    ▼
Discover and deduplicate running images
    │
    ▼
Scan each image with Trivy
    │
    ▼
Normalize and group findings by image, package, and fix status
    │
    ▼
Enrich CVEs with CISA KEV and EPSS, then assign priority
    │
    ▼
Compare the current groups with persisted state
    │
    ├── Slack summary: changes since the previous scan
    ├── Slack thread: current open findings
    └── Generic webhook: structured current state and diff
```

## 1. Scan cycle

### Discover running images

KestreLynx calls `GET /containers/json` through the configured Docker socket.
It reads the image reference used by each running container, removes duplicates,
and sorts the result. If ten containers use the same image reference, that image
is scanned once in the cycle.

One KestreLynx container monitors one Docker host. Stopped containers and images
that are present on disk but not used by a running container are outside the
scan scope.

If KestreLynx cannot list the running containers, the cycle ends without
changing the saved state. A later scheduled cycle will try again.

### Scan each unique image

KestreLynx runs the Trivy CLI separately for each unique image and requests JSON
output. The configured `scan.severity` values are passed to Trivy; the default is
`HIGH,CRITICAL`.

An error for one image does not cancel the other image scans. It is included in
the notification under **Scan failures**. Previous findings for that image are
carried forward in state for the cycle, because treating an unscanned image as
clean would create false “resolved” findings.

### Build package-level findings

Raw Trivy rows are normalized into package groups. The primary unit shown in
notifications is:

```text
image + package + Trivy status
```

All selected CVEs for that unit are deduplicated and collected together. The
group contains the installed version, fixed version when available, CRITICAL
and HIGH counts, references, and the strongest priority among its CVEs.

A package can appear in more than one status group when, for example, one CVE
has a fix while another CVE in the same package does not.

## 2. Three independent classifications

KestreLynx deliberately keeps severity, fix status, and priority separate.
They describe different facts and should not be interpreted as synonyms.

| Classification | Source | Question it answers |
| --- | --- | --- |
| Severity | Trivy/advisory data | How large could the impact be? |
| Fix status | Trivy | Is an upstream fix currently available? |
| Priority | KestreLynx triage | How urgently should this be reviewed, given exploitation evidence? |

For example, a CRITICAL CVE can be **Watch** when it has no strong exploitation
signal, while a HIGH CVE can be **Act now** because it is in CISA KEV.

### Fix status

KestreLynx preserves Trivy's status as the canonical remediation state:

| Trivy status | Meaning in KestreLynx |
| --- | --- |
| `fixed` | A fixed version is available. |
| `affected` | The package is affected, but no fix is available yet. |
| `will_not_fix` | Upstream indicates that it will not be fixed. |

These status groups remain in the structured webhook format. Slack is normally
rearranged by priority so the most urgent work appears first.

### Upgrade-risk hint

For a `fixed` package, KestreLynx annotates the size or type of the proposed
version change:

| Label | Rule |
| --- | --- |
| Distribution security update | OS package versions are handled as distribution revisions, not semantic versions. |
| Relatively safe | A language package stays on the same major version, or moves to a lower major version. |
| Needs care | A language package moves to a higher major version. |
| Unknown | The language-package versions cannot be parsed reliably. |

This is an **upgrade-size hint**, not a guarantee that an update is safe.
Release notes, application compatibility, and tests still matter.

### End-of-life base OS

When Trivy reports that an image's base OS is end of life, KestreLynx shows the
image in a separate **EOL base** section above the vulnerability buckets. EOL is
not a CVE priority: it means that normal security updates may no longer arrive,
so rebuilding on a supported base image is usually the appropriate response.

## 3. Exploitation-based triage

Triage is enabled by default. KestreLynx enriches the CVE IDs found by Trivy
with two data sources:

- **CISA KEV** identifies vulnerabilities known to have been exploited in the
  wild.
- **EPSS** estimates the probability of exploitation activity in the next 30
  days. It does not estimate impact and does not prove exploitability in the
  monitored environment.

### CVE priority rules

With the default thresholds, each CVE is classified in this order:

| Priority | Rule |
| --- | --- |
| **Act now** | Listed in CISA KEV, or EPSS is at least `0.10` (10%). |
| **Watch** | Not Act now, and EPSS is at least `0.01` (1%) or severity is CRITICAL. |
| **Low** | No rule above matched. This includes HIGH findings below the EPSS threshold and not in KEV. |

`triage.act_now_epss` and `triage.watch_epss` change the two EPSS thresholds.
If EPSS has no score for a CVE, the EPSS conditions are skipped rather than
treating the missing value as zero.

The KEV ransomware-campaign flag is displayed as evidence, but it does not
create a separate priority level.

### Interaction between priority and fix status

Lack of a fix never hides a strong exploitation signal:

- An Act-now CVE stays Act now for `fixed`, `affected`, and `will_not_fix`.
  When no fix exists, the notification suggests mitigation or replacement.
- A Watch CVE marked `will_not_fix` is reduced to Low to keep an unfixable item
  without a strong exploitation signal out of the active queue.
- Low remains Low regardless of status.

The priority of a package group is the highest priority of any CVE in that
group. Counts in a full priority view are therefore package-group counts, not
raw CVE counts. The diff heartbeat merges status groups with the same image and
package, counts that package once, and uses its highest current priority.

### Feed download, cache, and privacy

KEV and EPSS are downloaded in bulk. KestreLynx then matches CVE IDs locally;
it does not submit the host's complete CVE list to those services. The feed
cache is stored in the `intel` directory beside `state.path`.

- A feed is refreshed after about 20 hours.
- If refresh fails, a previously validated cache can be used for up to 7 days.
- KEV and EPSS are tracked independently. If one remains usable, triage uses it
  and the notification identifies the missing source.
- Downloads are validated before replacing the existing cache.

If neither source is usable, KestreLynx enters **degraded triage**. It displays
a warning and falls back to CRITICAL = Act now and other selected severities =
Watch. Nothing is placed in Low while exploitation intelligence is unavailable.
Priority-escalation events are also suppressed for that cycle, avoiding a feed
outage being reported as a mass risk increase.

When `triage.discussion_links` is enabled, only CVE IDs already classified as
Act now are sent to the Hacker News search API. A result is attached only when
the CVE ID matches and the discussion has at least 20 points. Set the option to
`false` if this additional CVE-ID egress is not wanted.

## 4. Diff state and change detection

In the default `diff` mode, KestreLynx stores history in `state.path` (default:
`/var/lib/kestrelynx/state.json`). The directory should be persisted with a
Docker volume.

For each image and package, state records:

- when it was first seen,
- the set of CVE IDs,
- whether any fix is available, and
- the package's previous maximum priority.

EOL first-seen dates and the reference to the most recent Slack full-report
thread are stored separately. State writes use a temporary file followed by an
atomic rename.

### What counts as a change

Current and previous state are compared in the following precedence order:

| Change | Condition |
| --- | --- |
| New | The image-and-package key was not in the previous state. |
| Escalated | A known package's maximum priority increased, for example Watch → Act now. |
| New CVEs | The known package gained one or more CVE IDs. |
| Now fixable | The known package had no fix before and has at least one fix now. |
| Resolved | A previously stored image-and-package key is absent from a successful current scan. |

Only the highest-precedence reason is shown when several conditions become true
in the same cycle. Priority decreases are silent, but the new lower priority is
saved and can be used as the baseline for a later escalation.

“Resolved” means that the finding is no longer in KestreLynx's current scope.
Possible causes include installing a fix, changing the image, stopping the
container, changing the selected severity levels, or a scanner-data change. It
does not by itself prove that a patch was installed.

On the first run, or when no usable state file exists, every current package is
reported as New. A corrupt state file is treated the same way and a warning is
logged. A state-format version mismatch starts fresh without trying to interpret
incompatible history.

### When state advances

If no notification is required, the newly computed state is saved immediately.
If delivery is required, state is saved only after all configured destinations
succeed. A failed delivery therefore causes the same changes to be retried on
the next cycle rather than silently lost.

When several destinations are configured, KestreLynx attempts all of them. A
partial failure can cause the successful destination to receive the same change
again on the next cycle; delivery favors not losing an alert over exactly-once
semantics.

## 5. When a notification is sent

### Diff mode (default)

| Current result | Notification with `notify_on_clean: false` |
| --- | --- |
| Findings exist and something changed | Send the changes and the current open-count summary. |
| Findings exist but nothing changed | Send a short heartbeat; do not repeat the detailed list in the channel. |
| The final finding was resolved | Send the resolved change and an all-clear status. |
| Clean and unchanged | Do not send. |
| One or more image scans failed | Send the failure, even if no vulnerability finding is available. |

After 14 days, the heartbeat marks the age of the oldest EOL, Act-now, or Watch
item with a clock. Low items do not age the heartbeat because an old Low item is
not treated as urgent debt.

On `notify.full_report_day` (Monday by default), the complete Slack report is
included when that cycle otherwise has something to send. Set the value to
`never` to disable the weekly report. The weekly setting does not force a
notification for a clean, unchanged result when `notify_on_clean` is false.

### Full mode

With `notify.mode: full`, no diff state is used. Every scan with findings or
scan failures sends the current report. A clean result is sent only when
`notify_on_clean` is true.

## 6. Slack presentation

Slack messages use plain `mrkdwn` text rather than Block Kit. In Slack,
“full report” means a current-state report rather than a full dump of every CVE:
Act-now and Watch items are expanded, while Low remains count-only. The generic
webhook is the unabridged data source.

With triage enabled, the current report is ordered as follows:

1. EOL base images
2. Act now — package details and the strongest CVE's KEV/EPSS evidence
3. Watch — compact package details and the strongest signal
4. Low — count only
5. Scan failures and intelligence freshness warnings

Act-now references can include Trivy's primary advisory, a vendor advisory from
KEV notes, and an optional Hacker News discussion. Low details are intentionally
omitted from Slack; the structured generic webhook carries the full list.

### Common header

Every Slack channel notification starts with the scan time and two image counts:

```text
🛡️ KestreLynx — scan results for 2026-08-16 09:00
4 images scanned, 3 affected
```

- `images scanned` is the number of unique running image references discovered
  in the cycle, including images whose scan failed.
- `affected` is the number of distinct images with a selected vulnerability or
  an EOL base OS. An image with only a scan failure is not counted as affected;
  it appears under **Scan failures** instead.
- The time is formatted in the process's local timezone. In the container, this
  is controlled by the `TZ` environment variable.

### Diff notification in the channel

The default channel message is a change report, not a copy of the current full
report. Its sections appear in this order when applicable:

1. Common header
2. Newly detected EOL base images
3. Vulnerability-intelligence warning
4. New or changed packages
5. Resolved EOL images and packages
6. Weekly current-state report, or scan failures and the **Open now** line
7. Bot-only link to the report in this message's thread or the previous report

An abbreviated example is:

```text
🛡️ KestreLynx — scan results for 2026-08-16 09:00
4 images scanned, 3 affected

🆕 New since last scan (1)
🚨 ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch — ⬆️ escalated to ACT NOW
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%

✅ Resolved since last scan (1)
• ghcr.io/example/worker:latest: libxml2

📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
   — oldest act-now/watch unresolved 4 day(s)

📊 Full report in this message's thread ↓
```

The number in `New since last scan (N)` is the number of changed
image-and-package entries, not the number of CVEs. New and changed entries are
sorted by priority first, then image and package name.

If nothing changed, the body becomes:

```text
No changes since last scan.
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
🔗 Last full report → thread
```

If nothing remains open, the **Open now** line is instead:

```text
🎉 Open now: none — all clear
```

### Current-state report layout

Full mode, the weekly report in a diff notification, and the Bot API thread all
represent what is open at the time of the current scan. The channel version has
the following shape:

```text
Priority: ⛔ 1 EOL base · 🚨 1 act now · 👀 2 watch · 🔕 8 low

⛔ Base OS end-of-life (top priority)
• ghcr.io/example/legacy:latest — base OS is EOL (...)

🚨 Act now (1) — exploited or likely to be
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (...) · EPSS 12%
       📎 advisory · vendor advisory · 💬 HN (120 pts)

👀 Watch (2) — not urgent, keep an eye on
• ghcr.io/example/frontend:latest
   • zlib 1.2.13 (no fix available) (CRITICAL 1 / HIGH 0) — CVE-2026-23456 · EPSS 0.4%

🔕 Low priority (8) — 8 finding(s) across 3 image(s), no exploitation signal (...)
```

Zero-count priority segments and empty sections are omitted. The priority
headline counts status-specific package groups. Consequently, one package can
contribute more than once if Trivy reports different CVEs for it under different
fix statuses.

### How to read a package entry

A fixable package line has this format:

```text
package installed-version → fixed-version (CRITICAL N / HIGH N) upgrade-label [lang] change-label
```

A package without a fix replaces the arrow and fixed version with
`(no fix available)`. CRITICAL and HIGH are counts of distinct CVE IDs in that
specific package and status group. `[lang]` identifies a language package; its
absence normally means an OS package.

The labels following a package have these meanings:

| Displayed label | Meaning |
| --- | --- |
| `🟢 upgrade: distro security patch` | Fix for an OS package; distribution versions are not compared as SemVer. |
| `🟢 upgrade: low-risk` | Language-package fix does not increase the major version. This is not a safety guarantee. |
| `🟠 upgrade: major version bump — needs care` | Language-package fix increases the major version and may break compatibility. |
| `⚪ upgrade: risk unknown` | The versions could not be parsed reliably. |
| `[lang]` | Trivy classified the package as a language dependency rather than an OS package. |
| `⬆️ escalated to ACT NOW/WATCH` | A known package's maximum priority rose since the previous scan. |
| `N new CVE(s)` | New CVE IDs appeared under a known image and package. |
| `fix now available` | A known package changed from no available fix to at least one available fix. |

The green upgrade icon describes the proposed version change. It does **not**
mean that the image, package, or vulnerability is safe.

### Evidence and reference lines

An Act-now package is followed by an evidence line for its strongest CVE:

```text
↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
```

The strongest CVE is selected by priority, then known and higher EPSS, then CVE
ID. If the package contains other CVEs, the channel appends
`(+N more CVE(s) in this package)` instead of expanding each one.

Evidence labels mean:

| Label | Meaning |
| --- | --- |
| `CISA KEV (exploited in the wild)` | The CVE is present in the current usable KEV catalog. |
| `EPSS N%` | Current EPSS probability. Missing scores are shown as `n/a`. Very small values use `<0.1%`; very large values use `>99%`. |
| `🧨 ransomware campaign` | CISA marks known use in ransomware campaigns. This is evidence, not a separate priority. |
| `no fix yet, consider mitigation` | The strongest evidence belongs to an `affected` group without a fix. |
| `upstream won't fix, consider replacing` | The group is `will_not_fix`; replacement or another compensating action may be needed. |
| `📎 advisory` | Trivy's primary advisory URL. |
| `vendor advisory` | A vendor or CISA reference extracted from KEV notes. |
| `💬 HN (N pts)` | An optional matching Hacker News discussion and its point count. |

Watch uses a shorter inline reason after the package, normally the strongest CVE
and its EPSS value. Low has no per-package Slack detail.

### Section, status, and warning labels

| Label | Meaning |
| --- | --- |
| `⛔ EOL base` | The base OS is end of life. It is tracked separately from CVE priority. |
| `🚨 Act now` | Known exploitation or EPSS at/above the Act-now threshold. |
| `👀 Watch` | Review and monitor; weaker signal than Act now. |
| `🔕 Low` | No signal reached the configured thresholds. It does not mean “not vulnerable.” |
| `🆕 New since last scan` | Contains new packages and known packages that changed. |
| `✅ Resolved since last scan` | No longer present in current scope; it does not prove a patch was installed. |
| `📌 Open now` | Compact current backlog counts after applying the latest scan. |
| `⏰ oldest ... unresolved` | The oldest EOL/Act-now/Watch item has remained open for at least 14 days. |
| `⚠️ Scan failures` | Images that could not be scanned in this cycle. |
| `⚠️ ... data unavailable` | One or both exploitation-intelligence sources are unavailable. |
| `Intel data is N day(s) old` | A validated stale cache is being used because refresh failed. |
| `📋 Weekly full report` | The current-state view appended on the configured weekday. |
| `📊 Full report in this message's thread` | The Bot API posted current-state replies below this channel message. |
| `🔗 Last full report` | No new thread was needed; follow the link to the last successful report. |

`✅ Actionable now (fixed)` appears only in the triage-disabled layout. In that
label, “actionable” means that a fix version exists. It is not the same as the
triage priority **Act now**.

### Slack thread format

The Bot API thread starts with `📊 Full report — YYYY-MM-DD HH:MM`, followed by
EOL, ACT NOW, WATCH, and LOW sections. Act-now and Watch packages are expanded:

```text
📊 Full report — 2026-08-16 09:00

🚨 ACT NOW (1) — exploited or likely to be
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (...) · EPSS 12%
       Short title supplied by Trivy
       📎 advisory · vendor advisory · 💬 HN (120 pts)
     also: CVE-2026-20001, CVE-2026-20002
     ⏱ open 4 day(s) — first seen 2026-08-12

🔕 LOW (8) — no exploitation signal
```

Only the strongest CVE receives a full evidence line and title. Up to eight
additional CVE IDs are displayed after `also:`; the rest become `(+N more)`.
`first seen today` is shown instead of an age on day zero. If the report exceeds
the message-size budget, it is split into consecutive replies and continued
section headings receive `(cont.)`.

Slack's current Low footer also refers readers to the weekly report. Low remains
count-only there as well, so the generic webhook is the source for the complete
per-CVE Low list.

### Incoming Webhook and Bot API

| Capability | Slack Incoming Webhook | Slack Bot API |
| --- | --- | --- |
| Post the channel summary | Yes | Yes |
| Post a current-state report in a thread | No | Yes |
| Link to the previous report thread on unchanged days | No | Yes |

With `slack_bot_token` and `slack_channel`, the channel remains the change feed.
When findings change or the weekly report is due, replies under that channel
message contain the current state. On an unchanged day, the channel heartbeat
links to the most recent successful report thread instead of recreating it.

The thread expands EOL, Act-now, and Watch items. For each package it shows the
strongest CVE, title when Trivy supplies one, evidence, references, additional
CVE IDs, and first-seen age. Low remains count-only. Long reports are split into
multiple replies at image or line boundaries. Slack API calls are retried up to
three times; the new thread reference is saved only after the report finishes.

On the first Bot API notification, after a channel change, or when no valid
previous permalink exists, KestreLynx creates a fresh report thread so future
heartbeats have a valid destination.

## 7. Generic webhook

`notify.generic_webhook_url` receives structured JSON and can be enabled beside
either Slack delivery method. It is a generic HTTP endpoint, not a preformatted
Discord, Teams, or other service-specific message.

Whenever a notification is sent, the payload includes the full current report:
summary counts, EOL images, fix-status sections, package versions, upgrade-risk
and priority values, CVE IDs and evidence, scan failures, and—when diff mode is
active—the current diff.

The top-level layout is:

| JSON field | Contents |
| --- | --- |
| `generated_at` | Scan time in RFC 3339 format. |
| `summary` | Total/affected image counts plus priority counts and intelligence freshness when triage is enabled. |
| `eosl_images` | Images whose base OS is EOL. |
| `actionable` | Current package groups with Trivy status `fixed`. |
| `watch` | Current package groups with Trivy status `affected`. |
| `wont_fix` | Current package groups with Trivy status `will_not_fix`. |
| `scan_errors` | Per-image scan failures. |
| `diff` | Diff-mode changes: `new`, `resolved`, EOL changes, and oldest-open age. Omitted in full mode. |

Each finding contains `package`, `installed`, `fixed`, `status`,
`severity_counts`, `upgrade_risk`, `priority`, `vuln_ids`, and a `vulns` array.
Each CVE object can include its severity, title, advisory URL, KEV/ransomware
flags, EPSS value, priority, and reference links. EPSS is `null` when no score
is known.

For compatibility, the top-level finding sections use fix status:
`actionable` means Trivy status `fixed`, `watch` means status `affected`, and
`wont_fix` means `will_not_fix`. These names are independent of each package's
triage `priority` field. In particular, the webhook's top-level `watch` array is
not the same thing as the triage priority **Watch**.

The full payload is attached only to cycles that meet the notification rules
above. A clean, unchanged cycle skipped by `notify_on_clean: false` does not
call the webhook.

## 8. Triage disabled

Setting `triage.enabled: false` stops the KEV, EPSS, and discussion lookups.
There are no Act-now, Watch-priority, or Low buckets. Slack falls back to the
fix-status view:

1. EOL base images
2. Fix available
3. Affected, waiting for an upstream fix
4. Upstream will not fix

Diff detection still reports New, New CVEs, Now fixable, and Resolved. Priority
escalation is unavailable because no priority baseline is computed.

## 9. Example across several scans

Suppose `openssl` in an image has one HIGH CVE with EPSS 0.4% and no KEV entry.

1. On the first scan, the package is **New** and its priority is **Low**.
2. The next day, the result is unchanged. KestreLynx sends only the open-count
   heartbeat in Slack.
3. A fix appears. The package is reported as **Now fixable** and its version
   change is annotated.
4. Before the update is deployed, the CVE is added to CISA KEV. The package is
   reported as **Escalated to Act now**, even though it was already known.
5. After the container image is updated and the package no longer appears, the
   finding is reported as **Resolved**.

This sequence is the core of KestreLynx: retain enough history to report a
meaningful change, while preserving the current state for investigation.
