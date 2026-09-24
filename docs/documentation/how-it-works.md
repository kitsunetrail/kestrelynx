# How KestreLynx works

KestreLynx uses Trivy scan results for running images to report changes since the previous scan and findings that remain unresolved.

- The Slack channel shows changes since the previous scan in the default `diff` mode.
- Slack Bot threads show the current state, and the generic webhook provides all findings and changes.
- See [Configuration](configuration.md) for setup instructions.

The overall scan flow is:

```text
Docker host / Kubernetes cluster
    │
    ▼
Discover running containers (Chapter 1)
    │
    ▼
Derive distinct images by identity (Chapter 1)
    │
    ▼
Scan each image with Trivy (Chapter 1)
    │
    ▼
Group findings by image, package, and fix status (Chapter 2)
    │
    ▼
Assign priority using CISA KEV and EPSS (Chapter 3)
    │
    ▼
Compare with persisted state to detect changes (Chapter 4)
    │
    ├── Slack summary: changes since the previous scan (Chapters 5 and 6)
    ├── Slack thread: current unresolved findings (Chapter 6)
    └── Generic webhook: structured current state and diff (Chapter 7)
```

## 1. Scan cycle

Scans cover images used by running containers. One instance monitors one Docker host or one Kubernetes cluster. Stopped containers and images not used by a running container are outside the scan scope.

Identical reference-and-identity pairs are combined into one entry. The same reference with different digests produces separate entries. Each image is scanned with Trivy, and findings are grouped by package.

`scan.severity` selects the severity levels to include. The default is `HIGH,CRITICAL`.

### Image and container identification

Docker and Kubernetes scan targets depend on the identity information available. Docker connections use `docker.socket`. Set `kubernetes.enabled: true` to monitor Kubernetes.

Kubernetes discovery includes running containers and currently running init containers with `restartPolicy: Always`. Ordinary init containers and ephemeral containers are excluded. `kubernetes.namespaces` can restrict discovery to selected namespaces.

Container and workload information is included only in the generic webhook. If the associated workload cannot be identified, it is recorded as `unknown`.

### Discovery retries

If listing containers fails, the cycle ends without changing saved state and retries on the next scheduled cycle. In Kubernetes, even a partial listing failure discards the partial results and leaves state unchanged for that cycle.

### Scan targets and identity verification

When an image's identity is known, the scan targets that identity. A result that does not match the requested digest or platform is treated as a scan failure.

When the identity is unknown, the image is scanned by reference and annotated with `identity unconfirmed: scanned by reference`.

### Failed scans and unconfirmed identities

A failed scan retains the target's previous findings. Unverified results cannot resolve previous findings. Failure to scan one image does not stop the remaining scans, and failures appear under Scan failures in Slack.

When only some identities under the same reference fail, previous CVE IDs, fix availability, and the higher priority are retained. In Kubernetes, even a successful reference scan retains previous findings and does not resolve ordinary packages or clear EOL packages.

### Package-level grouping

Findings are grouped by image reference and identity, package, and canonical fix status. Different fix statuses produce separate groups even for the same package.

Each group deduplicates CVE IDs and retains versions, CRITICAL and HIGH counts, reference URLs, and the highest priority in the group. State and diffs are keyed by image reference and package.

When a reference has multiple identities, Slack distinguishes them with labels such as `web:1.0 (3f2a9c1b7d4e)` or `web:1.0 (3f2a9c1b7d4e linux/amd64)`.

??? note "Technical details"

    Scan results are obtained as JSON from the Trivy CLI.

    | Item | Docker | Kubernetes |
    | --- | --- | --- |
    | Container listing | `GET /containers/json`: `Image`, `ImageID`, `Names`, and `Labels`. | Read-only LIST requests for nodes, pods, replicasets, and jobs. `kubernetes.namespaces` applies to all except nodes. |
    | Container names and running status | Leading slashes and link aliases are removed from `Names`. | Regular containers are considered running when `state.running` is present. |
    | Image identity | Config digest from `ImageID`, accepted only as `sha256:` followed by 64 hexadecimal digits. | Reference from `containerStatus.image`. Registry digest from `<repo>@sha256:<hex>` in `containerStatus.imageID`, optionally prefixed with `docker-pullable://`. A bare `sha256:...` uses a reference scan. |
    | Platform | Not applicable. | The node's `status.nodeInfo.operatingSystem` and `architecture`. No variant is inferred. The platform also contributes to image identity. |
    | Workload resolution | Compose when both `com.docker.compose.project` and `com.docker.compose.service` are valid. | `ownerReferences` resolves to a Deployment, StatefulSet, DaemonSet, CronJob, Job, or bare Pod. |
    | Trivy scan method | Local image selected by config digest with `--image-src docker`. | When the registry digest and platform are known, `<repo>@sha256:<hex>` with `--image-src remote` and `--platform <os>/<arch>`. |
    | Scan result verification | `Metadata.ImageID` must match the requested config digest. | `Metadata.RepoDigests` must contain the requested digest, and `Metadata.ImageConfig` must match the requested OS and architecture. |

    - Kubernetes LIST requests use pages of up to 500 objects and retry each page independently. Transport errors, HTTP 429, and server errors are retried up to 3 times with `Retry-After` and exponential backoff; HTTP 410 restarts the listing up to 2 times; HTTP 401 causes the ServiceAccount token to be read again.
    - The ServiceAccount token and CA are read each scan cycle.
    - Aliases for the same identity share only results that successfully confirm that identity. After a failed or unconfirmed scan, the next alias is scanned again.
    - When only some identities under the same reference fail, `content_id` is cleared and the union of CVE IDs is retained.
    - Slack considers a reference confirmed only when every identity under it was identified by a Docker config digest at discovery. This check is independent of scan results, and Kubernetes registry digests count as unconfirmed.

## 2. Severity, fix status, and EOL

Severity, fix status, and priority describe different information.

- Severity describes the potential impact reported by Trivy and advisory data.
- Fix status describes fix availability and support status reported by Trivy.
- Priority describes the urgency of review based on exploitation evidence.

### Status handling

Fix status comes from Trivy's `Status` and is not inferred from fix availability. A missing or empty `Status` is treated as `unknown`. Unrecognized statuses are included in `affected` rather than excluded.

When the original status differs from the canonical group status, it is available in the webhook's `vulns[].status`.

| Trivy status | Meaning in KestreLynx |
| --- | --- |
| `fixed` | A fixed version is available. Included in `fixed`. |
| `affected` | The package is affected, but no fix is available. Included in `affected`. |
| `will_not_fix` | Upstream indicates that it will not be fixed. Included in `will_not_fix`. |
| `fix_deferred` | A fix is deferred. Included in `affected`. |
| `end_of_life` | The selected CVEs are out of support for this release. Included in EOL package. |
| `unknown` | The fix status is unknown. Included in `affected`. |
| `under_investigation` | The vulnerability is under investigation. Included in `affected`. |
| `not_affected` | Excluded from grouping, notifications, and priority classification. |

### EOL base and EOL package

EOL describes support status and is handled separately from CVE priority. Base OS and package status appear as follows.

- EOL base indicates that Trivy reported the base OS as end of life and appears at the top.
- EOL package contains packages with `end_of_life` status and appears after EOL base, whether triage is enabled or disabled.

The usual response to EOL base is to rebuild on a supported base image. If the base OS is also EOL, the reference's EOL packages are folded into the base-OS line with `includes N end-of-life package(s)`.

Act now EOL packages show their details in Act now whether or not they are folded, including during degraded triage. Unfolded packages show `🚨 see Act now` in the EOL section, so EOL package and Act now counts can overlap.

EOL packages with Watch or Low priority appear only in their dedicated EOL section and are not repeated in the ordinary Watch or Low sections.

??? note "Technical details"

    - If the same CVE ID has multiple original statuses within one group, the canonical group status takes precedence when present; otherwise, the lexically smaller status is retained.

## 3. Exploitation-based triage

Triage indicates review priority based on exploitation evidence and is enabled by default. Each package group receives the highest priority of any CVE in that group.

- CISA KEV identifies vulnerabilities known to have been exploited in the wild.
- EPSS estimates the probability of exploitation activity in the next 30 days.

EPSS does not establish impact or guarantee exploitability in the monitored environment.

### CVE priority rules {#cve-priority-rules}

Normal triage assigns the following priorities using KEV membership, EPSS, and severity. `triage.act_now_epss` and `triage.watch_epss` configure the thresholds.

| Priority | Default condition |
| --- | --- |
| **Act now** | Listed in KEV, or EPSS is at least `0.10` (10%). |
| **Watch** | Not Act now, and EPSS is at least `0.01` (1%) or severity is CRITICAL. |
| **Low** | No rule above matched. This includes HIGH findings below the EPSS threshold and not in KEV. |

If no EPSS score is available, EPSS conditions are skipped rather than treating the score as 0. The KEV ransomware-campaign flag is displayed as evidence but does not create a separate priority.

Fix status affects priority as follows.

| Fix status | Relationship to priority |
| --- | --- |
| All reportable statuses | Act now is retained. When no fix is available, consider mitigation, replacement, or a supported version. |
| `will_not_fix` | Watch is reduced to Low during normal triage. |
| `affected`, `fix_deferred`, `under_investigation`, `unknown` | The same priority rules apply. |
| `end_of_life` | The reduction from Watch to Low does not apply. |
| All reportable statuses | Low is retained regardless of fix status. |
| `not_affected` | Excluded from priority classification. |

### Feeds and degraded operation

If intelligence refresh fails, triage continues using a validated cache for up to 7 days. The cache is stored in the `intel` directory beside `state.path` and refreshed after about 20 hours.

Limited source availability is handled as follows.

- If only one source is usable, triage continues with that source and the notification identifies the unavailable source.
- If neither source is usable, degraded triage assigns CRITICAL findings to Act now and other selected severities to Watch.

During degraded triage, nothing is classified as Low, and ordinary and EOL priority-escalation notifications are suppressed.

When `triage.discussion_links` is enabled, Hacker News discussions are added for Act now CVEs. A discussion must match the CVE ID and have at least 20 points. Set `triage.discussion_links: false` to stop sending CVE IDs for discussion searches.

Feed matching does not send the host's complete CVE list to external services.

??? note "Technical details"

    - KEV and EPSS are downloaded in bulk, and CVE IDs are matched locally.
    - Normal triage evaluates the priority table from top to bottom.
    - Discussion searches send only Act now CVE IDs to the Hacker News search API.

## 4. Diff state and change detection

In `diff` mode, the history in `state.path` is compared with current results to identify changes since the previous scan. The default state file is `/var/lib/kestrelynx/state.json`, and its directory should be persisted.

One state file holds one environment and must not be shared by multiple instances. Adding, changing, or removing `environment.name` does not reset history or first-seen dates.

Ordinary and EOL package state can coexist for the same image reference and package. Older state files load without conversion, but if `eol_packages` is absent, current EOL packages are reported as newly detected EOL packages.

### Changes included in the diff

For ordinary packages, notifications cover new findings, priority escalations, added CVEs, and newly available fixes. If multiple changes apply at once, only one reason is reported.

- New means that the image reference and package combination was absent from the previous state.
- Escalated means that the priority rose above the saved maximum priority.
- New CVEs means that new CVE IDs were added to a known package.
- Now fixable means that no fix was previously available and at least 1 fix is now available.

Priority decreases are saved without notification, and later escalations use the saved value as their baseline. Moving from EOL back to ordinary findings alone does not count as New or New CVEs.

EOL package changes are reported independently of ordinary changes.

- Newly detected EOL means that no previous EOL record exists, including a move from ordinary findings or a return after EOL cleared.
- Escalation to Act now means that an EOL package rose from its saved EOL priority to Act now; missing saved priority, degraded triage, and a rise from Low to Watch do not qualify.
- New EOL CVEs means that new EOL CVE IDs were added to a known EOL package.

A package being “resolved” means that its findings have left the current scope; it does not prove that a patch was installed. A previous image reference and package combination is resolved when it is absent from both ordinary and EOL findings in the current successful scan.

Moving all ordinary findings to EOL does not resolve the package. A combination that disappears from both sides is counted once in Slack. If ordinary findings remain after EOL clears, Slack shows `no longer end-of-life` rather than treating the vulnerabilities as resolved.

Base-OS changes also report newly detected EOL and references no longer recorded as EOL.

Image replacement is a diff independent of package changes and is reported even for images without findings. It applies when the previous and current verified content-ID sets are both nonempty and differ. The first observation does not count as a replacement.

Resolutions and EOL clearances are not reported when previous state is retained because of fully or partially failed scans or unconfirmed Kubernetes identities.

### State persistence and repeated notifications

When a notification is required, state is saved only after delivery succeeds to every configured destination. Delivery is attempted to all destinations even if some fail, so a destination that succeeded may receive the same change again on the next cycle.

When no notification is required, the new state is saved directly.

The first run, a missing or corrupt state file, or a state-format version mismatch starts fresh and reports current packages as new. A corrupt state file also produces a log warning.

??? note "Technical details"

    - Ordinary package state stores the first-seen timestamp, CVE ID set, fix availability, maximum priority, and `content_id` for a single verified identity.
    - Package-state `content_id` is empty when the reference is ambiguous or some scans fail.
    - The state file's `images` map is keyed by reference and records sorted `content_ids`, `registry_digests`, `ambiguous`, and `last_seen`.
    - Base-OS EOL first-seen timestamps are stored separately from ordinary package state.
    - EOL package first-seen-as-EOL timestamps, CVE ID sets, and maximum priorities are stored separately from ordinary package state.
    - The state-format version remains `1`.
    - Ordinary package changes are evaluated in the order New, Escalated, New CVEs, and Now fixable, with only the highest-precedence reason reported when several apply.
    - Ordinary comparisons also use previous EOL history.
    - EOL package changes are evaluated in the order newly detected EOL, escalation to Act now, and new EOL CVEs.
    - Retention caused by fully or partially failed scans or unconfirmed Kubernetes identities takes precedence over transitions between ordinary and EOL state.
    - State is written to a temporary file and then replaced atomically.

## 5. Notification conditions

The default `notify.mode: diff` reports changes and current unresolved counts. `notify_on_clean` (`notify.notify_on_clean`) controls whether cycles without vulnerabilities also send notifications.

- When findings exist and something changed, the notification includes changes and unresolved counts.
- When findings exist but nothing changed, a short heartbeat is sent.
- When the final finding is resolved, the notification includes the resolution and an all-clear status.
- When there are no findings or changes, `notify_on_clean: false` suppresses the notification.

Scan failures and image replacements trigger notifications even when there are no vulnerability findings.

When an unconfirmed Kubernetes identity causes previous package findings to be retained, including EOL packages, a notification is sent even if nothing changed. Retained base-OS EOL history alone does not meet this holding-notification condition.

On the weekday selected by `notify.full_report_day`, a full Slack report is added to cycles that qualify for notification. The default is Monday, and `never` disables it. Even on the weekly report day, no notification is forced for a cycle without findings or changes when `notify_on_clean: false`.

With `notify.mode: full`, diff state is not used, and every cycle with findings or scan failures sends the current report. If neither exists, a report is sent only when `notify_on_clean: true`.

## 6. Slack presentation

Slack channels show changes, and Bot threads show current details. Empty sections are omitted, and Low remains count-only even in a full report. The generic webhook provides the complete per-CVE data.

The image counts in the header have the following meanings.

- `images scanned` counts distinct reference-and-identity pairs, including failed scans; separate references count separately even when they share a scan.
- `affected` counts images with a selected vulnerability or an EOL base OS and excludes images with only a scan failure.

Times use the process's local timezone, configured through `TZ` in a container. `environment.name` appears only in the channel header.

### Section order

Diff notifications show changes since the previous scan, while current-state reports show unresolved findings by EOL status and priority. Each notification uses the following display order.

- Diff notifications use this order: common header → image content changes → new EOL base → EOL package changes → intelligence-source warnings → ordinary new or changed findings → resolutions and EOL clearances → weekly report or scan failures and Open now → identity-unconfirmed and holding annotations → Bot report link.
- Current-state reports use this order: EOL base → unfolded EOL package → Act now → Watch → Low → scan failures and intelligence-freshness warnings → identity-unconfirmed and holding annotations.
- Bot threads use this order: EOL base → EOL packages → ACT NOW → WATCH → LOW.

Warnings about unavailable intelligence sources appear immediately after the current-state report's Priority line, before the EOL sections.

Ordinary new and changed entries are sorted by priority, image name, and package name. `New since last scan (N)` counts ordinary image reference and package combinations that changed.

Act now EOL changes are shown individually. Other EOL changes are summarized as counts for each existing EOL base-OS reference. When a base OS and its packages become newly EOL in the same cycle, packages other than Act now are folded into the base-OS line and excluded from the EOL package diff heading's count.

### Open now and counts

Open now shows unresolved state after the latest scan, including retained records. EOL counts appear before priority counts and use the following units.

- EOL base counts retained EOL base-image references.
- EOL package counts image reference and package combinations not folded into a base OS.
- Act now, Watch, and Low count each reference and package once, using Act now if either its ordinary or EOL findings are Act now, and otherwise using its ordinary priority.

EOL Watch and Low findings do not contribute to priority counts. EOL package and Act now counts can overlap.

The current-state report's Priority line counts package groups by fix status, so one package may contribute more than once.

Open now varies with current findings and retained state.

- If the current report contains findings or EOL base images, counts are shown.
- `🎉 Open now: none — all clear` appears only when neither the current report nor retained state contains findings and no unconfirmed-identity holding condition applies.
- If the current report has no findings or EOL base images and packages are retained because of unconfirmed Kubernetes identities, an unconfirmed holding status is shown.
- Otherwise, if the current report has no findings but records are retained, a holding status is shown until the next successful scan.

### Unresolved age

The heartbeat's age is measured from the oldest first-seen date among included items. It shows the age after 1 day and adds a clock after 14 days. Retained records are included.

- With triage enabled, the age includes ordinary Act now and Watch findings, EOL base images, unfolded EOL packages, and folded EOL packages with Act now priority.
- With triage disabled, the age includes all ordinary packages and EOL records.

With triage enabled, ordinary Low findings are excluded, and the label remains `oldest act-now/watch unresolved N day(s)` even when EOL records contribute. With triage disabled, the label is `oldest unresolved N day(s)`.

EOL packages use their first-seen-as-EOL date. Folded EOL packages other than Act now use the base OS's first-seen-as-EOL date. Act now EOL packages contribute their own first-seen-as-EOL date even when folded.

### Label meanings

Labels identify changes, review priority, and reasons results could not be confirmed. Green upgrade icons describe only the type of version change and do not guarantee safety.

CRITICAL and HIGH count distinct CVE IDs within each package and fix-status group.

| Label | Meaning |
| --- | --- |
| `⛔ EOL base` | The base OS is end of life. |
| `⛔ EOL package` | The selected CVEs are out of support for this release. |
| `⛔ N EOL base` | EOL base-image count in the Priority line. |
| `⛔ N EOL package` | EOL group count in the Priority line, excluding groups folded into a base OS. |
| `🚨 N act now` | Act now group count in the Priority line, including Act now EOL groups. |
| `⛔ Package end-of-life (N) — vendor reports these CVEs as out of support for this release` | Current-state EOL package section. |
| `⛔ New: package end-of-life (N) — vendor reports these CVEs as out of support for this release` | Newly detected EOL packages, escalations to Act now, and added CVEs. |
| `⛔ EOL packages (N) — vendor reports these CVEs as out of support for this release` | EOL package section in a thread. |
| `🚨 Act now` | Known exploitation or EPSS at or above the threshold; also includes CRITICAL findings during degraded triage. |
| `👀 Watch` | Findings to review and monitor. |
| `🔕 Low` | No signal reaches the threshold; this does not mean there is no vulnerability. |
| `🔄 Image content changed` | A verified content-ID set changed. |
| `🆕 New since last scan` | New packages and changed known packages. |
| `✅ Resolved since last scan` | Resolved packages and EOL base images, and cleared EOL package records. |
| `📌 Open now` | Unresolved state after the latest scan. |
| `📌 Open now: unconfirmed — holding previous findings until re-confirmed` | No current findings, with previous ordinary or EOL package findings retained because of unconfirmed Kubernetes identities. |
| `📌 Open now: not re-scanned — holding previous findings until the next successful scan` | No current findings, with previous records retained outside the unconfirmed holding condition. |
| `⏰ oldest ... unresolved` | An included item has been unresolved for at least 14 days. |
| `<ref> — identity unconfirmed: scanned by reference` | A reference includes an identity that was not identified by a Docker config digest at discovery. |
| `<ref> (<12hex>)`, `<ref> (<12hex> linux/amd64)` | Digest and platform distinguish multiple identities under one reference. |
| `⚠️ identity unconfirmed: scanned by reference — a, b` | References containing identities not identified by Docker config digests at discovery, independent of scan results; this may list every Kubernetes reference. |
| `⏳ unconfirmed this cycle, holding previous findings — a, b` | Kubernetes references containing targets whose remote scans succeeded without pinning their identities; references with only failures are excluded, and the line may appear even without history. |
| `⚠️ Scan failures` | Failed scans, including digest or platform verification failures. |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | Neither source is usable, so triage uses severity alone and does not reduce anything to Low. |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | Triage uses EPSS and severity, and Act now detection may be incomplete. |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | Triage uses KEV and severity. |
| `_Intel data is N day(s) old (feeds unreachable)._` | Refresh failed, and a validated stale cache is in use. |
| `📋 Weekly full report` | Current-state report for the configured weekday. |
| `📊 *Full report — YYYY-MM-DD HH:MM*` | Heading for the current-state report in a Bot thread. |
| `📊 Full report in this message's thread` | The Bot posted the current state in this message's thread. |
| `🔗 Last full report` | Link to the most recent successful report. |
| `✅ Actionable now (fixed)` | Fix-available section when triage is disabled, separate from Act now. |

| Package or change label | Meaning |
| --- | --- |
| `🟢 upgrade: distro security patch` | OS package update treated as a distribution revision without SemVer comparison. |
| `🟢 upgrade: low-risk` | A language-package change that does not increase the major version. |
| `🟠 upgrade: major version bump — needs care` | A language-package change that increases the major version and may break compatibility. |
| `⚪ upgrade: risk unknown` | Versions could not be parsed reliably. |
| `[lang]` | Trivy classified the package as a language dependency. |
| `(no fix available)` | No fixed version is available for an ordinary fix status. |
| `⬆️ escalated to ACT NOW/WATCH` | A known package's maximum priority increased. |
| `new: CVE-…, CVE-… (+N more)` | Added CVEs are linked, with up to 3 per line and the remainder shown as a count. |
| `fix now available` | No fix was previously available, and at least 1 fix is now available. |
| `(end-of-life: no fix planned for this release)` | The selected CVEs are out of support for this release. |
| `🚨 see Act now` | The EOL package's details appear in Act now. |
| `includes N end-of-life package(s)` | Count of EOL groups folded into the base-OS line. |
| `includes N newly end-of-life package(s)` | Count of newly EOL packages other than Act now folded into a new EOL base. |
| `N package(s) newly end-of-life (base OS already EOL)` | Count of newly EOL packages other than Act now under an existing EOL base. |
| `N end-of-life package(s) with new CVEs (base OS already EOL)` | EOL packages other than Act now under an existing EOL base gained CVEs. |
| `no longer end-of-life` | Ordinary findings remain after EOL clears. |

| Evidence or reference label | Meaning |
| --- | --- |
| `CISA KEV (exploited in the wild)` | Listed in the usable KEV catalog. |
| `EPSS N%` | EPSS probability; missing scores use `n/a`, very small values use `<0.1%`, and very large values use `>99%`. |
| `🧨 ransomware campaign` | CISA identifies known use in ransomware campaigns. |
| `severity only (intel unavailable)` | Neither source is usable, so only severity is used. |
| `no fix yet, consider mitigation` | An `affected` group has no fix, so mitigation should be considered. |
| `upstream won't fix, consider replacing` | The group is `will_not_fix`, so replacement or another response should be considered. |
| `end-of-life: no fix planned for this release, consider a supported version` | A supported version should be considered for the EOL package. |
| `📎 advisory` | Trivy's primary advisory. |
| `vendor advisory` | A vendor or CISA reference from KEV notes. |
| `💬 HN (N pts)` | A qualifying Hacker News discussion and its point count. |

### Details and threads

Act now shows evidence for the strongest CVE, while Watch uses a compact display. In the channel, other CVEs are summarized as `(+N more CVE(s) in this package)`.

Changes outside Act now include `CVE-ID · KEV/EPSS`, or `CVE-ID SEVERITY` when intelligence is unavailable. Lines listing new IDs omit this suffix.

CVE IDs in evidence, Watch reasons, and `also:` lists link to NVD. Other identifiers, such as GHSA and DLA IDs, appear as plain text.

Threads show the strongest CVE's title, evidence, URLs, and age. Up to 8 other IDs appear after `also:`, with the remainder summarized as `(+N more)`.

On the day of detection, the age reads `first seen today`. Long reports are split into multiple replies, and continued headings receive `(cont.)`.

The following settings configure delivery methods and destinations.

- `notify.slack_webhook_url` supports channel notifications only.
- `slack_bot_token` (`notify.slack_bot_token`) enables Bot delivery and, together with `slack_channel`, supports thread reports and links to the previous report.
- `slack_channel` (`notify.slack_channel`) selects the Bot's destination channel.

The Bot posts current state in a thread when findings change or the weekly report is due, and links to the latest report on unchanged days. It also creates a new thread on the first notification, after a channel change, or when no valid previous permalink exists.

A typical unchanged-day message is:

```text
No changes since last scan.
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
_Details in the generic webhook payload, or in the weekly full report._
🔗 Last full report → thread
```

An Act now evidence line reads as follows:

```text
↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
```

??? note "Technical details"

    - Slack uses plain `mrkdwn` text.
    - The strongest CVE is selected by priority, whether an EPSS score is known, higher EPSS, and then CVE ID.
    - Slack API calls are attempted up to 3 times.
    - A new thread reference is saved only after the report finishes posting.

## 7. Generic webhook

The generic webhook provides the complete current report as structured JSON. It sends to `notify.generic_webhook_url` only when a cycle meets the notification conditions and includes changes in `diff` mode.

The payload includes Low findings, EOL packages folded in Slack, containers, and workloads. It can be used alongside either Slack delivery method, but it does not convert the payload into a Discord- or Teams-specific message format.

The top-level `watch` array is a fix-status section, separate from the Watch priority. `not_affected` is excluded from every finding section.

### Top-level fields and environment

Top-level fields provide the scan time, environment, findings by fix status, failures, and changes. `environment` is always present; only `name` is omitted when no environment name is configured.

| Field | Type | Meaning |
| --- | --- | --- |
| `generated_at` | string | Scan time in RFC 3339 format. |
| `environment` | object | Adapter kind and optional environment name. |
| `environment.kind` | string | `docker` or `kubernetes`. |
| `environment.name` | string | Configured `environment.name`; omitted when unset. |
| `summary` | object | Counts and intelligence status. |
| `eosl_images` | array of strings or `null` | EOL base images; may be `null` when none. |
| `actionable` | array of image objects | Current `fixed` groups. |
| `watch` | array of image objects | Current groups normalized to `affected`. |
| `wont_fix` | array of image objects | Current `will_not_fix` groups. |
| `eol_packages` | array of image objects | All `end_of_life` groups; `[]` when empty. |
| `scan_errors` | array of objects | Per-image scan failures. |
| `scan_errors[].image` | string | Image reference. |
| `scan_errors[].error` | string | Error details. |
| `diff` | object | Current changes; omitted in full mode. |

### Summary

`summary` provides image counts and, when triage is enabled, priority counts and intelligence status.

`priority_counts` includes EOL packages only when they are Act now. Its counts can therefore overlap with `eol_packages`, and the sum of its 3 values is not necessarily the total number of groups.

| `summary` field | Type | Meaning |
| --- | --- | --- |
| `images_total` | integer | Distinct reference-and-identity pairs, including failed scans. |
| `images_affected` | integer | Images with a selected vulnerability or an EOL base OS. |
| `priority_counts` | object | Integer package-group counts named `act_now`, `watch`, and `low`; present only with triage. |
| `intel` | object | Intelligence availability and freshness; present only with triage. |
| `intel.degraded` | boolean | Whether neither intelligence source is usable. |
| `intel.kev_ok` | boolean | Whether KEV data is usable. |
| `intel.epss_ok` | boolean | Whether EPSS data is usable. |
| `intel.stale_days` | integer | Age in days of stale intelligence data in use. |

### Images and containers

Each entry in `actionable`, `watch`, `wont_fix`, and `eol_packages` represents a reference and identity within that fix-status section. Even for an ambiguous reference, `containers` includes only containers matching that identity.

`registry_digests` is the union for the reference, while `identity_resolved` describes the individual entry.

| Field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Display reference. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `findings` | array of finding objects | Package groups for this image and fix status. |
| `containers` | array of container objects | Matching running containers; `[]` when none. |
| `content_id` | string | `sha256:<hex>` from a confirmed Docker config-digest scan; omitted for registry-digest and reference scans. |
| `registry_digests` | array of strings | Union of `RepoDigests` for the reference from successful confirmed scans; never `null`. |
| `identity_resolved` | boolean | Whether this scan confirmed the running image's identity. |
| `scan_target_kind` | string | `content_id`, `registry_digest`, or `reference`. |
| `containers[].name` | string | Docker container name with the leading slash removed and link aliases excluded, or `<namespace>/<pod>/<container>` in Kubernetes. |
| `containers[].workload` | object | Workload association, always present. |
| `containers[].workload.kind` | string | `unknown`, `compose`, `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod`; always present. |
| `containers[].workload.group` | string | Compose project or namespace; omitted when unknown. |
| `containers[].workload.name` | string | Compose service, resolved workload name, or bare Pod name; omitted when unknown. |

### Findings and vulnerabilities

`findings` provides package groups, and `vulns` provides individual vulnerabilities. The `priority` field in both findings and vulnerabilities is omitted when triage is disabled.

When `vulns[].status` is omitted, it has the same value as the finding's `status`.

| Finding field | Type | Meaning |
| --- | --- | --- |
| `package` | string | Package name. |
| `installed` | string | Installed version. |
| `fixed` | string | Fixed version, or `""` when none is available. |
| `status` | string | `fixed`, `affected`, `will_not_fix`, or `end_of_life`. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `upgrade_risk` | string | `""`, `distro_update`, `safe`, `caution`, or `unknown`. |
| `priority` | string | `act_now`, `watch`, or `low`. |
| `vuln_ids` | array of strings | Sorted vulnerability IDs. |
| `vulns` | array of vulnerability objects | Per-vulnerability details. |

| Vulnerability field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Vulnerability ID without Slack link markup. |
| `severity` | string | Trivy severity. |
| `status` | string | Original Trivy status, included only when it differs from the canonical group status; a missing original `Status` is represented as `unknown`. |
| `url` | string | Primary advisory URL; omitted when unavailable. |
| `title` | string | Short title supplied by Trivy; omitted when unavailable. |
| `kev` | boolean | Whether the vulnerability is in the usable KEV catalog. |
| `ransomware` | boolean | KEV ransomware-campaign flag; omitted when `false`. |
| `epss` | number or `null` | EPSS probability; `null` when unknown. |
| `priority` | string | `act_now`, `watch`, or `low`. |
| `refs` | array of reference objects | Additional references; omitted when empty. |
| `refs[].kind` | string | `vendor` or `discussion`. |
| `refs[].label` | string | Display label. |
| `refs[].url` | string | Reference URL. |

### Diff

`diff` provides changes since the previous scan by type. It is present only in diff mode, and empty arrays are returned as `[]` rather than `null`.

| `diff` field | Type | Meaning |
| --- | --- | --- |
| `new` | array of change objects | New or changed ordinary findings. |
| `resolved` | array of objects | Resolved combinations. |
| `resolved[].image` | string | Image reference. |
| `resolved[].package` | string | Package name. |
| `replaced` | array of replacement objects | References whose verified content-ID sets changed. |
| `new_eosl` | array of strings | Newly detected EOL base-image references. |
| `resolved_eosl` | array of strings | References no longer recorded as EOL. |
| `new_eol_packages` | array of EOL change objects | New or changed EOL findings, including those folded in Slack. |
| `resolved_eol_packages` | array of EOL resolution objects | Packages that left the EOL section. |
| `oldest_open_days` | integer | Whole days since the earliest included first-seen date across all ordinary packages, EOL base images, unfolded EOL packages, and folded Act now EOL packages; fractional days are rounded down. |

`oldest_open_days` includes retained records and ordinary Low findings, so its scope differs from the Slack age when triage is enabled. EOL packages use their first-seen-as-EOL date, while folded EOL packages other than Act now use the base OS's first-seen-as-EOL date.

| `new[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `new`, `escalated`, `new_cves`, or `now_fixable`. |
| `new_cve_count` | integer | Added CVE count; included only for `new_cves`. |
| `new_cve_ids` | array of strings | Added IDs without Slack link markup, included only for `new_cves`; the length matches `new_cve_count`. |
| `critical` | integer | CRITICAL count. |
| `high` | integer | HIGH count. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when unavailable. |
| `reason` | string | Plain-text evidence for an escalation; omitted otherwise. |

| `new_eol_packages[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `eol_new` for newly detected EOL, `eol_new_cves` for added CVEs, or `eol_escalated` for escalation to Act now. |
| `new_cve_ids` | array of strings | Sorted added EOL IDs without Slack link markup; included only for `eol_new_cves`. |
| `critical` | integer | CRITICAL count across current EOL groups. |
| `high` | integer | HIGH count across current EOL groups. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `reason` | string | Evidence included only for `eol_escalated`. |

EOL changes have no `new_cve_count` field. Use the length of `new_cve_ids` to obtain the added count.

| `resolved_eol_packages[]` field | Type | Meaning |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `still_open` | boolean | `true` when ordinary findings remain for the same reference and package; present even when `false`. |

| `replaced[]` field | Type | Meaning |
| --- | --- | --- |
| `ref` | string | Image reference. |
| `prev_content_ids` | array of strings | Sorted previous verified content-ID set. |
| `content_ids` | array of strings | Sorted current verified content-ID set. |

### Backward compatibility

Existing fields and the structure organized by fix status are preserved. Fix-status sections and `priority` are handled separately.

- `actionable` represents `fixed`.
- `watch` represents groups normalized to `affected`.
- `wont_fix` represents `will_not_fix`.
- `eol_packages` represents `end_of_life`.

`diff.new[].kind` remains `new`, `escalated`, `new_cves`, or `now_fixable`.

EOL changes use separate arrays and `kind` values. `diff.new_eol_packages` and `diff.resolved_eol_packages` return `[]` even when empty. EOL support preserves existing fields and adds new arrays and the optional `vulns[].status` field.

## 8. Triage disabled

With `triage.enabled: false`, priority classification stops, and Slack shows results by fix status. KEV, EPSS, and discussion-link lookups also stop.

Slack uses this order: EOL base → EOL package → fix available → waiting for an upstream fix → upstream will not fix. EOL sections and folding into the base OS work as they do with triage enabled. The waiting-for-an-upstream-fix section includes `affected`, `fix_deferred`, `under_investigation`, and `unknown`.

Open now starts with EOL counts, including retained records. The following CRITICAL, HIGH, and affected-image counts come from current findings. If there are no current findings and only retained records remain, the same holding display is used as with triage enabled.

New, New CVEs, Now fixable, Resolved, newly detected EOL, new EOL CVEs, and EOL clearances are still detected. Ordinary priority escalations and EOL package escalations to Act now are not detected.
