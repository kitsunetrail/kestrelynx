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
Docker host or Kubernetes cluster
    │
    ▼
Discover running containers
    │
    ▼
Derive distinct images by identity
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

The Docker adapter calls `GET /containers/json` through the configured Docker
socket. It reads each running container's image reference (`Image`), image
config digest (`ImageID`), name (`Names`), and labels (`Labels`). A config digest
is accepted only in the form `sha256:` followed by 64 hexadecimal digits.

The container name comes from `Names`, with the leading slash removed and link
aliases excluded. When both `com.docker.compose.project` and
`com.docker.compose.service` labels are present and valid, they identify the
container's workload as a Compose project and service. Otherwise, the workload
is `unknown`.

Distinct images are derived from the running containers by reference and
identity, then sorted. Ten containers using the same reference and digest
produce one image entry. One reference running two different digests produces
two entries.

One KestreLynx instance monitors one Docker host or one Kubernetes cluster.
Stopped containers and images that are present on disk but not used by a
running container are outside the scan scope.

If KestreLynx cannot list the running containers, the cycle ends without
changing the saved state. A later scheduled cycle will try again.

### Kubernetes discovery

With `kubernetes.enabled: true`, the Kubernetes adapter makes paginated,
read-only LIST requests for nodes, pods, replicasets, and jobs. Nodes are always
listed cluster-wide. Pods, replicasets, and jobs are listed across all
namespaces, or separately in each namespace selected by
`kubernetes.namespaces`.

The adapter includes containers whose status has `state.running`, including
native sidecars: init containers with `restartPolicy: Always` that are currently
running. Ordinary init containers and ephemeral containers are excluded.
Container names use the form `<namespace>/<pod>/<container>`.

The image reference comes from `containerStatus.image`. A registry digest is
read from `containerStatus.imageID` in the form `<repo>@sha256:<hex>`, optionally
prefixed with `docker-pullable://`. The platform comes from the node's
`status.nodeInfo.operatingSystem` and `architecture`; no variant is inferred.
A bare `sha256:...` image ID does not establish a registry identity and falls
back to a reference scan.

Workloads are resolved through `ownerReferences`:

| Owner chain | Workload |
| --- | --- |
| Pod → ReplicaSet → Deployment | Deployment |
| Pod → StatefulSet | StatefulSet |
| Pod → DaemonSet | DaemonSet |
| Pod → Job → CronJob | CronJob |
| Pod → Job without a parent owner | Job |
| Pod without an owner | Pod |
| Unresolved or unsupported chain | `unknown` |

Container and workload context is included only in the generic webhook payload,
not in Slack.

LIST requests use pages of up to 500 objects. Transport errors, HTTP 429, and
server errors are retried up to three times with exponential backoff, honoring
`Retry-After`. HTTP 410 restarts a list up to twice. The ServiceAccount token and
CA are read each cycle, and the token is read again after HTTP 401. Any LIST
failure fails the whole cycle: partial results are discarded and saved state
does not advance.

### Scan each unique image

KestreLynx runs the Trivy CLI for each distinct image identity and requests JSON
output. The configured `scan.severity` values are passed to Trivy; the default is
`HIGH,CRITICAL`.

The scan target depends on the identity available at discovery:

| Identity | Scan target |
| --- | --- |
| Docker config digest | Local Docker image selected by config digest with `--image-src docker`. |
| Kubernetes registry digest and known platform | Registry image selected by digest with `--image-src remote` and `--platform`. |
| Unresolved identity | Image reference fallback. |

The three invocation shapes are:

```text
trivy image --quiet --format json --severity <list> --image-src docker sha256:<config-digest>
trivy image --quiet --format json --severity <list> --image-src remote --platform <os>/<arch> <repo>@sha256:<hex>
trivy image --quiet --format json --severity <list> <ref>
```

After a digest-targeted scan, KestreLynx verifies the returned metadata. For a
Docker scan, `Metadata.ImageID` must match the requested config digest. For a
registry scan, the requested digest must appear in `Metadata.RepoDigests`, and
`Metadata.ImageConfig` must match the requested OS and architecture. A mismatch
is reported as a scan failure rather than attributed to the running image.

When several references identify the same content, a scan is shared across
those aliases only after it successfully pins the identity. After a failed or
unpinned scan, the next alias is scanned again.
Registry identities include the platform, so different
platforms are not treated as the same image. Reference scans are annotated
`identity unconfirmed: scanned by reference`.
For reference-level Slack labels and the summary, a reference is confirmed only when
every entity under it was identified by a Docker config digest at discovery, regardless
of scan results. Kubernetes registry digests count as unconfirmed in this check.

An error for one image does not cancel the other image scans. It is included in
the notification under **Scan failures**. Previous findings for that image are
carried forward in state for the cycle, because treating an unscanned image as
clean would create false “resolved” findings.

If a reference runs several identities and only some scans fail, previous
findings are retained with `content_id` cleared. Overlapping previous and
current findings are merged conservatively: CVE IDs are combined, fix
availability is retained if either result reports a fix, and the higher
priority is kept. Resolution is deferred for that reference.

In Kubernetes mode, a successful reference scan also holds previous findings
because it cannot confirm the running image's identity. Slack reports
`⏳ unconfirmed this cycle, holding previous findings — <refs>`. A notification
is sent when the unconfirmed reference has previously recorded package findings
being held, even if nothing changed. Retained EOL history alone does not trigger
this notification.

### Build package-level findings

Raw Trivy rows are normalized into package groups. The primary unit shown in
notifications is:

```text
(image reference + identity) + package + Trivy status
```

All selected CVEs for that unit are deduplicated and collected together. The
group contains the installed version, fixed version when available, CRITICAL
and HIGH counts, references, and the strongest priority among its CVEs.

A package can appear in more than one status group when, for example, one CVE
has a fix while another CVE in the same package does not.

When one tag refers to two running digests, Slack distinguishes the entries
with a short digest suffix, such as `web:1.0 (3f2a9c1b7d4e)` or
`web:1.0 (3f2a9c1b7d4e linux/amd64)`. State and diff keys remain image reference
plus package.

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
Docker volume, or a persistent volume in Kubernetes.

For each image and package, state records:

- when it was first seen,
- the set of CVE IDs,
- whether any fix is available,
- the package's previous maximum priority, and
- `content_id`, the config digest of a single verified identity, left blank
  when the reference is ambiguous or partially failed.

The top-level `images` map is keyed by reference and records sorted
`content_ids`, `registry_digests`, `ambiguous`, and `last_seen`. When
`environment.name` is set, an `environment` object records its `name` and
adapter-derived `kind`.

These fields were added without changing the state-format version, which
remains `1`. Older state files load without conversion. Naming, renaming, or
removing the environment name does not change history keys, reset first-seen
dates, or re-notify existing findings. One state file holds one environment;
two instances must not share it.

EOL first-seen dates and the reference to the most recent Slack full-report
thread are stored separately. State writes use a temporary file followed by an
atomic rename.

### What counts as a change

Current and previous package state are compared in the following precedence
order. Image replacements are detected independently:

| Change | Condition |
| --- | --- |
| New | The image-and-package key was not in the previous state. |
| Escalated | A known package's maximum priority increased, for example Watch → Act now. |
| New CVEs | The known package gained one or more CVE IDs. |
| Now fixable | The known package had no fix before and has at least one fix now. |
| Resolved | A previously stored image-and-package key is absent from a successful current scan. |
| Replaced | A reference's verified content-ID sets are non-empty in both cycles and differ. Shown as `🔄 Image content changed`. |

Only the highest-precedence package reason is shown when several conditions
become true in the same cycle. Priority decreases are silent, but the new lower
priority is saved and can be used as the baseline for a later escalation.
Escalation requires a stored priority and is suppressed during degraded triage.

Replaced is an image-level change, independent of package-level precedence. It
can appear alongside package changes and triggers a notification even for a
clean image. The first observation of an identity is not a replacement.

“Resolved” means that the finding is no longer in KestreLynx's current scope.
Possible causes include installing a fix, changing the image, stopping the
container, changing the selected severity levels, or a scanner-data change. It
does not by itself prove that a patch was installed. Fully failed, partially
failed, and unconfirmed Kubernetes references do not produce resolutions.

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
| Image content changed | Send the replacement, even if the image is clean. |
| Kubernetes reference scan is unconfirmed and previously recorded package findings for that reference are held | Send the holding status, even if nothing changed. Retained EOL history alone does not trigger this notification. |

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
6. Identity-unconfirmed and previous-findings-held annotations, when applicable

Act-now references can include Trivy's primary advisory, a vendor advisory from
KEV notes, and an optional Hacker News discussion. Low details are intentionally
omitted from Slack; the structured generic webhook carries the full list.

CVE IDs in Slack evidence lines, Watch reasons, and thread `also:` lists are
links to their NVD records. The examples below show the visible IDs without link
markup. Other identifiers, such as GHSA or DLA IDs, remain plain text.

### Common header

Every Slack channel notification starts with the scan time and two image counts:

```text
🛡️ *KestreLynx* — scan results for 2026-08-16 09:00
4 images scanned, 3 affected
```

With `environment.name: prod-vps`, the header becomes:

```text
🛡️ *KestreLynx* [prod-vps] — scan results for 2026-08-16 09:00
4 images scanned, 3 affected
```

The environment name appears only in the channel header, not in the thread.

- `images scanned` is the number of distinct reference-and-identity pairs
  discovered in the cycle, including images whose scan failed. One reference
  running two digests counts twice; two references sharing one scan also count
  twice.
- `affected` is the number of distinct images with a selected vulnerability or
  an EOL base OS. An image with only a scan failure is not counted as affected;
  it appears under **Scan failures** instead.
- The time is formatted in the process's local timezone. In the container, this
  is controlled by the `TZ` environment variable.

### Diff notification in the channel

The default channel message is a change report, not a copy of the current full
report. Its sections appear in this order when applicable:

1. Common header
2. Image content changed
3. Newly detected EOL base images
4. Vulnerability-intelligence warning
5. New or changed packages
6. Resolved EOL images and packages
7. Weekly current-state report, or scan failures and the **Open now** line
8. Identity-unconfirmed and previous-findings-held annotations
9. Bot-only link to the report in this message's thread or the previous report

An abbreviated example is:

```text
🛡️ *KestreLynx* — scan results for 2026-08-16 09:00
4 images scanned, 3 affected

*🔄 Image content changed (1)*
• ghcr.io/example/worker:latest: image updated (111111111111 → 222222222222)

*🆕 New since last scan (1)*
🚨 ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch — ⬆️ escalated to ACT NOW
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%

*✅ Resolved since last scan (1)*
• ghcr.io/example/worker:latest: libxml2

📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low — oldest act-now/watch unresolved 4 day(s)
_Details in the generic webhook payload, or in the weekly full report._

_📊 Full report in this message's thread ↓_
```

The number in `New since last scan (N)` is the number of changed
image-and-package entries, not the number of CVEs. New and changed entries are
sorted by priority first, then image and package name.

If nothing changed, the body becomes:

```text
No changes since last scan.
📌 Open now: 🚨 1 act-now / 👀 2 watch / 🔕 8 low
_Details in the generic webhook payload, or in the weekly full report._
🔗 Last full report → thread
```

Scan failures and identity annotations are included when applicable. When EOL
images remain open, the **Open now** counts start with `⛔ N EOL base`.

If nothing remains open, the **Open now** line is instead:

```text
🎉 Open now: none — all clear
```

If the current report contains any findings or EOL images, normal counts are
shown. If previous findings are held after an unconfirmed Kubernetes scan and
the current report has no findings or EOL images at all, it reads:

```text
📌 Open now: unconfirmed — holding previous findings until re-confirmed
```

### Current-state report layout

Full mode, the weekly report in a diff notification, and the Bot API thread all
represent what is open at the time of the current scan. The channel version has
the following shape:

```text
*Priority:* ⛔ 1 EOL base · 🚨 1 act now · 👀 2 watch · 🔕 8 low

*⛔ Base OS end-of-life (top priority)*
• ghcr.io/example/legacy:latest — base OS is EOL (no more security updates coming)

*🚨 Act now (1) — exploited or likely to be*
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
       📎 advisory · vendor advisory · 💬 HN (120 pts)

*👀 Watch (2) — not urgent, keep an eye on*
• ghcr.io/example/frontend:latest
   • zlib 1.2.13 (no fix available) (CRITICAL 1 / HIGH 0) — CVE-2026-23456 · EPSS 0.4%

*🔕 Low priority (8)* — 8 finding(s) across 3 image(s), no exploitation signal (not in KEV, EPSS below threshold).
_Details in the generic webhook payload or the weekly full report._
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
| `new: CVE-…, CVE-… (+N more)` | New CVE IDs appeared under a known image and package, linked, up to 3 listed per line and the rest counted. |
| `fix now available` | A known package changed from no available fix to at least one available fix. |

The green upgrade icon describes the proposed version change. It does **not**
mean that the image, package, or vulnerability is safe.

Every changed entry other than Act now also carries a compact evidence suffix
naming its strongest CVE — `CVE-ID · KEV/EPSS` when triage is on and the intel
behind it is usable, or `CVE-ID SEVERITY` otherwise — so the entry says which
CVE is behind it without a trip to the webhook payload. A line that lists new
CVE IDs omits the compact evidence, since that list is already the headline;
when a package renders as two lines (fixed and unfixed CVEs), each new ID is
listed only under the line it belongs to, and the other line follows the
normal rule.

### Evidence and reference lines

An Act-now package is followed by an evidence line for its strongest CVE:

```text
↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
```

The strongest CVE is selected by priority, then known and higher EPSS, then CVE
ID. If the package contains other CVEs, the channel appends
`(+N more CVE(s) in this package)` instead of expanding each one.

During degraded triage, the evidence line uses:

```text
↳ CVE-2026-12345 CRITICAL · severity only (intel unavailable)
```

Evidence labels mean:

| Label | Meaning |
| --- | --- |
| `CISA KEV (exploited in the wild)` | The CVE is present in the current usable KEV catalog. |
| `EPSS N%` | Current EPSS probability. Missing scores are shown as `n/a`. Very small values use `<0.1%`; very large values use `>99%`. |
| `🧨 ransomware campaign` | CISA marks known use in ransomware campaigns. This is evidence, not a separate priority. |
| `severity only (intel unavailable)` | Neither intelligence source is usable; priority is based on severity. |
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
| `🔄 Image content changed` | A reference's verified content-ID set changed; independent of package changes and possible for clean images. |
| `🆕 New since last scan` | Contains new packages and known packages that changed. |
| `✅ Resolved since last scan` | No longer present in current scope; it does not prove a patch was installed. |
| `📌 Open now` | Compact current backlog counts after applying the latest scan. |
| `📌 Open now: unconfirmed — holding previous findings until re-confirmed` | The current report has no findings or EOL images at all, and previous package findings are being held after an unconfirmed Kubernetes scan. If any current findings or EOL images exist, normal counts are shown. |
| `⏰ oldest ... unresolved` | The oldest EOL/Act-now/Watch item has remained open for at least 14 days. |
| `<ref> — identity unconfirmed: scanned by reference` | At reference level, this label marks references with at least one entity that was not identified by a Docker config digest at discovery, regardless of scan results. Kubernetes registry digests count as unconfirmed in this check. |
| `<ref> (<12hex>)` or `<ref> (<12hex> linux/amd64)` | Short digest and optional platform distinguish multiple identities under one reference. |
| `⚠️ identity unconfirmed: scanned by reference — a, b` | References with at least one entity that was not identified by a Docker config digest at discovery, regardless of scan results. Kubernetes registry digests count as unconfirmed in this check, so the summary can list every Kubernetes reference. |
| `⏳ unconfirmed this cycle, holding previous findings — a, b` | Kubernetes references with at least one entity whose remote scan succeeded this cycle but could not pin its identity. Scan failures alone do not qualify. This line appears regardless of whether previous findings exist, including on a first run with no history. |
| `⚠️ Scan failures` | Images that could not be scanned in this cycle, including digest or platform verification failures. |
| `⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low` | Neither exploitation-intelligence source is usable. |
| `⚠️ CISA KEV data unavailable — act-now detection may be incomplete` | KEV is unavailable; triage uses EPSS and severity. |
| `⚠️ EPSS data unavailable — triage is using KEV and severity only` | EPSS is unavailable; triage uses KEV and severity. |
| `_Intel data is N day(s) old (feeds unreachable)._` | A validated stale cache is being used because refresh failed. |
| `📋 Weekly full report` | The current-state view appended on the configured weekday. |
| `📊 Full report in this message's thread` | The Bot API posted current-state replies below this channel message. |
| `🔗 Last full report` | No new thread was needed; follow the link to the last successful report. |

`✅ Actionable now (fixed)` appears only in the triage-disabled layout. In that
label, “actionable” means that a fix version exists. It is not the same as the
triage priority **Act now**.

### Slack thread format

The Bot API thread starts with `📊 *Full report — YYYY-MM-DD HH:MM*`, followed by
EOL, ACT NOW, WATCH, and LOW sections. Act-now and Watch packages are expanded:

```text
📊 *Full report — 2026-08-16 09:00*

*🚨 ACT NOW (1) — exploited or likely to be*
• ghcr.io/example/api:latest
   • openssl 3.0.13 → 3.0.14 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch
     ↳ CVE-2026-12345 CRITICAL · CISA KEV (exploited in the wild) · EPSS 12%
       Short title supplied by Trivy
       📎 advisory · vendor advisory · 💬 HN (120 pts)
     also: CVE-2026-20001, CVE-2026-20002
     ⏱ open 4 day(s) — first seen 2026-08-12

*🔕 LOW (8)* — no exploitation signal; details in the weekly full report or the webhook payload
```

Only the strongest CVE receives a full evidence line and title. Up to eight
additional CVE IDs are displayed after `also:`; the rest become `(+N more)`.
`first seen today` is shown instead of an age on day zero. If the report exceeds
the message-size budget, it is split into consecutive replies and continued
section headings receive `(cont.)`.

When applicable, the thread ends with the same identity-unconfirmed summary:

```text
⚠️ identity unconfirmed: scanned by reference — legacy:1
```

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
summary counts, environment, EOL images, fix-status sections, image identities,
containers and workloads, package versions, upgrade-risk and priority values,
CVE IDs and evidence, scan failures, and—when diff mode is active—the current
diff. Container and workload context appears only in this payload, not in
Slack.

### Top-level fields

| JSON field | Type | Contents |
| --- | --- | --- |
| `generated_at` | string | Scan time in RFC 3339 format. |
| `environment` | object | Always present; adapter kind and optional environment name. |
| `summary` | object | Image counts, plus priority counts and intelligence freshness when triage is enabled. |
| `eosl_images` | array of strings or `null` | Images whose base OS is EOL; may be `null` when none. |
| `actionable` | array of image objects | Current package groups with Trivy status `fixed`. |
| `watch` | array of image objects | Current package groups with Trivy status `affected`. |
| `wont_fix` | array of image objects | Current package groups with Trivy status `will_not_fix`. |
| `scan_errors` | array of objects | Per-image failures, each with string fields `image` and `error`. |
| `diff` | object | Changes since the previous scan. Omitted in full mode. |

### Environment

| JSON field | Type | Contents |
| --- | --- | --- |
| `kind` | string | `docker` or `kubernetes`, derived from the active adapter. |
| `name` | string | Configured `environment.name`; omitted for the unnamed default. |

### Summary

| JSON field | Type | Contents |
| --- | --- | --- |
| `images_total` | integer | Distinct reference-and-identity pairs, including failed scans. |
| `images_affected` | integer | Images with a selected vulnerability or an EOL base OS. |
| `priority_counts` | object | Present only with triage; integer package-group counts named `act_now`, `watch`, and `low`. |
| `intel` | object | Present only with triage; intelligence availability and freshness. |
| `intel.degraded` | boolean | Neither intelligence source is usable. |
| `intel.kev_ok` | boolean | KEV data is usable. |
| `intel.epss_ok` | boolean | EPSS data is usable. |
| `intel.stale_days` | integer | Age in days of stale intelligence data in use. |

### Image object

Each entry in `actionable`, `watch`, and `wont_fix` represents an image reference
and identity within that fix-status section.

| JSON field | Type | Contents |
| --- | --- | --- |
| `image` | string | Display reference. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `findings` | array of finding objects | Package groups for this image and fix status. |
| `containers` | array of container objects | Running containers matching this image identity; an empty array, never `null`, when none. |
| `content_id` | string | `sha256:<hex>` config digest for a confirmed Docker config-digest scan. Omitted for registry-digest and reference scans. |
| `registry_digests` | array of strings | Union of Trivy `RepoDigests` for the reference, from successful confirmed scans only. Never `null`. |
| `identity_resolved` | boolean | Whether this entry's scan confirmed the running image identity. |
| `scan_target_kind` | string | `content_id`, `registry_digest`, or `reference`. |

Container and workload fields are:

| JSON field | Type | Contents |
| --- | --- | --- |
| `containers[].name` | string | Docker container name with the leading slash removed and link aliases excluded, or `<namespace>/<pod>/<container>` in Kubernetes. |
| `containers[].workload` | object | Workload association, always present. |
| `containers[].workload.kind` | string | `unknown`, `compose`, `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, or `pod`. Always present. |
| `containers[].workload.group` | string | Compose project or Kubernetes namespace. Omitted when unknown. |
| `containers[].workload.name` | string | Compose service, resolved Kubernetes workload name, or bare Pod name. Omitted when unknown. |

For an ambiguous reference, each image entry lists only its own matching
containers. `registry_digests` is the union for the reference, while
`identity_resolved` describes the individual entry.

### Finding

| JSON field | Type | Contents |
| --- | --- | --- |
| `package` | string | Package name. |
| `installed` | string | Installed version. |
| `fixed` | string | Fixed version, or `""` when none is available. |
| `status` | string | `fixed`, `affected`, or `will_not_fix`. |
| `severity_counts` | object | Integer counts named `CRITICAL` and `HIGH`. |
| `upgrade_risk` | string | `""`, `distro_update`, `safe`, `caution`, or `unknown`. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `vuln_ids` | array of strings | Sorted vulnerability IDs. |
| `vulns` | array of vulnerability objects | Per-vulnerability details. |

### Vulnerability

Each object in `vulns` has these fields:

| JSON field | Type | Contents |
| --- | --- | --- |
| `id` | string | Vulnerability ID, without Slack link markup. |
| `severity` | string | Trivy severity. |
| `url` | string | Primary advisory URL; omitted when unavailable. |
| `title` | string | Short title supplied by Trivy; omitted when unavailable. |
| `kev` | boolean | Whether the vulnerability is in the usable KEV catalog. |
| `ransomware` | boolean | KEV ransomware-campaign flag; omitted when false. |
| `epss` | number or `null` | EPSS probability; `null` when no score is known. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when triage is disabled. |
| `refs` | array of reference objects | Additional references; omitted when empty. |
| `refs[].kind` | string | `vendor` or `discussion`. |
| `refs[].label` | string | Display label. |
| `refs[].url` | string | Reference URL. |

### Diff

The `diff` object is present only in diff mode. Its arrays are `[]`, not `null`,
when empty.

| JSON field | Type | Contents |
| --- | --- | --- |
| `new` | array of change objects | New or changed image-and-package entries. |
| `resolved` | array of objects | Resolved entries, each with string fields `image` and `package`. |
| `replaced` | array of replacement objects | References whose verified content-ID sets changed. |
| `new_eosl` | array of strings | Newly detected EOL image references. |
| `resolved_eosl` | array of strings | Image references no longer recorded as EOL. |
| `oldest_open_days` | integer | Age in whole days from the earliest first-seen date across all retained package findings, including Low, and all retained EOL images. Unlike this field, the Slack heartbeat age excludes Low when triage is enabled. |

Each object in `new` has these fields:

| JSON field | Type | Contents |
| --- | --- | --- |
| `image` | string | Image reference. |
| `package` | string | Package name. |
| `kind` | string | `new`, `escalated`, `new_cves`, or `now_fixable`. |
| `new_cve_count` | integer | Number of added CVE IDs, populated only when `kind` is `new_cves`. Omitted for other kinds even if CVE IDs were added. |
| `new_cve_ids` | array of strings | The added CVE IDs themselves, without Slack link markup. Populated only when `kind` is `new_cves`, same count as `new_cve_count`. |
| `critical` | integer | CRITICAL count. |
| `high` | integer | HIGH count. |
| `priority` | string | `act_now`, `watch`, or `low`; omitted when unavailable. |
| `reason` | string | Plain-text evidence for an escalation; omitted otherwise. |

Each object in `replaced` has these fields:

| JSON field | Type | Contents |
| --- | --- | --- |
| `ref` | string | Image reference. |
| `prev_content_ids` | array of strings | Sorted previous verified content-ID set. |
| `content_ids` | array of strings | Sorted current verified content-ID set. |

For compatibility, the top-level finding sections use fix status:
`actionable` means Trivy status `fixed`, `watch` means status `affected`, and
`wont_fix` means `will_not_fix`. These names are independent of each package's
triage `priority` field. In particular, the webhook's top-level `watch` array is
not the same thing as the triage priority **Watch**.

The full payload is attached only to cycles that meet the notification rules
above. A clean, unchanged cycle skipped by `notify_on_clean: false` does not
call the webhook. Image replacements and Kubernetes cycles holding previously
recorded package findings for an unconfirmed reference still meet the notification
rules. Retained EOL history alone does not trigger the holding notification.

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
