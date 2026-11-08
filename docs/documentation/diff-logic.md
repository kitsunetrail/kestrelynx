# Change and history decisions

## Comparison baseline {#comparison-baseline}

Changes are determined by comparing current findings with history saved through previous cycles.
Packages are compared by the combination of image name, including its tag or other components, and package name.

Packages with the same image name and package name are compared together even when they belong to separate [scan result groups](scan-logic.md#package-grouping).
Differences in digest, ecosystem, installed version, or fix status alone do not create separate histories.

Ordinary and EOL findings are recorded separately, so both histories can exist for the same combination.
Whether to send a notification is determined separately by the [Notification conditions](notification-conditions.md#notification-conditions).

## Package changes {#package-changes}

Changes are determined separately for ordinary and EOL findings.
If multiple changes apply on the same side, one reason is selected in precedence order.

### Ordinary package changes {#normal-changes}

The following rules are evaluated in order, and the first matching change is selected.

1. If neither ordinary nor EOL history exists, classify the finding as new
2. If the current maximum priority exceeds the comparison baseline, classify it as a priority escalation
3. If CVE IDs absent from the baseline are added, classify it as added CVEs
4. If the previous ordinary findings contained no `fixed` group and the current findings contain at least one, classify it as newly fixable
5. If the package was previously muted and no longer meets the muting conditions, classify it as unmuted

Priority and CVE comparisons use both the previous ordinary and EOL findings.
The baseline uses the higher priority and the union of CVE IDs from both sides.

- No priority escalation is detected when no priority was saved or the current cycle uses degraded triage
- A priority decrease alone is not a change, and the lower value becomes the baseline for the next cycle once saved
- Moving from EOL back to ordinary findings alone does not count as a new finding or added CVEs

A package that returns from EOL with `fixed` status may qualify as newly fixable.
See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions and reasons for unmuting.

New findings, added CVEs, newly fixable findings, and unmuting are still detected when triage is disabled.
Priority escalations do not occur because no priorities are assigned.

### EOL package changes {#eol-package-changes}

EOL changes use only the previous EOL history as their baseline and are evaluated in the following order.

1. If no previous EOL history exists, classify it as newly detected EOL
2. If the priority rises from the saved EOL priority to Act now, classify it as an escalation to Act now
3. If CVE IDs absent from the previous EOL history are added, classify it as added EOL CVEs

- Newly detected EOL includes moves from ordinary findings and detections after EOL previously cleared
- No escalation to Act now is detected when no priority was saved or the current cycle uses degraded triage
- A rise from Low to Watch or a priority decrease alone does not count as a change

Newly detected EOL and added EOL CVEs are still detected when triage is disabled.

### Resolution decisions {#resolved-findings}

When history does not need to be retained, resolution depends on whether the same combination remains in the current ordinary or EOL findings.

| Previous record | Current state | Decision |
| --- | --- | --- |
| Ordinary findings exist | Remains in ordinary findings | Unresolved |
| Ordinary findings exist | Leaves ordinary findings but remains in EOL findings | Unresolved |
| EOL findings exist | Leaves EOL findings but remains in ordinary findings | EOL cleared; vulnerabilities remain unresolved |
| Ordinary or EOL findings exist | Disappears from both | Resolved |

Removing some CVEs does not resolve a package while findings remain for the same combination.

!!! note "Meaning of resolution"

    Resolution means that findings have left the current scan scope; it does not prove that a patch was installed.
    This includes cases where a previous target is no longer observed because a container stopped or an image name changed.

See [Package changes](slack-display.md#package-change-labels) and [EOL display](slack-display.md#eol-display) for how these distinctions appear.

## Base OS EOL changes {#eol-base-changes}

Base OS EOL is compared by image name.
These changes are independent of package changes.

| Previous record | Current state | Decision |
| --- | --- | --- |
| No EOL record | EOL detected | Newly detected EOL |
| EOL recorded | EOL detected | Ongoing |
| EOL recorded | EOL not detected and history need not be retained | Removed from EOL records |

Removal from EOL records includes cases where the image name leaves the scan scope.
The absence of a base OS EOL record does not mean that individual vulnerabilities are resolved.

## Image digest changes {#image-content-changes}

For each image name, KestreLynx compares the previous and current sets of config digests obtained from Docker.
An image digest change, such as replacement of the content behind `:latest`, is detected when all the following conditions hold.

- The same image name exists in both the previous and current observations
- Both observations contain at least one confirmed config digest
- The two sets differ

The first observation and cases where either set is empty do not qualify.
Kubernetes registry digests alone are not used to detect this image digest change.

This decision is independent of package findings and scan success.
An image digest change is detected whenever the conditions hold, even if there are no findings or the current scan fails.

## Image name updates {#reference-changes}

When KestreLynx can identify an image name update for the same workload, such as `repo:sha-A` to `repo:sha-B`, it carries history over to the new image name.
This transfer occurs before package and EOL diffs are calculated.

### Conditions for transferring history {#transfer-conditions}

All the following conditions must hold.

- The old image name exists in the previous image records and is absent from current observations
- The new image name is currently observed and is absent from the previous image records
- The old and new image names are valid image names in the same repository
- The old image name's records and the new image name's observations share a workload
- The old and new image names have a one-to-one match both per image name and per shared workload
- All scans of the new image name succeed, and a single digest is confirmed across all running containers
- The new image name has no existing finding, EOL, or muting history

Repository comparison ignores tags and digests but distinguishes registry ports.
Docker Hub shorthand is expanded, so `app` and `docker.io/library/app` are treated as the same repository.

Workload matching uses the following information.

| Deployment type | Matching information |
| --- | --- |
| Compose | Project and service |
| Kubernetes | Workload kind, namespace, name, and container name within the Pod |
| Standalone Docker container with no identifiable workload | Container name |

Candidates with failed scans or unconfirmed digests are included when checking for a one-to-one match.
Failed candidates are not excluded to make a remaining candidate the sole transfer destination.

### Transferred history {#transferred-history}

The following history is carried from the old image name to the new image name.

- First-seen dates, CVE IDs, priorities, and fix availability for ordinary findings
- First-seen-as-EOL dates, CVE IDs, and priorities for EOL packages
- The base OS's first-seen-as-EOL date
- Muting history

After the transfer, this history is compared with the new image name's current results.
Added CVEs are handled as ordinary CVE additions, and packages that disappear are resolved under the new image name.

Muting conditions are reassessed using the new image name's current information.
See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for conditions and reasons for unmuting.

### Cases without history transfer {#no-transfer}

History is not carried over as an image name update in cases such as the following.

- Containers using the old and new image names run simultaneously during a rolling update
- A shared image name splits into multiple new image names
- Multiple old image names merge into one new image name
- The new image name has failed scans, partially failed scans, or unconfirmed digests
- Multiple images with different digests are running under the new image name
- Previous records lack workload information, so the match cannot be confirmed

Without a transfer, each image name is compared with its own history.
Findings under a new image name with no history are new, while findings under the old image name are resolved once they leave the scan scope and no longer need to be retained.

## History continuity {#state-lifecycle}

History is compared and updated in `diff` mode.
To maintain comparisons, retain and reuse history for the same environment.

See [Configuration](configuration.md) for storage, persistence, and environment-name handling, and [Getting started](getting-started.md) for deployment instructions.
See [Scan notification redelivery](notification-conditions.md#scan-redelivery) for how delivery success or failure affects saving history and resending notifications.

### History initialization {#state-initialization}

KestreLynx starts without comparable history in the following cases.

- This is the first run
- No history exists
- History cannot be read or is corrupted
- The history format version does not match

Current packages are treated as new findings, and current EOL findings as newly detected EOL.
Read failures and corruption produce log warnings.

Readable older history is not reset solely because additional information is missing.
Missing information affects decisions as follows.

| Missing information | Effect on decisions |
| --- | --- |
| Priority | No priority escalation is detected in that cycle because there is no comparison baseline |
| EOL package records | Current EOL packages are treated as newly detected EOL |
| Image digest information | Current digests are recorded as the comparison baseline |
| Workload records | History is not transferred from that old image name |

### Retained history {#retained-findings}

History retained under the [scan failure rules](scan-logic.md#scan-failures) remains as findings that could not be confirmed in the current cycle.
Retention takes precedence over processing moves between ordinary and EOL findings.

- Findings subject to retention are not confirmed as resolved even if absent from current results
- EOL subject to retention is not confirmed as cleared even if absent from current results
- Retained muting history does not trigger unmuting solely because of a failure in that cycle

Retention does not prevent successful scans from detecting new findings or added CVEs.
Resolution and EOL clearance for retained findings are determined from results that can be confirmed again.
