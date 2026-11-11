---
title: Slack runtime usage display
---

# Slack runtime usage display

When Sensor information is available, packages show runtime usage.
Sensor observes whether packages are being used in running containers.

See [Runtime usage](runtime-usage.md) for usage decisions and observation limits.

## Usage labels {#usage-labels}

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

## Runtime evidence {#runtime-evidence}

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

## Muted findings {#muted-display}

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

When a package's notifications resume alongside another change, such as a newly available fix or increased priority, KestreLynx gives precedence to [that change's display](slack-package-display.md#package-change-labels).

See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions and reasons notifications resume.
