---
title: Reading Slack warnings
---

# Reading Slack warnings

Warnings identify information that was unavailable when checking vulnerabilities, determining priority, or observing runtime usage.
The following table lists their scope and location.

| Type | What it reports | Location |
| --- | --- | --- |
| [Scan](#scan-warnings) | Images or runtimes whose vulnerabilities could not be checked | Later in the full report, or at the end of the diff report |
| [Threat intelligence](#intel-warnings) | Missing or old information used to determine priority | Source warnings before findings; the age note later in the full report |
| [Sensor](#sensor-warnings) | Problems with runtime usage observation | Immediately after the channel notification header |

## Scan warnings {#scan-warnings}

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
- To check whether scanning used an image name, see `identity_resolved` and `scan_target_kind` under the webhook's [Image elements](webhook-reference.md#image-identity)

An image absent from this list may still have previous findings retained because its scan failed.
See [Failed scans](scan-logic.md#scan-failures) for how results are retained.

The unchecked-runtime note identifies the skipped targets as follows.

- The name is `Node.js` or `Python runtime` as applicable, or `Node.js, Python runtime` when both are affected
- N counts distinct image names whose runtimes were not checked

See [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable) for when matching is skipped and how previous findings are handled.

### Images that could not be scanned {#scan-failure-causes}

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

## Threat intelligence warnings {#intel-warnings}

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

See [Full report order](slack-display.md#current-order) for placement and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for the effect on decisions.

## Sensor warnings {#sensor-warnings}

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

See [Usage labels](slack-runtime-display.md#usage-labels) for individual package displays and [Runtime usage](runtime-usage.md) for observation methods and limits.
