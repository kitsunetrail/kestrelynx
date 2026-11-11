---
title: Webhook runtime fields
---

# Webhook runtime fields

This page describes the fields in the top-level `runtime` and `findings[].runtime` in the generic webhook payload.
See [Payload overview](webhook-reference.md#payload-overview) for the overall payload structure and [Report fields](webhook-reference.md#report-fields) for table conventions and values shared by several fields.

Runtime fields appear in three places.

| Location | Contents |
| --- | --- |
| Top-level `runtime` | Sensor status and usage counts |
| `findings[].runtime` | Usage for each package group |
| [`runtime_usage` in changes](webhook-diff-reference.md) | Usage for packages with changes |

All of these fields are omitted when runtime usage is disabled.
See [Runtime usage](runtime-usage.md) for assessment methods and observation limits.

## Sensor information {#sensor-fields}

The top-level `runtime` describes Sensor status, the conditions for assessing packages as in use, and usage counts.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `sensor_status` | string | Overall Sensor status | — |
| `heartbeat_at` | string | Time of the latest Sensor report in RFC 3339 format | omitted when no report time is available |
| `interval_seconds` | integer | Sampling interval in seconds | omitted when `0` |
| `rules` | object | Fixed values describing the conditions for assessing packages as in use | — |
| `rules.os_packages` | string | Assessment condition for OS packages | — |
| `rules.lang_packages_binary` | string | Assessment condition for language packages embedded in executables | — |
| `rules.lang_packages_runtime` | string | Assessment condition for language packages loaded by a runtime | — |
| `events_status` | string | Status of event observation through eBPF | `""` when the Sensor report cannot be read |
| `events_reason` | string | Reason event observation through eBPF is unavailable | omitted when no reason is available |
| `counts` | object | [Usage counts](#runtime-counts) | — |

The values of `sensor_status` are as follows.

| Value | Meaning |
| --- | --- |
| `ok` | The Sensor is operating normally |
| `degraded` | Problems such as stalled processing interfere with observation or saving results |
| `stale` | The latest Sensor report is too old to confirm that observations are current |
| `not_reporting` | The file containing Sensor observations does not exist yet |
| `permission_denied` | The Sensor lacks permission to read information such as container process details |
| `evidence_invalid` | KestreLynx cannot read the observations file, or its contents fail validation |
| `isolation_failed` | The Sensor could not restrict operations other than reading and has not started observing |
| `isolation_degraded` | Some restrictions on Sensor operations other than reading are not effective |

The fixed values of the fields in `rules` are as follows.

| Field | Value | Meaning |
| --- | --- | --- |
| `os_packages` | `executed_or_loaded_by_running_process` | Assessed as in use when execution of a package file or its loading as a library was confirmed by a periodic check or an eBPF event |
| `lang_packages_binary` | `in_running_binary` | Assessed as in use when a periodic check found the executable embedding the package running, or eBPF observed it starting |
| `lang_packages_runtime` | `runtime_process_running` | Assessed as in use when a periodic check found a process for the package's corresponding runtime running, or eBPF observed it starting |

`events_status` describes event observation through eBPF separately from `sensor_status`.
Its values are as follows.

| Value | Meaning |
| --- | --- |
| `ok` | Event observation through eBPF is available |
| `unavailable` | Event observation through eBPF is unavailable, so observation uses sampling only |

The values of `events_reason` are as follows.

| Value | Meaning |
| --- | --- |
| `kernel_unsupported` | The kernel does not support event observation |
| `btf_missing` | Kernel type information required for event observation cannot be read |
| `permission` | Permissions required for observation through eBPF are unavailable |
| `attach_failed` | Preparing or starting event observation failed |
| `cgroup_v1` | The host uses a container management mechanism other than the required cgroup v2 |

The following example shows the top-level `runtime` when the Sensor is operating normally.

```json
{
  "sensor_status": "ok",
  "heartbeat_at": "2026-06-24T09:00:00Z",
  "interval_seconds": 30,
  "rules": {
    "os_packages": "executed_or_loaded_by_running_process",
    "lang_packages_binary": "in_running_binary",
    "lang_packages_runtime": "runtime_process_running"
  },
  "events_status": "ok",
  "counts": {
    "in_use": 2,
    "not_observed": 2,
    "unavailable": 1,
    "muted": 0
  }
}
```

## Usage counts {#runtime-counts}

`runtime.counts` counts every package group in `actionable`, `watch`, `wont_fix`, and `eol_packages` by usage.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `in_use` | integer | Number of package groups in use | `0` |
| `not_observed` | integer | Number of package groups whose use was not observed | `0` |
| `unavailable` | integer | Number of package groups whose usage could not be assessed | `0` |
| `muted` | integer | Number of [muted](runtime-usage.md#muting-findings-without-a-fix) package groups | `0` |

`muted` is a subset of `not_observed` because it counts only package groups whose use was not observed.

See [Usage values](webhook-reference.md#usage-values) for the meaning of each usage state.

## Package group usage {#finding-runtime}

`findings[].runtime` describes a package group's usage and the observations used to assess it.
Its fields are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `usage` | string | Package group usage | — |
| `reason` | string | [Reason usage could not be assessed](#runtime-reasons) | omitted when `usage` is not `unavailable` |
| `evidence_kinds` | array of strings | Types of observations that confirmed use | omitted when `usage` is not `in_use` |
| `events_coverage` | string | Coverage of event observation through eBPF | omitted when `usage` is `in_use`, no target containers exist, or the Sensor report cannot be used |
| `exposure` | string | Port exposure of a process whose use was confirmed | omitted when the Sensor report cannot be used, or when `usage` is `in_use` and `containers[0].process` is absent |
| `high_privilege` | boolean | `true` when running with high privileges | omitted when not applicable |
| `containers` | array of objects | [Observations for each container](#container-evidence) | omitted when no target containers exist or the Sensor report cannot be used |
| `muted` | boolean | `true` when [muted](runtime-usage.md#muting-findings-without-a-fix) | omitted when not muted |
| `muted_reason` | string | Reason for [muting](runtime-usage.md#muting-findings-without-a-fix) | omitted when not muted |

The `evidence_kinds` values for OS packages are as follows.

| Value | Meaning |
| --- | --- |
| `exe` | A periodic check found a package file running |
| `mapped_library` | A periodic check found a running program that had loaded a package library |
| `exec_event` | eBPF captured an event in which a package file was executed |
| `library_load_event` | eBPF captured an event in which a package library was loaded |

The `evidence_kinds` values for language packages are as follows.

| Value | Meaning |
| --- | --- |
| `binary_running` | A periodic check found the executable embedding the package running |
| `binary_executed` | eBPF captured an event in which the executable embedding the package started |
| `runtime_running` | A periodic check found the runtime corresponding to the package running |
| `runtime_executed` | eBPF captured an event in which the runtime corresponding to the package started |

The values of `events_coverage` are as follows.

| Value | Meaning |
| --- | --- |
| `since_start` | Event observation through eBPF began before container startup, with no recorded event losses |
| `partial` | Event observation began after container startup, or some events were lost |
| `none` | No event observation through eBPF |

The values of `exposure` are as follows.

| Value | Meaning |
| --- | --- |
| `host_published_all` | Published on all host interfaces |
| `host_published_loopback` | Published only on host loopback interfaces |
| `container_listening` | Listening without being published on the host |
| `unknown` | Exposure cannot be assessed, or the package is not in use |

The value of `muted_reason` is as follows.

| Value | Meaning |
| --- | --- |
| `no_fix_not_in_use_7d` | No fix is available, and use has not been observed for at least seven days |

The following fields have additional notes.

- `usage`
    - Apply the following conditions to assessments across containers and language package locations, in order
        1. If any is in use, use `in_use`
        2. If any cannot be assessed, use `unavailable`
        3. If use was not observed for any of the assessed targets, use `not_observed`
- `events_coverage`
    - Uses the least complete coverage across containers and language package locations, preferring `none`, then `partial`, then `since_start`
- `high_privilege`
    - Set to `true` when any of the following applies
        - Running in a privileged container
        - Holding a [dangerous capability](#container-evidence)
        - Running with effective UID 0 outside a user namespace
    - When `usage` is `in_use`, taken together with `exposure` from observations for the first element, `containers[0]`
    - Describes the same process as `exposure`, with information about the selected process output in `containers[0].process`
- `containers`
    - Includes one element for each container running this image that is subject to observation
    - Includes containers where the package is not in use

The following example shows `runtime` for a package group in use.

```json
{
  "usage": "in_use",
  "evidence_kinds": [
    "exe"
  ],
  "exposure": "host_published_all",
  "high_privilege": true,
  "containers": [
    {
      "name": "web-1",
      "container_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "generation_started_at": "2026-06-24T08:00:00Z",
      "usage": "in_use",
      "last_seen": "2026-06-24T09:00:00Z",
      "ports": [
        "0.0.0.0:443/tcp"
      ],
      "process": {
        "exe": "/usr/sbin/nginx",
        "effective_uid": 0,
        "userns": false,
        "privileged": false
      }
    }
  ]
}
```

See [Usage values](webhook-reference.md#usage-values) for the meaning of `usage`.
See [Muting findings without a fix](runtime-usage.md#muting-findings-without-a-fix) for muting conditions.

## Container evidence {#container-evidence}

`findings[].runtime.containers[]` describes usage in each container, observed processes, and assessments for each language package location.
Containers are listed in the following order.

1. Containers where the package is in use come first
2. Containers where the package is in use are ordered by exposure: all host interfaces, host loopback only, listening without host publication, then unknown exposure
3. Among containers where the package is in use with the same exposure, highly privileged containers come first
4. When usage, exposure, and privilege do not determine the order, containers are ordered by container ID

The fields describing the container itself are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `name` | string | Container name | `""` |
| `container_id` | string | Container ID, consisting of 64 hexadecimal characters | `""` |
| `generation_started_at` | string | Time when the Sensor first observed this container during its current run | omitted |
| `usage` | string | Package usage in this container | — |
| `reason` | string | [Reason usage could not be assessed](#runtime-reasons) | omitted when `usage` is not `unavailable` |
| `last_seen` | string | Time of the latest observation | omitted |
| `ports` | array of strings | Container-side addresses and ports on which the process described by `process` listens | omitted |
| `kinds_ambiguous` | boolean | `true` when observation types for an OS package cannot be associated with individual processes | omitted when `false` |
| `process_exes` | array of strings | Deduplicated list of observed executables | omitted when `kinds_ambiguous` is `false` |
| `process` | object | Information about a process providing evidence of use | omitted when no process was observed |
| `instances` | array of objects | Usage for each language package location | omitted for OS packages |

The fields of `process` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `exe` | string | Executable path | omitted |
| `effective_uid` | integer | Process effective UID | — |
| `userns` | boolean | `true` when a user namespace is used | `false` |
| `dangerous_caps` | array of strings | Dangerous capabilities held by the process | omitted |
| `privileged` | boolean | `true` when running in a privileged container | `false` |

The fields of each `instances[]` element are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `type` | string | Package type | omitted |
| `target` | string | File path or runtime name identifying the detection target | omitted |
| `pkg_path` | string | File path identifying the location of the individual package | omitted |
| `usage` | string | Package usage at this location | — |
| `reason` | string | [Reason usage could not be assessed](#runtime-reasons) | omitted when `usage` is not `unavailable` |

The following fields have additional notes.

- `generation_started_at`
    - A timestamp in RFC 3339 format
- `last_seen`
    - A timestamp in RFC 3339 format
    - When in use, the latest observation time for the reported evidence of use
    - When not in use, the latest time the container was confirmed
- `ports`
    - Uses the format `address:port/protocol`, for example `0.0.0.0:443/tcp`
    - Does not translate these values to published host addresses or ports
- `kinds_ambiguous`
    - When `true`, do not read `evidence_kinds` types as corresponding one to one with executables in `process.exe` or `process_exes`
- `process`
    - When multiple processes were observed, describes one with the broadest exposure, preferring the highest privilege when exposure is equal
- `process.dangerous_caps`
    - Covers `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, and `CAP_SETGID`
- `instances`
    - Provides an assessment for each location when the same language package exists in multiple places within a container
    - Locations include executables embedding the package and package paths
- `instances[].type`
    - A package type such as `python-pkg` or `node-pkg`
- `instances[].target` and `instances[].pkg_path`
    - If the Trivy value begins with `/`, that single leading character is removed from the output
    - For Node.js and Python runtime findings added by KestreLynx, both fields contain the runtime executable path determined by KestreLynx

The following example describes one container where a Python language package was assessed as in use.

```json
{
  "name": "api-1",
  "container_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  "generation_started_at": "2026-06-24T08:00:00Z",
  "usage": "in_use",
  "last_seen": "2026-06-24T09:00:00Z",
  "process": {
    "exe": "/usr/bin/python3.11",
    "effective_uid": 1000,
    "userns": false,
    "privileged": false
  },
  "instances": [
    {
      "type": "python-pkg",
      "usage": "in_use"
    }
  ]
}
```

See [Usage values](webhook-reference.md#usage-values) for the meaning of `usage` in containers and `instances[]`.

## Reasons usage is unavailable {#runtime-reasons}

The `reason` field for a package group, container, or language package location is output when `usage` is `unavailable`.
It uses the following values to explain why usage could not be assessed.

The values concerning retrieval of Sensor information and preparation or continuation of observation are as follows.

| Value | Meaning |
| --- | --- |
| `sensor_not_reporting` | The file containing Sensor observations does not exist yet |
| `sensor_stale` | The Sensor report or confirmation of the target container is too old to conclude that use was not observed |
| `evidence_invalid` | Reading or validating Sensor observations failed |
| `isolation_failed` | The Sensor could not restrict operations other than reading and has not started observing |
| `permission_denied` | The Sensor was denied access to container process information or files |
| `initializing` | Preparation to associate packages with files is not complete |
| `stalled` | Processing to inspect the target container did not finish within its time limit |
| `truncated` | Limits such as the amount of data read prevented some required information from being obtained |
| `incomplete` | Some observations cannot be used, so use within the missing portion cannot be confirmed |

The values concerning the association between containers and observations are as follows.

| Value | Meaning |
| --- | --- |
| `generation_unverified` | The observations cannot be confirmed to match the container's current run and the scanned image |
| `container_not_observed` | No observations usable for assessment are available for the target container |

The values concerning package management information and its association with files are as follows.

| Value | Meaning |
| --- | --- |
| `parse_failed` | The process that parses package management information in the container has failed |
| `db_absent` | No usable package management information has been found in the container |
| `db_error` | Supported package management information was found, but reading or parsing it failed |
| `db_unsupported` | The container's package management information uses a format the Sensor does not support |
| `no_file_list` | A list of files belonging to the package cannot be obtained from package management information |
| `attribution_ambiguous` | The observed file belongs to multiple packages, so the package being used cannot be identified |
| `file_replaced` | The observed file was deleted or replaced, preventing its association with a package from being confirmed |
| `version_mismatch` | The package version observed in use by the Sensor differs from the scanned version of the package with the same name |

The values concerning association with language packages are as follows.

| Value | Meaning |
| --- | --- |
| `ecosystem_unmapped` | No runtime is mapped to this language package type for usage assessment |
| `binary_path_unknown` | The scan results lack the executable location required to assess package usage |

The following example shows `runtime` for a package group whose usage cannot be assessed because the Sensor has not reported.

```json
{
  "usage": "unavailable",
  "reason": "sensor_not_reporting"
}
```
