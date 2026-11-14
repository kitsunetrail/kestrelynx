---
title: Webhook remediation update check fields
---

# Webhook remediation update check fields

This page describes the fields for checks before and after language package updates and for updated files.
See [Remediation plan overview](webhook-remediation-reference.md#remediation-overview) for the overall structure.

`language_items[].source_check` is included when a dependency-file check record exists, even if the scan or check failed.
`language_items[].artifacts` is included when information about adopted updated files is available and is omitted when empty.

Field names in each table are relative to the object named immediately before the table.
See [Report fields](webhook-reference.md#report-fields) for how to read “When there is no value.”

## Checks before and after updates {#language-source-check-fields}

The fields of `language_items[].source_check` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `commit_sha` | string | SHA of the commit from which the dependency files before the update were retrieved | — |
| `before` | array of objects | List of [Checked files](#language-check-file-fields) before the update | `null` |
| `after` | array of objects | List of [Checked files](#language-check-file-fields) after the update | `null` |
| `conditions` | object | Record of [Scan conditions](#language-check-condition-fields) | — |
| `counts` | array of integers | Three counts in the order resolved, remaining, and newly detected | — |
| `truncated` | boolean | Whether any vulnerability or re-resolution comparison result lists were truncated at the item limit | omitted when `false` |
| `resolved` | array of objects | List of [Resolved, remaining, and newly detected vulnerabilities](#language-check-vulnerability-fields) detected only before the update | omitted |
| `remaining` | array of objects | List of [Resolved, remaining, and newly detected vulnerabilities](#language-check-vulnerability-fields) detected both before and after the update | omitted |
| `introduced` | array of objects | List of [Resolved, remaining, and newly detected vulnerabilities](#language-check-vulnerability-fields) detected only after the update | omitted |
| `passed` | boolean | Whether the checks before and after the update passed | `false` |
| `basis` | string | Comparison method used for [Re-resolution scan comparisons](#language-chain-scan-fields) | omitted when there is no additional comparison |
| `chain_new_findings` | array of objects | [Newly detected vulnerabilities](#language-check-chain-new-fields) by package version after the update, excluding carried vulnerabilities | omitted |
| `chain_entry_growth` | array of objects | Results showing [Increased occurrences](#language-check-entry-growth-fields) of vulnerable packages in the lockfile | omitted |
| `chain_edge_growth` | array of objects | Results showing [Increased dependency relationships](#language-check-edge-growth-fields) that use vulnerable packages | omitted |
| `chain_carried` | array of objects | [Carried vulnerabilities](#language-check-carried-fields) that remain in the same dependency relationships despite version changes | omitted |
| `chain_position_refusals` | array of objects | [Dependency position check failure reasons](#language-check-position-refusal-fields) found when checking changes in dependency relationships | omitted |

The following fields have additional notes.

- `counts`
    - Each package name and vulnerability ID pair counts as one, even if it occurs at multiple versions or locations
    - Python package names are matched after converting them to lowercase and replacing consecutive `-`, `_`, and `.` characters with a single `-`
    - Counts include vulnerabilities detected in dependency files for the relevant package manager, not just those in packages targeted for updating
    - Counts are reported before lists are truncated at the item limit
    - Occurrence counts, dependency relationship counts, and counts of elements in the `chain_*` lists are not included
    - A scan or other failure before comparison also results in `[0, 0, 0]`, so zero counts alone do not establish that the check completed
- `truncated`
    - `resolved`, `remaining`, `introduced`, and each of the five `chain_*` lists contain up to 500 elements
    - `true` if any list exceeds the limit
- `passed`
    - Indicates whether the checks passed, not whether a PR has been created
    - Also check `language_items[].reason` and `language_items[].detail` for reasons the checks failed or did not complete

The following example excerpts the commit, file lists, counts, and pass or fail result from a check record.

```json
{
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "before": [
    {
      "path": "package-lock.json",
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    {
      "path": "package.json",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ],
  "after": [
    {
      "path": "package-lock.json",
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    {
      "path": "package.json",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  ],
  "counts": [
    2,
    0,
    0
  ],
  "passed": true
}
```

### Checked files {#language-check-file-fields}

The fields of an element in `language_items[].source_check.before[]` and `language_items[].source_check.after[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | Path of the file checked, relative to `language_items[].source.directory` | — |
| `sha256` | string | Hexadecimal SHA-256 hash of the checked file's contents | — |

Each list is sorted by `path`.
The files checked do not necessarily match the files in `artifacts[]` to be written in the PR.

### Scan conditions {#language-check-condition-fields}

The fields of `language_items[].source_check.conditions` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `TrivyVersion` | string | Trivy version used for the check | `""` |
| `VulnerabilityDB` | object | [Database information](#language-check-database-fields) for the vulnerability database | — |
| `JavaDB` | object | [Database information](#language-check-database-fields) for the Java database | — |
| `Severities` | array of strings | List of [Severity](#language-check-severity-values) levels included in detection | `null` |
| `AnalysisSettings` | string | String identifying the analysis settings applied to the scan | `""` |
| `VulnerabilityDBSHA` | string | Hexadecimal SHA-256 hash of the vulnerability database file's contents | `""` |
| `JavaDBSHA` | string | Hexadecimal SHA-256 hash of the Java database file's contents | `""` |
| `TrivySHA` | string | Hexadecimal SHA-256 hash of the Trivy executable | `""` |

The following fields have additional notes.

- Keys such as `TrivyVersion`
    - Names differ from those in `remediation.conditions` and are output exactly as shown in the table, including capitalization
    - `conditions` and its child fields are not omitted even when the information could not be recorded
- `Severities`
    - Values are converted to uppercase, deduplicated, and output in lexicographical order
- `AnalysisSettings`
    - A string identifying the scan method and analysis settings, rather than a fixed category code

#### Database information {#language-check-database-fields}

The fields of `language_items[].source_check.conditions.VulnerabilityDB` and `language_items[].source_check.conditions.JavaDB` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `Version` | integer | Database schema version | `0` |
| `UpdatedAt` | string | Date and time the database was built, in RFC 3339 format | `"0001-01-01T00:00:00Z"` |

`Version` alone cannot identify the database contents.
Use the corresponding `VulnerabilityDBSHA` or `JavaDBSHA` to identify the contents.

The following example excerpts `conditions` from a check record in which the scans before and after the update succeeded.

```json
{
  "TrivyVersion": "0.71.2",
  "VulnerabilityDB": {
    "Version": 2,
    "UpdatedAt": "2026-10-09T03:00:00Z"
  },
  "JavaDB": {
    "Version": 1,
    "UpdatedAt": "2026-10-09T03:00:00Z"
  },
  "Severities": [
    "CRITICAL",
    "HIGH"
  ],
  "AnalysisSettings": "fs;scanners=vuln;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;dev-deps=included;config=none;ignorefile=none;vex=none;env=sanitized;workdir=isolated",
  "VulnerabilityDBSHA": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "JavaDBSHA": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "TrivySHA": "1111111111111111111111111111111111111111111111111111111111111111"
}
```

If a failure occurs before the scans before and after the update complete, `conditions` is output with all its information unrecorded.
In that case, the Trivy version, analysis settings, and hashes are `""`, the severity list is `null`, and each database's version is `0` and timestamp is `"0001-01-01T00:00:00Z"`.

### Resolved, remaining, and newly detected vulnerabilities {#language-check-vulnerability-fields}

The fields of an element in `language_items[].source_check.resolved[]`, `language_items[].source_check.remaining[]`, and `language_items[].source_check.introduced[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package in which the vulnerability was detected | — |
| `version` | string | Version of the package in which the vulnerability was detected | `""` |
| `vuln_id` | string | Vulnerability ID | — |
| `severity` | string | [Severity](#language-check-severity-values) of the detected vulnerability | omitted |
| `fixed_ver` | string | Fixed-version information reported by the scan | omitted |
| `kev` | boolean | Whether inclusion in CISA KEV was confirmed | omitted when `false` |

The following fields have additional notes.

- `version`
    - `resolved[]` uses the version from detection before the update, while `remaining[]` and `introduced[]` use the version from detection after the update
    - When the same package name and vulnerability ID are detected at multiple versions, the finding whose version comes first in lexicographical order is output as the representative
    - The representative version is not necessarily the oldest when compared as version numbers
- `fixed_ver`
    - The string reported by the scan is output as-is, so it is not necessarily a single version number
- `kev`
    - Omitted both when the vulnerability is not listed and when information to confirm inclusion is unavailable

The following is an example of one element in `resolved[]`.

```json
{
  "package": "minimist",
  "version": "1.2.5",
  "vuln_id": "CVE-2031-0100",
  "severity": "HIGH"
}
```

#### Severity {#language-check-severity-values}

The main values of `severity` and the values of `conditions.Severities[]` are as follows.

| Value | Meaning |
| --- | --- |
| `CRITICAL` | Critical |
| `HIGH` | High |
| `MEDIUM` | Medium |
| `LOW` | Low |
| `UNKNOWN` | Unknown |

`severity` outputs the string returned by the scan as-is.

## Re-resolution scan comparisons {#language-chain-scan-fields}

Re-resolution through dependent packages records vulnerabilities by package version, along with changes in occurrences of vulnerable packages and dependency relationships.
`counts` and the three ordinary vulnerability lists still contain comparison results based on package name and vulnerability ID pairs.

The values of `language_items[].source_check.basis` are as follows.

| Value | Meaning |
| --- | --- |
| `package_version_vuln_edges_positions` | Checks package names, versions, vulnerability IDs, occurrence counts, and dependency relationship counts, as well as the positions of changed dependency relationships |
| `package_version_vuln_edges` | Compares package names, versions, vulnerability IDs, occurrence counts, and dependency relationship counts |

When dependency positions are checked, results may appear in `chain_carried[]` or `chain_position_refusals[]`.
Even when the lists are omitted, `basis` indicates whether positions were checked.

### Newly detected vulnerabilities {#language-check-chain-new-fields}

The fields of an element in `language_items[].source_check.chain_new_findings[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package in which a new vulnerability was found after the update | — |
| `version` | string | Version of the package in which the vulnerability was detected after the update | `""` |
| `vuln_id` | string | ID of the newly detected vulnerability | — |
| `severity` | string | [Severity](#language-check-severity-values) of the detected vulnerability | omitted |
| `fixed_ver` | string | Fixed-version information reported by the scan | omitted |
| `kev` | boolean | Whether inclusion in CISA KEV was confirmed | omitted when `false` |

Entries are output when the package name, version, and vulnerability ID combination was absent before the update and did not qualify as carried.
Even if the same package name and vulnerability ID were present before the update, a version change can cause an entry to appear in this list.

`fixed_ver` and `kev` are handled as described in [Resolved, remaining, and newly detected vulnerabilities](#language-check-vulnerability-fields).

### Increased occurrences {#language-check-entry-growth-fields}

The fields of an element in `language_items[].source_check.chain_entry_growth[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package whose occurrence count increased | — |
| `version` | string | Package version when reporting a per-version increase | omitted when versions are counted together |
| `vuln_id` | string | ID of the vulnerability in the versions whose occurrence count increased | — |
| `before` | integer | Occurrence count in the lockfile before the update | `0` |
| `after` | integer | Occurrence count in the lockfile after the update | — |

The following fields have additional notes.

- `version`
    - When present, the result compares occurrence counts for that version
    - When omitted, the occurrence count combines the package versions affected by that vulnerability
    - When per-version increases are output for a package name and vulnerability ID pair, an increase across versions is not output as well
- `before` and `after`
    - Counts package entries in the lockfile, not the total number of paths from the project
    - Counts each snapshot for pnpm and each package name and version pair as one for uv

### Increased dependency relationships {#language-check-edge-growth-fields}

The fields of an element in `language_items[].source_check.chain_edge_growth[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package whose dependency relationship count increased | — |
| `version` | string | Package version when counting only a specific version | omitted in the current output |
| `vuln_id` | string | ID of the vulnerability in the versions whose dependency relationship count increased | — |
| `before` | integer | Count of dependency relationships using vulnerable versions before the update | `0` |
| `after` | integer | Count of dependency relationships using vulnerable versions after the update | — |

The following fields have additional notes.

- `version`
    - Currently not output because affected versions are counted together for each package name and vulnerability ID pair
- `before` and `after`
    - Counts direct dependencies from the project and dependencies between packages, including peer dependencies
    - Dependencies from the same dependent package that reference the same lockfile entry under the same name are counted as one when their applicability conditions match
    - Dependencies with different applicability conditions are counted separately

### Carried vulnerabilities {#language-check-carried-fields}

The fields of an element in `language_items[].source_check.chain_carried[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package in which the vulnerability remains | — |
| `from` | string | Representative version before the change | — |
| `to` | string | Version after the change | — |
| `vuln_id` | string | ID of the vulnerability that remains | — |
| `positions` | integer | Number of dependency relationship locations where the same vulnerability remains | — |
| `kev` | boolean | Whether inclusion in CISA KEV was confirmed | omitted when `false` |

The following fields have additional notes.

- `from`
    - When there are multiple versions before the change, the first in lexicographical order is output
- `positions`
    - Differs from the total number of paths from the project to the vulnerable package
- `kev`
    - Omitted both when the vulnerability is not listed and when information to confirm inclusion is unavailable

`chain_carried[]` groups records by package name, version after the change, and vulnerability ID.
Carried vulnerabilities remain unfixed by this update.

### Dependency position check failure reasons {#language-check-position-refusal-fields}

The fields of an element in `language_items[].source_check.chain_position_refusals[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `package` | string | Name of the package causing the check to fail | — |
| `version` | string | Version of the package causing the check to fail | — |
| `parent` | string | Name of the dependent package that uses that package | omitted |
| `check` | string | Reason the dependency position check failed | — |
| `vuln_id` | string | One vulnerability ID absent from the corresponding old version | omitted when `check` is not `new_vuln` |

The following fields have additional notes.

- `package` and `version`
    - When `check` is `split`, the package name and version before the split
    - For values other than `split`, the dependency's package name and version after the update
- `parent`
    - Omitted when the dependent is the project itself or `check` is `split`
- `vuln_id`
    - When multiple vulnerability IDs apply, the first in lexicographical order is output

The values of `check` are as follows.

| Value | Meaning |
| --- | --- |
| `no_position` | A corresponding dependency relationship at the same position before the update cannot be confirmed |
| `merged` | Multiple dependency paths merge, so a single package entry before the update cannot be chosen for comparison |
| `name` | The dependency's package name changes at the same position |
| `new_vuln` | The new version contains a vulnerability absent from the corresponding old version |
| `split` | One package entry before the update splits into multiple vulnerable package entries after the update |

Carried vulnerabilities do not establish that the checks pass; check `language_items[].source_check.passed` for the check result.
Check `language_items[].update.chain.outcome` for re-resolution adoption status, and see [Results of re-resolution through dependent packages](remediation-update-results.md#dependent-reresolution-results) for the meanings of its values.

`language_items[].source_check` is the record of one check retained in the processing result.
The following fields have additional notes.

- `language_items[].source_check` and `language_items[].artifacts`
    - When updated files are present, both correspond to the same adopted update
    - When `language_items[].update.chain.outcome` is `adopted`, they contain the re-resolution result; when re-resolution is rejected and an ordinary update is adopted, they contain the ordinary update result
- `language_items[].source_check`
    - When the ordinary update fails and subsequent re-resolution is also rejected, the re-resolution check record is retained if available
    - If the ordinary update is then rerun with packages excluded and its result is finalized as adopted or failed, the check record is replaced with that of the rerun
    - When the rerun is deferred, the check record from before the rerun may be retained

Each of the five lists contains up to 500 elements, and `language_items[].source_check.truncated` is `true` when elements are omitted.
Pass or fail decisions for re-resolution scan comparisons use all results before truncation.

See [Re-resolution check conditions](remediation-reresolution-logic.md#dependent-reresolution-rules) for check conditions and [Carried vulnerabilities](remediation-reresolution-logic.md#dependent-reresolution-carried-findings) for examples of carried vulnerabilities.

## Updated files {#language-artifact-fields}

The fields of an element in `language_items[].artifacts[]` are as follows.

| Field | Type | Meaning | When there is no value |
| --- | --- | --- | --- |
| `path` | string | Path of the updated file relative to the repository root | — |
| `sha256` | string | Hexadecimal SHA-256 hash of the file's contents after the update | — |
| `size` | integer | File size in bytes after the update | `0` |
| `mode` | string | Git file mode of the updated file | omitted |

The values used for `mode` are as follows.

| Value | Meaning |
| --- | --- |
| `100644` | Regular file without execute permission |
| `100755` | Regular file with execute permission |

File contents are not included.
The presence of `artifacts[]` alone does not indicate whether a PR has been created.

The following example excerpts the updated files from one element in `language_items[]`.

```json
{
  "artifacts": [
    {
      "path": "package-lock.json",
      "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "size": 30,
      "mode": "100644"
    }
  ]
}
```
