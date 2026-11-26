---
description: "This article describes the criteria for choosing remediation candidates from Trivy findings using KEV and EPSS and where those criteria come from. It compares them with selection by severity alone across nine public images, showing how many findings each approach selects and which findings are included."
---

# How to Choose Remediation Candidates When Trivy Reports Too Many Findings

Published: November 26, 2026

## Introduction

When a Trivy scan of a container image returns many findings, it can be hard to
decide which ones to consider for remediation first. Even limiting the
candidates to CRITICAL or HIGH findings can leave a long list.

Severity describes the technical seriousness of a vulnerability. On its
own, it cannot show whether a vulnerability is being exploited in the
wild or how likely it is to be exploited in the future.
We therefore use KEV and EPSS to narrow the list of candidates.
CISA describes the KEV Catalog as an input for setting remediation
priorities, and FIRST describes the EPSS score in the same
terms.[^cisa-kev][^first-epss]

The decision to use KEV and EPSS does not, by itself, tell us how many
candidates will remain or which findings will be included compared with
filtering by severity. We applied both approaches to actual scan results
to compare the number and composition of the candidates. Using KEV and
EPSS yielded far fewer candidates than filtering by severity and also
selected MEDIUM and LOW findings that severity alone would have
excluded.[^records]

This article covers the following:

- The criteria for choosing candidates using KEV and EPSS and where those criteria come from.
- Two studies that use an EPSS threshold to narrow the list of candidates.
- How candidate counts differ between the two approaches and examples of MEDIUM and LOW findings selected using KEV and EPSS.
- Counts of selected findings with and without a recorded fixed version.
- The limits of the comparison.

## Choosing remediation candidates

A finding is a candidate for remediation if the vulnerability is listed
in KEV or its EPSS score is at least 0.10, regardless of severity.
This article uses the [criteria KestreLynx implements for its highest priority (Act now)](../documentation/scan-logic.md#cve-priority-rules)
without modification, including the default Act now EPSS threshold of 0.10.

FIRST does not prescribe a single EPSS score at which a vulnerability
should be considered for remediation. It states that each organization
sets its threshold by trying it and refining it in light of the
results.[^first-epss]
We did not test whether 0.10 is an appropriate threshold for choosing
remediation candidates.

## Related research

One study compared using an EPSS threshold to narrow the list of
candidates with selecting by CVSS. Another proposed combining an EPSS
threshold with KEV and CVSS to assign priorities.

In their paper on EPSS version 3, Jacobs et al. compare selection by
EPSS with selection by CVSS. In their evaluation, selecting
vulnerabilities with a CVSS base score of at least 7 captured 82.1% of
exploited vulnerabilities but made 58.1% of all vulnerabilities
candidates for remediation. The authors report that selecting
vulnerabilities with an EPSS score of at least 0.088 captured 82% of
exploited vulnerabilities and made 7.3% of all vulnerabilities
candidates for remediation.[^jacobs]

Shimizu and Hashimoto propose Vulnerability Management Chaining (VMC)
for efficient prioritization using CVSS, EPSS, and KEV in a decision
tree framework that systematically integrates these three approaches.
Using exclusively open-source data, VMC first selects vulnerabilities
listed in KEV or with an EPSS score of at least 0.088, then assigns
priorities according to whether the CVSS score is at least 7.0.
VMC uses the same EPSS threshold as the study by Jacobs et al.
The authors evaluated VMC on 28,377 vulnerabilities and
report 18-fold efficiency improvements while maintaining 85.6%
coverage.[^shimizu-hashimoto]

## Validation details

We applied both sets of criteria to the same scan results to see how many
candidates remained when using KEV and EPSS and how those candidates
differed from the ones selected by severity. For severity, we selected
CRITICAL or HIGH findings. For KEV and EPSS, we used the criteria in
“Choosing remediation candidates.”

### Images used in the validation

We deliberately chose old tags for nine public images to represent
container images that had gone a long time without an update.
In the table, † marks images for which Trivy recorded the OS as
end-of-life.

| Image | OS | Findings |
| --- | --- | ---: |
| `nginx:1.21.0` | Debian 10.10 † | 394 |
| `postgres:15.3` | Debian 12.1 | 1,377 |
| `redis:7.0.11` | Debian 12.0 | 10,997 |
| `mysql:8.0.33` | Oracle Linux 8.8 | 542 |
| `node:20.11.0` | Debian 12.5 | 16,136 |
| `grafana/grafana:10.0.0` | Alpine 3.17.4 † | 509 |
| `elasticsearch:8.8.0` | Ubuntu 20.04 † | 378 |
| `ghost:5.51.0` | Debian 11.7 † | 1,249 |
| `apache/airflow:2.6.1` | Debian 11.7 † | 2,339 |
| Total | | 33,921 |

### Scan and matching conditions

Trivy pulled `linux/amd64` images from the registry and scanned all
images with the same vulnerability database.

| Item | Value |
| --- | --- |
| Trivy | `0.71.2` |
| Vulnerability database update time | `2026-11-24T07:08:30.893544587Z` |
| Scan options | `--scanners vuln --image-src remote --platform linux/amd64 --skip-db-update --skip-java-db-update` |
| CISA KEV Catalog version | `2026.11.24` |
| FIRST EPSS score timestamp | `2026-11-24T12:00:20Z` |
| EPSS model version | `v2026.06.15` |

Each finding in a Trivy report counts once: one vulnerability ID
reported for one package. We used `collect.sh` to collect the data and
`compare.py` to aggregate the results. The image digests are recorded
in `records/conditions.json`, the summary tables in `records/summary.md`,
and the individual findings in `records/findings.tsv.gz`.[^records]

## Validation results

### Candidate counts

For each of the nine public images, using KEV and EPSS selected fewer
candidates than using severity.

| Image | Findings | Selected by severity | Selected using KEV and EPSS |
| --- | ---: | ---: | ---: |
| `nginx:1.21.0` | 394 | 165 | 47 |
| `postgres:15.3` | 1,377 | 516 | 27 |
| `redis:7.0.11` | 10,997 | 2,035 | 51 |
| `mysql:8.0.33` | 542 | 213 | 23 |
| `node:20.11.0` | 16,136 | 3,489 | 80 |
| `grafana/grafana:10.0.0` | 509 | 183 | 20 |
| `elasticsearch:8.8.0` | 378 | 105 | 24 |
| `ghost:5.51.0` | 1,249 | 530 | 20 |
| `apache/airflow:2.6.1` | 2,339 | 852 | 64 |
| Total | 33,921 | 8,088 | 356 |

A single package, `linux-libc-dev`, accounted for 19,345 of the 33,921
findings (57%). Of the 14,576 findings remaining after excluding
`linux-libc-dev`, 4,764 were CRITICAL or HIGH, while KEV and EPSS
narrowed the list to 301 candidates. Of those 301, the 106 findings
that severity alone would have excluded were all MEDIUM or LOW, the same
pattern seen in the full comparison.[^records]

The number of candidates selected by EPSS varied substantially with the
score threshold. Counting by EPSS score alone, lowering the threshold
from 0.10 to 0.01 increased the number of qualifying findings from 334
to 3,150.

### Severity and exploitation signals

Selecting by severity alone leaves many candidates while excluding some
findings for vulnerabilities that are listed in KEV or have an EPSS
score of at least 0.10.
Most CRITICAL and HIGH findings in these scans were for vulnerabilities
absent from KEV with an EPSS score below 0.10. Of the 462 CRITICAL
findings, KEV and EPSS selected 29. Of these, 5 were for vulnerabilities
listed in KEV and 24 were for vulnerabilities absent from KEV with an
EPSS score of at least 0.10.

| Severity | Listed in KEV | Not in KEV, EPSS ≥ 0.10 | Not in KEV, 0.01 ≤ EPSS < 0.10 | Not in KEV, EPSS < 0.01 | Not in KEV, no EPSS score | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CRITICAL | 5 | 24 | 146 | 284 | 3 | 462 |
| HIGH | 46 | 152 | 1,042 | 6,241 | 145 | 7,626 |
| MEDIUM | 8 | 71 | 808 | 18,437 | 101 | 19,425 |
| LOW | 2 | 48 | 802 | 4,743 | 43 | 5,638 |
| UNKNOWN | 0 | 0 | 0 | 199 | 571 | 770 |
| Total | 61 | 295 | 2,798 | 29,904 | 863 | 33,921 |

The “Not in KEV, no EPSS score” column also includes findings whose IDs
could not be matched against KEV because they were not in CVE format.

Of the 356 findings selected using KEV and EPSS, 227 were CRITICAL or
HIGH. The remaining 129 were MEDIUM or LOW and would have been excluded
by severity alone. The MEDIUM and LOW candidates include findings for
vulnerabilities that met the EPSS threshold without a KEV listing and a
finding for a vulnerability listed in KEV.[^records]

| Vulnerability ID | Severity | KEV | EPSS | Where detected | Fixed version |
| --- | --- | --- | ---: | --- | --- |
| `CVE-2023-48795` | MEDIUM | Not listed | 0.93547 | Packages including `libssh` and `paramiko` across 4 images | Yes |
| `CVE-2011-3389` | LOW | Not listed | 0.73327 | `libgnutls30` in 5 images | No (`affected`) |
| `CVE-2026-123158` | LOW | Listed | 0.95538 | `openssh-client` in 2 images | No (`affected`) |

### Fixed versions for selected candidates

Most candidates selected using KEV and EPSS had a fixed version
recorded in `FixedVersion`, so an update could be considered.

| Fixed version recorded | `Status` | Meaning of `Status` | Findings |
| --- | --- | --- | ---: |
| Yes | `fixed` | A fix is available | 316 |
| No | `affected` | The package is affected, with no fix released yet | 27 |
| No | `fix_deferred` | The fix is postponed | 6 |
| No | `will_not_fix` | There is no current plan to fix it | 7 |
| Total | | | 356 |

## Limits of the comparison

This comparison does not establish whether the 7,861 findings selected
by severity but excluded when using KEV and EPSS can be deferred.
We did not test whether the selected vulnerabilities could be exploited
in the target containers, including whether the vulnerable code was
reachable or the package was used at runtime. A validation that matched
runtime usage to scan results is described in
[How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans](which-container-scan-findings-are-actually-running.md).

Using KEV and EPSS, we could not assess 863 findings, including
3 CRITICAL and 145 HIGH findings. Of those 863 findings, 670 had IDs
that were not in CVE format and could not be matched against either KEV
or EPSS. The remaining 193 had CVE-format IDs, but none of the
corresponding vulnerabilities were listed in KEV or had an EPSS score.

The comparison used nine images with deliberately old tags, and Trivy
recorded the OS as end-of-life for five of them. The KEV and EPSS data
were current as of November 24, 2026. Other images or dates may yield
different proportions.

Because Trivy reports the same vulnerability ID for multiple packages, the
difference in candidate counts does not show how much work could be
saved.

## Summary

Across nine public images, limiting candidates to CRITICAL or HIGH
still left 8,088 findings. Selecting findings for vulnerabilities
listed in KEV or with an EPSS score of at least 0.10, regardless of
severity, narrowed the list to 356 candidates, including 129 MEDIUM or
LOW findings.

## References

///Footnotes Go Here///

[^records]: [Programs and records used in the comparison](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/triage-comparison). The full results are summarized in `records/summary.md` and the results excluding `linux-libc-dev` in `records/without-linux-libc-dev/summary.md`.

[^cisa-kev]: [CISA: Reducing the Significant Risk of Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities)

[^first-epss]: [FIRST: Using EPSS](https://www.first.org/epss/using-epss)

[^jacobs]: Jay Jacobs, Sasha Romanosky, Octavian Suciu, Benjamin Edwards, and Armin Sarabi. “[Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights](https://arxiv.org/abs/2302.14172).” 2023.

[^shimizu-hashimoto]: Naoyuki Shimizu and Masaki Hashimoto. “[Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization](https://arxiv.org/abs/2506.01220).” IEEE Access, vol. 14, 2026.

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack, email, or a webhook.

Remediation plans and pull requests (experimental) for Docker, Compose, and Kubernetes support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[About KestreLynx](../index.md) · [View source on GitHub](https://github.com/kitsunetrail/kestrelynx)
