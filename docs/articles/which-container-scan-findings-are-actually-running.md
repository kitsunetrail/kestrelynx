---
description: "Check runtime usage of packages reported by container vulnerability scans using procfs, understand sampling limits, and combine runtime evidence with KEV and EPSS to prioritize fixes."
---

# How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans

Published: September 16, 2026

## Introduction

Trivy reports many vulnerability findings, including findings for packages
that are not actually used in the container. Prioritizing findings for
packages in use requires checking each package's usage.
Trivy findings alone cannot establish usage, so runtime information
is needed.

For example, a scan of `nginx:1.27` reported 616 vulnerability findings
across 72 packages, including 153 rated HIGH or CRITICAL.
Runtime sampling confirmed loaded files from packages associated with
9 of those 153 findings.[^measurements][^harness]

This article covers the following:

- What Trivy findings alone cannot show.
- What loaded-package evidence proves, and what it leaves unanswered.
- Measured results from stock images, self-built images, and an operational host.
- How to combine runtime evidence with KEV and EPSS.
- A compact way to inspect the same relationship on a Docker host.

## What Trivy findings alone cannot show

For this comparison, a finding is a package, installed version, and CVE
tuple produced by matching detected software against vulnerability
information. Counts are CVE × package, so multiple findings can refer to
the same package.[^trivy]
Counts describe the number of these combinations, while severity describes
the seriousness of the reported vulnerabilities.

Findings have the following limitations:

- They do not show whether the package is actually used in this container.
- They do not show whether its vulnerable functionality was reached.
- Adding KEV or EPSS does not show whether the affected package is used in this environment.
    - CISA KEV identifies CVEs with evidence of exploitation in the wild; see [KEV Catalog Basics and Usage](kev-known-exploited-vulnerabilities.md).[^kev]
    - FIRST EPSS estimates exploitation likelihood over the next 30 days; see [EPSS Basics and How to Check Scores](epss-exploit-prediction-scoring-system.md).[^epss]

Checking a package's runtime usage therefore requires information (runtime
evidence) connecting an observed process to a package and version in this
container. Confirmed package use supports raising the remediation priority
of the associated vulnerabilities. Record usage separately from KEV and
EPSS assessments so that the reason for raising priority remains clear.

## Meaning of “used at runtime”

Here, “used at runtime” means that a running process has loaded an executable
or shared library from the package. Loading is observed through procfs using
`/proc/<pid>/exe` and `/proc/<pid>/maps`.[^proc][^exe][^maps]

This definition establishes the following:

- A process was executing or mapping that file at the sample time.
- The file's owning package and version match the package and version in the finding.

It does not establish the following:

- Whether a vulnerable function was executed.
    - Observing loading does not show which functions were called.
- That an unobserved package is unused.
    - It may load during another request, in a different worker, or between samples.

Confirmed package use therefore supports raising the remediation priority
of the associated vulnerabilities. If use cannot be confirmed, that does
not establish that the package is unused, so it is not a reason to lower
priority.[^harness]

For details on handling observed paths, ownership, and versions, see the
[procfs process-to-package mapping article](procfs-process-to-package-mapping.md).

## Measurement method

For each Trivy finding, the measurement checked whether running processes
loaded files from the corresponding package.
The confirmation rate was confirmed findings / total findings, primarily for HIGH/CRITICAL, with all severities as a secondary view.

- **Targets**
    - Stock images: `nginx:1.27`, `postgres:16`, and `nginx-unprivileged:1.27-alpine`.
    - Self-built images, each adding a small program to an official base image to reproduce a specific situation: `python:3.12-slim` with a cryptography wheel, `debian:12-slim` with a static Go server, and Debian cases reproducing short-lived processes and temporary `dlopen`.
    - Operational sample: four containers (static Go, JVM with bundled JDK, two Node.js) on a separate Ubuntu host; one root run with AppArmor enabled.
    - Main environment: one WSL2 host, Linux 6.6.114, Docker Engine 29.1.3; scanner: Trivy v0.71.
- **Procedure**
    - Scan the running container's image ID.
    - Periodically observe `/proc/<pid>/exe` and executable mappings in `maps` for host PIDs from `docker top`.
    - Resolve file ownership through container dpkg/apk databases and match package names and versions to findings.
- **Conditions and criteria**
    - Baseline: 10 root samples, every 30 seconds over 300 seconds.
    - Compare seven intervals, windows, and start-time combinations to check short-lived process capture.
    - Confirmation requires matching the scanned image, package name, and version; never guess unknown ownership.
- **Accuracy checks**
    - Self-built images: compare program usage logs for misses and false positives within their scope.
    - Official images: manually map resident-process files to check only misses.
    - Neither confirms execution of vulnerable code itself.

The [public measurement results](../development/runtime-prioritization.md#results-2026-09-12)
describe the runs, and the measurement harness contains the collection
procedure.[^measurements][^harness] The results below describe those measurements, not a
guaranteed confirmation rate for another workload.

## Measurement results for stock and self-built images

For Debian-based stock images, running processes had loaded files from the
affected package for 9 of the 153 HIGH or CRITICAL vulnerabilities Trivy
reported in nginx, and for 5 of 113 in PostgreSQL.
The table below shows, for the stock images and the self-built images
(Python with cryptography, static Go), how many vulnerabilities reported by
Trivy had confirmed package loading.

| Image | HIGH/CRITICAL vulnerabilities reported by Trivy (confirmed / total) | Packages with findings (confirmed / total) | All-severity vulnerabilities (confirmed / total) |
| --- | ---: | ---: | ---: |
| `nginx:1.27`, Debian | 9/153 (5.9%) | 2/43 | 66/616 |
| `postgres:16` | 5/113 (4.4%) | 3/34 | 71/409 |
| `nginx-unprivileged:1.27-alpine` | 16/34 (47%) | 4/10 | 42/109 |
| `python:3.12-slim` with the cryptography wheel | 0/54 | 0/19 | 22/180 |
| `debian:12-slim` with a static Go server | 0/56 | 0/17 | 0/222 |

The results show the following:

- For Debian-based nginx and postgres, loading was confirmed for only 9 of 153 and 5 of 113 HIGH/CRITICAL vulnerabilities reported by Trivy.
    - The 9 confirmed nginx findings came from 2 of 43 packages carrying HIGH/CRITICAL findings: `libssl3` and `zlib1g`, providing the OpenSSL and zlib shared libraries loaded by the server.
    - Across all severities, confirmation covered 4 of 72 packages with findings: `libc6`, `libssl3`, `zlib1g`, and `libcrypt1`.
    - The mapped `nginx` and `libpcre2-8-0` packages carried no findings, so they did not add to the confirmed count.[^harness]
- Alpine nginx had fewer packages with findings and a confirmed fraction of 47%; this difference describes overlap between findings and observed package use, not relative risk.
- In Python, the 54 HIGH/CRITICAL vulnerabilities reported by Trivy involved OS packages, none of which corresponded to OS libraries loaded by the running Python process, leaving 0 confirmed findings.
    - Across all severities, 22 findings were confirmed, while pip-package findings appeared only in the all-severity results and were outside OS ownership mapping, as described under “Limits of this measurement method.”
- In static Go, the 56 HIGH/CRITICAL vulnerabilities reported by Trivy remained unobserved, with 0 confirmed, because the statically linked executable did not load shared libraries, as described under “Limits of this measurement method.”
- Across all synthetic cases, counting nginx once despite measurements under three conditions, 33 of 627 HIGH/CRITICAL findings were confirmed, or 5.3%; the remaining 594 were unobserved, not unused.[^measurements]

The package column counts confirmed / total packages carrying HIGH/CRITICAL
findings; the public development log records finding counts, while package
counts come from the same runs.[^measurements][^harness]
Usage-log comparisons found 0 false positives but covered only 1–2 packages
per case, leaving accuracy across all scanned packages undetermined.[^measurements]
The synthetic aggregate also describes selected cases, not an estimate of
vulnerable software use across container deployments.

## Measurement results on an operational host

Across four containers on an operational host, none of the 103 HIGH or
CRITICAL vulnerabilities reported by Trivy had confirmed package loading.
OS-package runtime evidence added nothing to HIGH/CRITICAL prioritization
in this measurement.

The containers ran a static Go service, a JVM with a bundled JDK, and two
Node.js services on a separate Ubuntu host; collection ran once as root
with AppArmor enabled, sampling every 30 seconds for 300 seconds.[^measurements]

| HIGH/CRITICAL vulnerabilities reported by Trivy | Confirmed / total | Interpretation |
| --- | ---: | --- |
| Language packages | 0/84 | Outside OS ownership mapping |
| OS packages | 0/19 | No confirming use observed |
| Total | 0/103 | No HIGH/CRITICAL runtime confirmation |

The results show the following:

- Of the 103 findings, 84 involved language packages—Go modules, JARs, and npm packages—which OS ownership information could not map.
- The remaining 19 involved OS packages whose loading was not observed, without establishing that they were unused.[^measurements]
- On a host dominated by language runtimes, more frequent sampling alone is insufficient; a separate method is needed to connect files or executables to language packages.

This was one run on one host, so it does not establish that OS-package
evidence is unhelpful across operational environments.

## Limits of this measurement method

This method can miss short-lived processes and temporary library loading.
OS ownership information also cannot map language packages, statically
linked dependencies, or executables outside the package database.

### Short-lived processes

Sampling misses processes that run briefly and exit before a sample is
taken. Capture depends on the starting time as well as the interval.

- Curl, running for about 0.1 seconds every 5 seconds, was captured once in 30 samples taken every 10 seconds over 300 seconds.
- At the baseline starting offset, 30-second and 60-second intervals over 300 seconds captured curl 0 times.
- Git was captured 0 times across all seven tested conditions.[^measurements]

These are counts of samples that saw a process, not proportions of
executions captured, and they do not yield a general miss rate.

### Temporary library loading

A temporary `dlopen` can begin and end between samples.

- SQLite, loaded for 7 seconds and unloaded for 7 seconds, was confirmed in all seven conditions and captured in 3 of 10 samples under the baseline condition of sampling every 30 seconds for 300 seconds.[^measurements]

Temporary loading can be observed and needs measurement, but these results
do not guarantee capture of shorter loading periods.

### Language packages

OS ownership information cannot identify Python extensions, Go modules,
JARs, or npm packages, so a visible extension file does not establish the
language package and version reported by the scanner.
Observing Python or Node.js alone also does not confirm use of its
dependencies.[^harness]

- In Python with a cryptography wheel, pip-package findings could not be mapped through OS ownership information, and neither the Python executable nor its extensions had an OS-package owner.
    - The 54 HIGH/CRITICAL vulnerabilities reported by Trivy involved OS packages whose loading was not observed.
    - Across all severities, 22 of 180 findings were linked to loaded OS packages.[^measurements]

For language software packaged by a distribution, ownership identifies
only the distribution package; a separate language-package finding still
requires additional mapping.

### Static linking

A statically linked executable has no shared-library mappings, leaving
no separate library paths and ownership information to connect its
embedded dependencies to findings.

- In the Debian-based static Go test, the executable was observed but had no owner in the OS package database, leaving 0 of 56 HIGH/CRITICAL findings confirmed.[^harness]

A confirmation count of 0 does not mean the process has no vulnerabilities.

### Executables outside the package database

An executable outside the OS package database can be readable without an
identifiable owning package.

- On the operational host, `/usr/local/bin/node`, the bundled JDK, and the static Go executable were outside the OS package database.[^harness]

Do not infer ownership from a filename or directory; record the missing
relationship separately from a failed process read.

## Use of runtime evidence in remediation prioritization

When package use is confirmed at runtime, use that information to support
raising the remediation priority of its vulnerabilities. If use is not
confirmed during the observation period, that does not establish that the
package is unused, so do not lower priority on that basis.
Record usage separately from KEV and EPSS assessments and use it to inform
remediation decisions.

| Layer | What it answers | What it cannot answer |
| --- | --- | --- |
| KEV | Has exploitation of this CVE been established? | Whether this container loads the affected package[^kev] |
| EPSS | How likely is exploitation in the forecast period? | Whether this particular container will be compromised[^epss] |
| Runtime evidence | Was the package version observed through an executable or mapping here? | Whether the vulnerable function was reached[^harness] |

Keep every finding in the remediation workflow and attach its observation
result using the classifications from the procfs mapping article:

| Classification | Meaning |
| --- | --- |
| `confirmed` | A valid sample linked an executable or mapping to the finding's OS package name and version |
| `unknown` | Failed reads, missing metadata, ambiguous ownership, or identity/version problems prevented a reliable conclusion |
| `unobserved` | Valid collection produced no confirming evidence, including unsupported language-package mapping |

These classifications describe evidence, not severity.
Retain the observation time, successful sample count, and reason for an
unsuccessful match alongside the classification.[^harness]

Apply them as follows:

- A confirmed HIGH finding gains a local reason for prompt investigation, even without another signal increasing its priority.
- An unobserved HIGH finding for a KEV-listed CVE is still urgent; sampling absence does not cancel exploitation evidence.
- An unknown finding needs its collection problem investigated while retaining its existing remediation priority.
- An unobserved language-package finding needs appropriate mapping evidence, not a claim that its runtime never loaded it.

Avoid presenting the confirmed count as the complete fix list.
Attach an explanation such as “this installed package version was mapped
by this process at this time” to the existing finding.

## Verification procedure on your own host

This procedure manually checks whether running processes in one container
load packages reported by the scan.
It assumes a Debian-based container with `dpkg-query`, Trivy, and `jq`
available on the host.

Run these commands on the Linux Docker Engine host.
Replace placeholders with actual values before execution.

List the container's processes, then select a returned host PID.[^docker-top]

```bash
docker top '<container>' -eo pid,ppid,user
```

Extract executable file mapping paths for that PID. The expression retains
the pathname after removing the fixed columns.[^maps]

```bash
sudo awk '$2 ~ /x/ && $5 != 0 && $6 ~ /^\// {
  for (i = 0; i < 5; i++) sub(/^[^[:space:]]+[[:space:]]+/, "")
  print
}' '/proc/<host-pid>/maps'
```

Example output:

```text
/usr/sbin/nginx
/usr/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/libssl.so.3
```

Query the container's dpkg database through its process root. This example
uses the recorded libc path; a mapped `/usr/lib` path may correspond to a
database entry under `/lib`.[^root][^dpkg-query]

```bash
sudo dpkg-query --admindir='/proc/<host-pid>/root/var/lib/dpkg' \
  -S /lib/x86_64-linux-gnu/libc.so.6
```

Finally, scan the image ID used by that container and extract OS finding
identities from JSON.[^reporting]

```bash
trivy image --scanners vuln --format json '<running-image-id>' |
  jq -r '.Results[] | select(.Class == "os-pkgs") |
    .Vulnerabilities[]? |
    [.PkgName, .InstalledVersion, .VulnerabilityID] | @tsv'
```

Compare the resolved package with `PkgName`, then verify its version from
the container's package metadata against `InstalledVersion`. An ownership
query alone does not complete version confirmation.

This is a manual spot check. Repeat collection across the container's
processes before drawing conclusions about its observed packages. For
merged-`/usr` aliases, symlink ownership, permissions, and reliable version
matching, follow the [full procfs procedure](procfs-process-to-package-mapping.md).

## References

This article is based on information verified as of September 16, 2026.

- The [public development log](../development/runtime-prioritization.md#results-2026-09-12) records the measurement results and their limits.
- These results describe specific hosts and workloads, not a general confirmation rate or proof that unobserved packages are unused.

///Footnotes Go Here///

[^measurements]: [Runtime Evidence Prioritization: Feasibility Research, Results (2026-09-12)](https://kestrelynx.dev/development/runtime-prioritization/#results-2026-09-12)

[^trivy]: [Trivy: Vulnerability scanning](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)

[^kev]: [CISA: Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

[^epss]: [FIRST: EPSS Frequently Asked Questions](https://www.first.org/epss/faq)

[^proc]: [Linux manual: proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)

[^exe]: [Linux manual: proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)

[^maps]: [Linux manual: proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)

[^docker-top]: [Docker: docker container top](https://docs.docker.com/reference/cli/docker/container/top/)

[^root]: [Linux manual: proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)

[^dpkg-query]: [Debian: dpkg-query(1)](https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.en.html)

[^reporting]: [Trivy: Reporting](https://trivy.dev/docs/latest/configuration/reporting/)

[^harness]: [Runtime discovery measurement harness and README](https://github.com/kitsunetrail/kestrelynx/tree/main/experiments/runtime-discovery)

---

KestreLynx is a lightweight, open-source agent that scans images used by
running containers in Docker or Kubernetes and reports vulnerability changes
that require attention. It combines Trivy scan results with CISA KEV and
EPSS data to classify findings into urgent issues and noise.

[Learn more about KestreLynx](../index.md) · [View the source on GitHub](https://github.com/kitsunetrail/kestrelynx)
