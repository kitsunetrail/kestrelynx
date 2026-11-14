---
description: "Technical guides to CVE, KEV, EPSS, CVSS, and Trivy. Understand vulnerability data, read scan results, and prioritize remediation."
---

# Technical Articles

This section covers foundational knowledge, operational practices, and related security technologies.

<div class="kl-log__item" markdown>

October 5, 2026
{ .kl-log__date }

[Interactive Guide to the procfs Package Mapping Workflow](procfs-package-mapping-interactive.md)
{ .kl-log__title }

One nginx worker in eight steps, path extraction from maps, package ownership and version lookup with dpkg, Trivy matching, and confirmation of loading

</div>

<div class="kl-log__item" markdown>

October 5, 2026
{ .kl-log__date }

[Interactive Guide to the bpftrace Measurement Workflow](bpftrace-event-observation-interactive.md)
{ .kl-log__title }

One curl run in nine steps, E/O/X output lines, open entry/exit pairing, container attribution, and conversion to JSONL

</div>

<div class="kl-log__item" markdown>

September 20, 2026
{ .kl-log__date }

[Mapping Language Packages Detected by Trivy to Runtime Files](trivy-language-packages-runtime-mapping.md)
{ .kl-log__title }

Package detection and file mapping for Python, Node.js, Java, and Go, measured results by method, observation timing, and evidence granularity

</div>

<div class="kl-log__item" markdown>

September 19, 2026
{ .kl-log__date }

[Observing Container Execution and File Opens with bpftrace](bpftrace-container-exec-open-events.md)
{ .kl-log__title }

The programs used for measurement, tracepoints and cgroup attribution, short-lived execution capture, observation timing, and lost records

</div>

<div class="kl-log__item" markdown>

September 18, 2026
{ .kl-log__date }

[Understanding and Checking Trivy Status Values](trivy-vulnerability-status.md)
{ .kl-log__title }

Status versus FixedVersion, actual scan records, data-source differences, filtering, and remediation decisions

</div>

<div class="kl-log__item" markdown>

September 17, 2026
{ .kl-log__date }

[Reading Process Information Without Root Using Linux Capabilities](linux-capabilities-read-process-info.md)
{ .kl-log__title }

The roles of CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, ptrace access checks and file permissions, measured permission conditions, and the collector used for the measurements

</div>

<div class="kl-log__item" markdown>

September 16, 2026
{ .kl-log__date }

[How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans](which-container-scan-findings-are-actually-running.md)
{ .kl-log__title }

Validation of matching observed files to scan findings, limited ground-truth comparisons, detection and mapping limitations, and unevaluated coverage

</div>

<div class="kl-log__item" markdown>

September 13, 2026
{ .kl-log__date }

[How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md)
{ .kl-log__title }

How to find a container's host PIDs, read exe, maps, status and sockets under /proc, resolve paths to dpkg, apk and distroless packages, and the pitfalls and permission checks measured on real images

</div>

<div class="kl-log__item" markdown>

September 10, 2026
{ .kl-log__date }

[Trivy Basics and How to Read Scan Results](trivy-basics-scan-results.md)
{ .kl-log__title }

What Trivy scans, how to read its JSON output, and considerations when using scan results for vulnerability management

</div>

<div class="kl-log__item" markdown>

September 8, 2026
{ .kl-log__date }

[CVSS Basics and the Scoring and Publication Process](cvss-basics-scoring-and-publication.md)
{ .kl-log__title }

What CVSS measures, how assessments are scored and published, and how to check scores and vector strings in NVD

</div>

<div class="kl-log__item" markdown>

August 30, 2026
{ .kl-log__date }

[EPSS Basics and How to Check Scores](epss-exploit-prediction-scoring-system.md)
{ .kl-log__title }

What EPSS measures, how to interpret and retrieve scores, how the model works, and how to use EPSS in vulnerability management

</div>

<div class="kl-log__item" markdown>

August 27, 2026
{ .kl-log__date }

[KEV Catalog Basics and Usage](kev-known-exploited-vulnerabilities.md)
{ .kl-log__title }

What the KEV Catalog is, what qualifies a vulnerability for inclusion, what data the catalog provides, and how to use it to prioritize remediation

</div>

<div class="kl-log__item" markdown>

August 23, 2026
{ .kl-log__date }

[CVE Basics and the Publication Process](cve-basics-and-publication-flow.md)
{ .kl-log__title }

What a CVE ID represents, how the CVE Program is organized, and the process from vulnerability reporting to publication

</div>
