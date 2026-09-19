---
description: "Technical guides to CVE, KEV, EPSS, CVSS, and Trivy. Understand vulnerability data, read scan results, and prioritize remediation."
---

# Technical Articles

This section covers foundational knowledge, operational practices, and related security technologies.

- August 23, 2026 — [CVE Basics and the Publication Process](cve-basics-and-publication-flow.md) — what a CVE ID represents,
  how the CVE Program is organized, and the process from vulnerability reporting to publication
- August 27, 2026 — [KEV Catalog Basics and Usage](kev-known-exploited-vulnerabilities.md) — what the KEV Catalog is,
  what qualifies a vulnerability for inclusion, what data the catalog provides, and how to use it to prioritize remediation
- August 30, 2026 — [EPSS Basics and How to Check Scores](epss-exploit-prediction-scoring-system.md) — what EPSS measures,
  how to interpret and retrieve scores, how the model works, and how to use EPSS in vulnerability management
- September 8, 2026 — [CVSS Basics and the Scoring and Publication Process](cvss-basics-scoring-and-publication.md) — what CVSS measures,
  how assessments are scored and published, and how to check scores and vector strings in NVD
- September 10, 2026 — [Trivy Basics and How to Read Scan Results](trivy-basics-scan-results.md) — what Trivy scans,
  how to read its JSON output, and considerations when using scan results for vulnerability management
- September 13, 2026 — [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md) — how to find a container's host PIDs,
  read exe, maps, status and sockets under /proc, resolve paths to dpkg, apk and distroless packages, and the pitfalls and permission checks measured on real images
- September 16, 2026 — [How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans](which-container-scan-findings-are-actually-running.md) — validation of matching observed files to scan findings,
  limited ground-truth comparisons, detection and mapping limitations, and unevaluated coverage
- September 17, 2026 — [Reading Process Information Without Root Using Linux Capabilities](linux-capabilities-read-process-info.md) — the roles of CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, ptrace access checks and file permissions, measured permission conditions, and the collector used for the measurements
- September 18, 2026 — [Understanding and Checking Trivy Status Values](trivy-vulnerability-status.md) — Status versus FixedVersion, actual scan records, data-source differences, filtering, and remediation decisions
- September 18, 2026 — [Observing Container Execution and File Opens with bpftrace](bpftrace-container-exec-open-events.md) — the programs used for measurement, tracepoints and cgroup attribution, short-lived execution capture, observation timing, and lost records
