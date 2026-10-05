---
description: "Follow one curl run from bpftrace output to JSONL events in nine interactive steps, including open entry/exit pairing and container attribution."
template: explainer.html
explainer: bpftrace-events
hide:
  - navigation
  - toc
---

# Interactive Guide to the bpftrace Measurement Workflow

Published: October 5, 2026

## Overview

- This nine-step diagram follows one `curl` run inside a container, showing how its execution and file open become bpftrace output lines and then events with a container ID
    - Executions and file opens by other programs, such as `node`, are recorded through the same flow
- It illustrates the measurement workflow used in [Observing Container Execution and File Opens with bpftrace](bpftrace-container-exec-open-events.md)
- The values are illustrative examples; the E, O, and X lines follow the actual script output format

## Diagram

<div class="klx-explainer" data-klx-explainer="bpftrace-events" tabindex="-1">
  <p class="klx-fallback">JavaScript is required to use this interactive guide.</p>
</div>

For measurement results and implementation details, see [Observing Container Execution and File Opens with bpftrace](bpftrace-container-exec-open-events.md).
For the periodic-read approach and its sampling limitations, see [How to Map Running Container Processes to OS Packages with procfs](procfs-process-to-package-mapping.md).

---

KestreLynx is a lightweight open-source agent that scans images used by running Docker or Kubernetes containers and notifies you when actionable vulnerabilities change. It combines Trivy scan results with CISA KEV and EPSS to separate urgent issues from noise.

[About KestreLynx](../index.md) · [View source on GitHub](https://github.com/kitsunetrail/kestrelynx)
