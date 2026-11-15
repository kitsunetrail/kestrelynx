# How it works

## Feature overview {#overview}

KestreLynx scans images used by running containers with Trivy and groups findings by package.
It uses exploitation intelligence to assign priorities and compares results with saved history to identify changes such as new and resolved findings.

Slack and email show changes and current findings, while the generic webhook provides structured findings and diffs.
Notification conditions and explanations of notification displays and fields are documented on separate pages.

KestreLynx can also send remediation plans for Docker, Compose, and Kubernetes and create remediation PRs on GitHub (experimental, disabled by default).
Plans propose image and dependency updates; users handle merging, building, and deployment.
See [Remediation plans and pull requests](remediation.md) for details.

See [Getting started](getting-started.md) for setup instructions and [Configuration](configuration.md) for settings.

## Page guide {#contents}

This guide lists pages on decision logic, reading notifications, webhook field specifications, and outbound communication.

The following pages explain scan, change, and notification decisions, and outbound communication.

| What you want to know | Page |
| --- | --- |
| Scan targets, result grouping, and exploitation-based priority | <span id="cve"></span><span id="cve-priority-rules"></span>[Scan and priority decisions](scan-logic.md) |
| Package and image changes, and history transfer | [Change and history decisions](diff-logic.md) |
| Delivery conditions and redelivery for scan notifications and remediation plans | <span id="notification-conditions"></span><span id="remediation-slack-delivery"></span><span id="remediation-webhook-delivery"></span><span id="remediation-redelivery"></span>[Notification conditions](notification-conditions.md) |
| Communication destinations, transmitted information, and credential destinations | <span id="outbound-communication"></span><span id="kev-download"></span><span id="epss-download"></span><span id="hacker-news-search"></span><span id="trivy-downloads"></span><span id="github-communication"></span><span id="candidate-registry-communication"></span><span id="worker-image-downloads"></span><span id="tool-downloads"></span><span id="dependency-downloads"></span><span id="notification-delivery"></span><span id="credential-destinations"></span><span id="worker-network"></span>[Outbound communication](outbound-communication.md) |

The following pages explain how to read Slack displays and counts.

| What you want to know | Page |
| --- | --- |
| Report locations, notification language, section order, and counts | <span id="slack-display"></span><span id="notification-language"></span>[Report structure and counts](slack-display.md) |
| Package card contents and change labels | [Package cards and change labels](slack-package-display.md) |
| Usage labels, observation evidence, and muted finding displays | [Runtime usage display](slack-runtime-display.md) |
| Scan, threat intelligence, and Sensor (a container that observes packages in use) warnings | [Warnings](slack-warnings-display.md) |

The following pages describe the base, diff, and runtime field specifications for the generic webhook.

| What you want to know | Page |
| --- | --- |
| Fields for the overall payload, reports, images, and findings | <span id="generic-webhook"></span>[Base fields](webhook-reference.md) |
| Fields for package, image, and EOL changes | [Diff fields](webhook-diff-reference.md) |
| Fields for Sensor status, usage, and observation evidence | [Runtime fields](webhook-runtime-reference.md) |

The following pages describe the field specifications for remediation plans included in the generic webhook.

| What you want to know | Page |
| --- | --- |
| Remediation plan overview and shared objects | <span id="remediation-fields"></span>[Overview and shared objects](webhook-remediation-reference.md) |
| Published image items and Kubernetes workload information | <span id="remediation-image-fields"></span>[Published images](webhook-remediation-image-reference.md) |
| Base image plans, results for each running image, and rebuild estimates | <span id="remediation-dockerfile-fields"></span>[Base images](webhook-remediation-dockerfile-reference.md) |
| Results for each language package and guidance when a fixed version cannot be reached | <span id="remediation-language-fields"></span>[Items and packages](webhook-remediation-language-reference.md) |
| Language package update records, runtimes, and tools | [Update records](webhook-remediation-update-reference.md) |
| Checks before and after language package updates, and updated files | [Update checks](webhook-remediation-check-reference.md) |
| PR processing results, operation events, and problems that stop writes | <span id="remediation-pr-fields"></span><span id="remediation-json-example"></span><span id="remediation-operation-fields"></span><span id="remediation-problem-fields"></span>[PR processing](webhook-remediation-pr-reference.md) |
