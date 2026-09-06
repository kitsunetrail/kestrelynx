# The Kubernetes Vulnerability Scanning Landscape

- **Status:** Research notes ahead of work on Kubernetes support
- **Published:** September 5, 2026

## Overview

As we considered Kubernetes support for KestreLynx, we reviewed the capabilities of existing vulnerability scanning tools to define the scope of the features we would add.

We plan to use the same CISA KEV and EPSS prioritization approach for Kubernetes that KestreLynx already implements.

This article summarizes what existing tools provide and where additional implementation is needed to meet KestreLynx's requirements. We examined three areas:

| Area | What we checked |
| --- | --- |
| Scanning and prioritization | Whether tools can discover running images and prioritize remediation using KEV, EPSS, and similar data |
| Change notifications | Whether notifications can distinguish new, worsened, and resolved vulnerabilities |
| Image identification | Whether tools can detect content changes behind an unchanged tag and recognize when multiple workloads use the same image |

The findings are based on the versions and documentation we checked as of September 5, 2026.

## What existing tools already do

### Trivy Operator

[Trivy Operator](https://aquasecurity.github.io/trivy-operator/latest/) is a tool that continuously scans a Kubernetes cluster.

- The version reviewed is v0.34.0, released on August 24, 2026, and bundling Trivy v0.74.0.
- Scan results are stored as Kubernetes custom resources, with the main reports listed below.

| Report | Coverage |
| --- | --- |
| `VulnerabilityReport` | Image vulnerabilities |
| `ConfigAuditReport` | Configuration audits |
| `ExposedSecretReport` | Exposed secrets |
| `RbacAssessmentReport` | RBAC assessments |
| `InfraAssessmentReport` | Cluster infrastructure assessments |
| `ClusterComplianceReport` | Compliance assessments |
| `SbomReport` | Software bills of materials (SBOMs) |

- Beyond image vulnerabilities, a single operator covers configuration audits, RBAC, cluster infrastructure assessments, and compliance reporting, exceeding KestreLynx's planned scope.
- It also provides [Prometheus metrics](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/metrics/), including per-severity counts and per-CVE information when enabled.
- A webhook can send each report in full as it is generated.
- For notifications to Slack, Teams, or similar channels, the official documentation points to integrations with [Postee](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/webhook/) or [Policy Reporter](https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/policy-reporter/).
- Chat notifications rely on external tools rather than a built-in feature.

### Kubescape

[Kubescape](https://kubescape.io/docs/operator/) is a CNCF Incubating project.

- It provides image scanning using Grype, configuration checks, and RBAC analysis.
- One of its distinctive features is **relevancy**, which uses runtime information to narrow down vulnerabilities.
- An eBPF-based node-agent observes which packages a container actually loads.
- It uses that information to filter the vulnerability list down to vulnerabilities associated with the observed packages.
- This mechanism is a promising way to reduce CVE noise.
- KestreLynx does not plan to implement this runtime observation capability.

### Grype and k8s-inventory

[Grype](https://github.com/anchore/grype) is a vulnerability scanner with [CISA KEV and EPSS support](https://github.com/anchore/grype/pull/2587).

- It sorts results by a “Risk” score that combines this information by default.
- The scanner itself can handle prioritization after scanning.
- This is a significant development in the growing trend for vulnerability scanners to handle prioritization themselves rather than leave it entirely to downstream tools.
- For continuous cluster monitoring, Anchore pairs Grype with [`k8s-inventory`](https://github.com/anchore/k8s-inventory).
- `k8s-inventory` is an agent that periodically queries the Kubernetes API to collect running images.
- It can run inside the cluster or connect externally using kubeconfig.
- This collection method is similar to KestreLynx's planned approach to Kubernetes discovery.

### OWASP Dependency-Track

[Dependency-Track](https://docs.dependencytrack.org/) was the closest match among the open-source tools reviewed for our prioritization and notification requirements.

- It imports CISA and ENISA EU KEV data by default and [supports EPSS](https://dependencytrack.org/news/dependency-track-5-1/).
- It provides eight notification integrations, including Slack, Teams, Mattermost, Jira, and email.
- It can send event-driven notifications for newly discovered vulnerabilities.

### Policy Reporter

[Policy Reporter](https://github.com/kyverno/policy-reporter) is a lightweight tool that watches `PolicyReport` resources and sends notifications about newly discovered policy violations to Slack, Teams, and other destinations.

- It can be self-hosted.
- It also integrates with Trivy Operator through an adapter to watch its reports.

### Commercial platforms

Some commercial products offer more advanced prioritization and notification capabilities.

| Product | Main capabilities |
| --- | --- |
| [Wiz](https://www.wiz.io/solutions/vulnerability-management) | Prioritization using CVSS, EPSS, and CISA KEV, plus environmental context such as external exposure |
| [Snyk](https://snyk.io/product/container-vulnerability-management/) | Prioritization using CVSS, EPSS, and CISA KEV |
| [Sysdig Secure](https://docs.sysdig.com/en/sysdig-secure/vulnerability-management/) | Prioritization based on runtime usage (In Use) |
| [ARMO Platform](https://www.armosec.io/armo-vs-kubescape/) | Kubescape's commercial counterpart, with eBPF-based relevancy and built-in Slack, Teams, and Jira notifications |

- These products primarily target larger organizations and differ from a self-hosted, single-binary deployment.
- Wiz's cloud scanning is agentless by default.
- The Kubernetes integrations of Sysdig, ARMO, and Snyk generally combine an in-cluster agent with a SaaS backend.

## What we could not confirm

We require the following three capabilities for Kubernetes, all of which are already implemented for Docker hosts.

| Requirement | For Docker hosts | For Kubernetes |
| --- | --- | --- |
| KEV/EPSS-based prioritization and change notifications that distinguish new, worsened, and resolved findings compared with the previous results | Implemented | The same mechanism is required |
| Distinguishing an actual fix from a finding simply no longer being observable when determining resolution | Implemented | The same distinction is required |
| Identifying image content by digest to deduplicate scans, associate images with workloads, and deduplicate notifications | Implemented | Support for all three uses is required |

The following subsections describe what existing tools provide in the versions and documented configurations we checked, and the additional implementation users would need to supply to meet these requirements by combining existing tools.

### Notifications that distinguish new, worsened, and resolved findings

In this research, we could not confirm a tool that provides KEV/EPSS-based prioritization and notifications that distinguish **new, worsened, and resolved** findings, while also distinguishing an actual fix from an interruption in observation when reporting resolution, in a single component that can be self-hosted.

- Dependency-Track supports prioritization and notifications for new findings, but within the scope we checked, it does not provide notifications for resolutions or severity increases.
- Trivy Operator's webhook also sends full reports, so users would need to implement a separate comparison against previous results to meet the change-notification requirement with it.

### Determining resolution when metrics disappear

Trivy Operator's per-vulnerability (per-CVE) metrics can be combined with Prometheus and Alertmanager to send a notification when a vulnerability is detected and another when the alert resolves.

- A metric disappearing does not by itself establish that a vulnerability was fixed.
  - Metrics can also disappear when a workload is scaled down or stopped, a report expires, or metric collection is interrupted.
  - Reporting this as a resolution without additional handling may tell users that a vulnerability was fixed when it was not.
- Severity changes also need care when metrics are distinguished by severity.
  - When severity changes, the monitoring system sees the old item disappear and a new item appear.
  - Without additional handling, a worsening of the same vulnerability may be reported as “the previous vulnerability was resolved” and “a different vulnerability was newly detected.”
- To determine this correctly, users need to design and implement two kinds of processing:
  - Check that the target's state can still be observed successfully to distinguish a fix from an interruption in observation.
  - Match the same vulnerability before and after a change to determine whether it is new, worsened, or resolved.
- This processing can be implemented within Prometheus or handled in a separate application.

### Identifying images by digest

When identifying images, we need to distinguish a tag from the content it points to.

- An image's content can change after an update even when its tag stays the same.
  - For example, the name `example/api:latest` may remain unchanged while pointing to different content after an update.
  - Recording the digest that identifies the content makes it possible to track this change.
- The SBOM generation tool `sbom-operator` that we examined uses the tag to identify the record when sending results to Dependency-Track, if a tag is present.
  - Even when the tag points to different content and the digest changes, the same record is overwritten.
  - It uses the digest to identify the record only when no tag is present.
  - In this configuration, a change in the content a tag points to is not tracked as a distinct image.
- With this behavior in mind, we examined the following three uses of digests separately:

| Area checked | Purpose |
| --- | --- |
| Scan deduplication | Avoid duplicate scans of images with the same digest |
| Workload correlation | Recognize that multiple workloads use an image with the same digest |
| Notification deduplication | Avoid duplicate notifications for the same digest |

- We found partial support for each, but could not confirm a configuration that meets all three together.
  - To meet the requirements by combining the existing tools we checked, users need to confirm what those tools support for each use and implement the missing processing.
- In particular, the ability to correlate multiple workloads using an image with the same digest may also exist in other tools.
  - We will continue comparing and verifying this capability against existing tools.

These findings are based on the versions and documentation we checked as of September 5, 2026. They do not establish that capabilities we could not confirm are absent from other tools or configurations, or that they will remain unavailable in the future.

## Our approach to Kubernetes support

Based on these findings, we plan to add the following capabilities:

- **Discovering running images:** Retrieve information through read-only access to the Kubernetes API (`kube-apiserver`), without direct node access or privileged agents.
- **Prioritization and change notifications:** Apply the KEV/EPSS-based prioritization and notifications for new, worsened, and resolved findings already implemented for Docker hosts to Kubernetes workloads.
- **Tracking image content:** Use digests to track changes in the content a tag points to, with the aim of correlating workloads that use the same image content and avoiding duplicate scans and notifications for that content.

---

This article is part of the KestreLynx development log. [Learn more about KestreLynx](../index.md)
