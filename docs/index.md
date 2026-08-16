# Vulnerability notifications for Docker images

KestreLynx is a lightweight, open-source agent that scans the images currently
running on a Docker host and reports changes in vulnerabilities that require
attention.

Instead of sending the same complete scan results every day, KestreLynx
highlights **new findings**, **resolved findings**, **changes in fix
availability**, and **priority escalations**. It combines
[Trivy](https://trivy.dev/) scan results with
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and
[EPSS](https://www.first.org/epss/) data to separate urgent problems from noise.

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **Set up KestreLynx**

    ---

    Install one container on a Docker host and send the results to Slack or a
    webhook.

    [Setup instructions](documentation/getting-started.md)

-   :material-bell-badge-outline: **Notification decision logic**

    ---

    Learn how change detection and exploitation intelligence classify findings
    as act now, watch, or low.

    [How KestreLynx works](documentation/how-it-works.md)

</div>

!!! warning "Early release"
    KestreLynx is currently an MVP focused on CVE notifications for Docker
    hosts.
