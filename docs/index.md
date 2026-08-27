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

- :material-rocket-launch-outline: [Setup instructions](documentation/getting-started.md)
- :material-bell-badge-outline: [Notification decision logic](documentation/how-it-works.md)
- :material-hammer-wrench: [Development logs](development/index.md)
- :material-book-open-page-variant-outline: [Technical articles](articles/index.md)

!!! warning "Early release"
    KestreLynx is currently an MVP focused on CVE notifications for Docker
    hosts.
