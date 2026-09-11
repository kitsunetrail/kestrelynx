# Container image vulnerability notifications for Docker and Kubernetes

KestreLynx is a lightweight, open-source agent that scans images used by
running containers in Docker or Kubernetes and reports changes in
vulnerabilities that require attention.

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

!!! info "Kubernetes verification scope"
    Kubernetes discovery, scanning, and
    notifications have been verified on a single-node K3s cluster with
    containerd on linux/amd64. See the [verification record and limitations](development/kubernetes-support.md)
    for details, including configurations that have not been verified.
