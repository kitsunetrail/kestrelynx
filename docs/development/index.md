# Development Logs

This section covers the problems being addressed, approaches tried, lessons learned during implementation, and technical decisions.

Development logs record how features were explored and implemented.
For instructions on currently available features, see [Documentation](../documentation/index.md).

- [Runtime evidence prioritization: feasibility research](runtime-prioritization.md) — investigating whether processes,
  listening ports, and privileges can be linked to vulnerability findings to improve prioritization (research in progress)
- [Developing Kubernetes support](kubernetes-support.md) — connecting Kubernetes workloads to scanning, prioritization,
  and diff notifications, starting with K3s + containerd (implemented; verified end to end on a real K3s cluster)
- [The Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md) — what existing tools already
  cover and what we found missing, ahead of Kubernetes support (research note)
- [Designing the remediation relations model](remediation-relations-model.md) — the relation models that connect
  a detected vulnerability to a proposal for where to fix it (models defined)
- [Developing the environment and workload model](environment-workload-model.md) — identifying environments and
  mapping containers to services, connected to vulnerability records (implemented)
- [Developing the image identity model](image-identity-model.md) — migration from image-name-based processing to identifying
  image content by immutable digests (implemented)
