# Development Logs

This section covers the problems being addressed, approaches tried, lessons learned during implementation, and technical decisions.

Development logs record how features were explored and implemented.
For instructions on currently available features, see [Documentation](../documentation/index.md).

- [Runtime Evidence Observation Environment Validation](runtime-environment-validation.md) — the permissions, continuous-observation overhead, and production start conditions and workflows to verify before implementing the adopted runtime evidence
- [Runtime Evidence Coverage Validation](runtime-coverage-validation.md) — how much of the packages a workload really used each method confirmed, evaluated against independent ground truth (measured)
- [Runtime evidence observation with eBPF: feasibility research](runtime-event-evidence.md) — whether eBPF-based execution and
  file-loading events can confirm the short-lived programs and language packages that sampling could not
- [Runtime evidence prioritization: feasibility research](runtime-prioritization.md) — whether processes,
  listening ports, and privileges can be linked to vulnerability findings to improve prioritization (research complete)
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
