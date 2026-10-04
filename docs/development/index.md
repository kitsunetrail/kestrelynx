# Development Logs

This section covers the problems being addressed, approaches tried, lessons learned during implementation, and technical decisions.

Development logs record how features were explored and implemented.
For instructions on currently available features, see [Documentation](../documentation/index.md).

- 2026-10-02 [Kubernetes Sensor Feasibility](kubernetes-runtime-sensor.md) — validation of the Docker Sensor's permissions and isolation on Kubernetes and the changes needed for cgroup namespaces and AppArmor (design and feasibility validation only; implementation not started)
- 2026-09-25 [Runtime Evidence Prioritization Development](runtime-prioritization-development.md) — implementation plan defining in-use classification, its effect on prioritization, and the observation component’s placement and permissions (design finalized)
- 2026-09-22 [Runtime Evidence Observation Environment Validation](runtime-environment-validation.md) — the permissions, continuous-observation overhead, and production start conditions and workflows verified before implementing the adopted runtime evidence (measurement complete)
- 2026-09-19 [Runtime Evidence Coverage Validation](runtime-coverage-validation.md) — how much of the packages a workload really used each method confirmed, evaluated against independent ground truth (measured)
- 2026-09-13 [Runtime evidence observation with eBPF: feasibility research](runtime-event-evidence.md) — whether eBPF-based execution and
  file-loading events can confirm the short-lived programs and language packages that sampling could not
- 2026-09-09 [Runtime evidence prioritization: feasibility research](runtime-prioritization.md) — whether processes,
  listening ports, and privileges can be linked to vulnerability findings to improve prioritization (research complete)
- 2026-09-06 [Developing Kubernetes support](kubernetes-support.md) — connecting Kubernetes workloads to scanning, prioritization,
  and diff notifications, starting with K3s + containerd (implemented; verified end to end on a real K3s cluster)
- 2026-09-05 [The Kubernetes vulnerability scanning landscape](kubernetes-scanning-landscape.md) — what existing tools already
  cover and what we found missing, ahead of Kubernetes support (research note)
- 2026-08-31 [Designing the remediation relations model](remediation-relations-model.md) — the relation models that connect
  a detected vulnerability to a proposal for where to fix it (models defined)
- 2026-08-25 [Developing the environment and workload model](environment-workload-model.md) — identifying environments and
  mapping containers to services, connected to vulnerability records (implemented)
- 2026-08-22 [Developing the image identity model](image-identity-model.md) — migration from image-name-based processing to identifying
  image content by immutable digests (implemented)
