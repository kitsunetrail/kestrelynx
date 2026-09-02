# Development Logs

This section covers the problems being addressed, approaches tried, lessons learned during implementation, and technical decisions.

Development logs record how features were explored and implemented.
For instructions on currently available features, see [Documentation](../documentation/index.md).

- [Designing the remediation relations model](remediation-relations-model.md) — the relation models that connect
  a detected vulnerability to a proposal for where to fix it (models defined)
- [Developing the environment and workload model](environment-workload-model.md) — identifying environments and
  mapping containers to services, connected to vulnerability records (implemented)
- [Developing the image identity model](image-identity-model.md) — migration from image-name-based processing to identifying
  image content by immutable digests (implemented)
