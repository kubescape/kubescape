---
entities:
  - { entity: container-profile, shows: [Workload, Files opened, Capabilities used] }
entryPoints:
  - mcp-server: kubescape://container-profiles/{namespace}/{profile_name}
---

# Container profile

One container's recorded runtime behaviour.
