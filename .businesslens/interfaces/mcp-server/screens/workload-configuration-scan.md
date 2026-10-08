---
entities:
  - { entity: workload-configuration-scan, shows: [Workload, Control results] }
entryPoints:
  - mcp-server: kubescape://configuration-manifests/{namespace}/{manifest_name}
---

# Workload configuration scan

One workload's detailed misconfiguration results.
