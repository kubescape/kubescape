---
appliesTo:
  - type: capability
    id: fix-misconfigurations
  - type: entity
    id: workload
references:
  - kind: code
    role: implementation
    target: core/core/clusterfix.go#emitClusterFixes
---

# Fixing never changes a cluster

Fixes for a cluster scan are printed or written as manifests for the User to
review and apply; Kubescape never applies them to the cluster.

## Rationale

A cluster scan records objects as they were scanned, with some values redacted,
so only the User can judge whether a fix still applies.
