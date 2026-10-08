---
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go
---

# Validating Admission Policies

Generating the Kubescape CEL admission policy library and the bindings that put
its policies into effect.

## Boundary

It does not own applying them: the User applies the printed manifests to the
cluster.
