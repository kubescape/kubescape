---
appliesTo:
  - type: capability
    id: fix-misconfigurations
  - type: entity
    id: manifest
    effect: creates
references:
  - kind: code
    role: implementation
    target: core/pkg/fixhandler/fixhandler.go
---

# Cluster fixes are never made from redacted records

A cluster fix is not offered for a Secret, a ConfigMap, a workload with
container environment variables, or a resource owned by another resource; each
is listed as unfixed with its reason.

## Rationale

Scan reports replace environment values and Secret and ConfigMap data with
placeholders, so a manifest rendered from them would overwrite real
configuration; an owned resource is recreated by its owner.
