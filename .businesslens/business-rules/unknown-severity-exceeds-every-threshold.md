---
appliesTo:
  - type: capability
    id: scan-misconfigurations
  - type: capability
    id: scan-container-images
references:
  - kind: code
    role: implementation
    target: cmd/scan/framework.go#enforceSeverityThresholds
---

# An unknown severity counts as exceeding every threshold

A failed control or a vulnerability whose severity cannot be determined fails
any severity threshold.

## Rationale

A finding that cannot be ranked must not let a pipeline pass silently.
