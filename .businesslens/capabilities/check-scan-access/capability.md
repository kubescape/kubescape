---
domain: scan
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/scan/scan.go#GetScanCommand
  - kind: code
    role: implementation
    target: core/pkg/resourcehandler/preflight.go
  - kind: code
    role: implementation
    target: core/core/scan.go
---

# Check scan access

Check, before scanning a cluster, whether the current credentials can list every
resource type the requested frameworks or controls need, without collecting
resources or evaluating controls.
