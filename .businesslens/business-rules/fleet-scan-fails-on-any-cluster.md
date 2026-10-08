---
appliesTo:
  - type: capability
    id: scan-fleet
  - type: entity
    id: fleet-report
references:
  - kind: code
    role: implementation
    target: cmd/scan/fleetscan.go
---

# A fleet scan fails when any cluster fails

A fleet scan fails when any context could not be scanned, after reporting the
others; such clusters are left out of the compliance rollup.
