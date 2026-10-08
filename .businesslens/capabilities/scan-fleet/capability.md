---
domain: scan
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/scan/fleetscan.go#fleetScan
  - kind: code
    role: implementation
    target: core/pkg/fleet/rollup.go#ComplianceRollup
---

# Scan a fleet of clusters

Scan several clusters in one run, one kube context each, writing a report per
cluster and, on request, one combined fleet report that rolls up compliance and
shows where clusters diverge.
