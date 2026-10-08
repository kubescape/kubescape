---
domain: scan
references:
  - kind: code
    role: implementation
    target: cmd/scan/fleetscan.go#fleetScan
  - kind: code
    role: implementation
    target: core/pkg/fleet/rollup.go#ComplianceRollup
---

# Fleet report

One combined report of a scan across several clusters, each reached through
its own kube context.

## Information kept

- **Cluster statuses** — whether each cluster was scanned, unreachable, failed or cancelled
- **Compliance rollup** — the fleet's compliance, excluding clusters that were not scanned, not scored or scanned with low coverage
- **Control matrix** — each control's status in each cluster
- **Divergence** — where clusters differ from one another or from the reference cluster
- **Reference cluster** — the cluster the others are compared against, when one is named
