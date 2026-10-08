---
references:
  - kind: code
    role: implementation
    target: cmd/scan/scan.go#GetScanCommand
---

# Scan

Assessing Kubernetes resources and container images: misconfiguration scans of
clusters and files, fleet scans across clusters, image vulnerability scans, the
access check before a cluster scan, and the scan contracts that pin how a
repository is scanned.

## Boundary

Scan owns producing reports. It does not own acting on them — fixing
manifests, patching images or comparing reports — nor scans the Kubescape
Operator runs inside a cluster.
