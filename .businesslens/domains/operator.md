---
references:
  - kind: code
    role: implementation
    target: cmd/operator/operator.go
---

# Operator

Asking the Kubescape Operator running in a cluster to scan it and to act on
findings.

## Boundary

Operator does not own what the Kubescape Operator then does or keeps; that is
the Operator's own behaviour, outside Kubescape.
