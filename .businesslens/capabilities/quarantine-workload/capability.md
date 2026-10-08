---
domain: operator
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
---

# Quarantine workloads

Have the Kubescape Operator isolate workloads behind a deny-all network policy —
one named workload, or every workload failing a chosen control or at or above a
chosen severity. Nothing changes until the User confirms.
