---
domain: operator
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
  - kind: code
    role: implementation
    target: core/cautils/operatorscaninfo.go
---

# Annotate workloads

Have the Kubescape Operator mark workloads with a remediation annotation and a
reason — one named workload, or every workload failing a chosen control or at or
above a chosen severity. Nothing changes until the User confirms.
