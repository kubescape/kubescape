---
domain: operator
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
---

# Revert remediation

Have the Kubescape Operator remove the remediation annotations and quarantine
policies it applied. Nothing changes until the User confirms.
