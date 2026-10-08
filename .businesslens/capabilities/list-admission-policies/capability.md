---
domain: vap
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/vap/listpolicies.go
---

# List admission policies

List the policies in the admission policy library built into Kubescape, with the
control each one implements, whether it reads a parameter object, and which
names or control IDs are claimed more than once.
