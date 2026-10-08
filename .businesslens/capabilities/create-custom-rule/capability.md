---
domain: policy
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/policy/init.go
  - kind: code
    role: implementation
    target: core/pkg/policytest/scaffold.go#Scaffold
---

# Create a custom rule

Scaffold a new Rego rule with metadata and two test cases — one resource it
flags and one it passes — whose expected results already match, ready to edit.
