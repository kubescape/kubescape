---
domain: policy
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/policy/test.go
  - kind: code
    role: implementation
    target: core/pkg/policytest/run.go
---

# Test custom rules

Run every test case of one rule or a directory of rules and report which pass.
