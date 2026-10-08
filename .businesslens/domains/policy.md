---
references:
  - kind: code
    role: implementation
    target: cmd/policy/policy.go
---

# Policy

Authoring custom Rego rules and their test cases, and testing them.

## Boundary

Policy does not own the frameworks and controls Kubescape downloads, nor
evaluating custom rules during a scan, which belongs to Scan.
