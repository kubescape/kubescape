---
appliesTo:
  - type: entity
    id: admission-policy-binding
    effect: creates
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go#checkParameterReference
  - kind: code
    role: implementation
    target: cmd/vap/vap.go
---

# A binding never widens the policy it binds

A binding binds exactly one library policy, named or found by its control ID; it
may narrow the resource types the policy matches but never add one, carries a
parameter reference exactly when the policy reads one, and combines Audit with
Deny or Warn but never Deny with Warn. Namespaces alone never exempt
cluster-scoped resources.
