---
domain: vap
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go
  - kind: code
    role: implementation
    target: cmd/vap/vap.go#parseValidationActions
  - kind: code
    role: implementation
    target: cmd/vap/vap.go#checkParameterReference
---

# Create an admission policy binding

Generate a binding that puts one library policy into effect for chosen
namespaces and labels, with the action the cluster takes on a violation, and
print it for the User to apply.
