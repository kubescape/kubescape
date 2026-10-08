---
appliesTo:
  - type: capability
    id: deploy-admission-policy-library
  - type: capability
    id: create-admission-policy-binding
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go#writeOutput
---

# Admission policies and bindings are printed, never applied

The admission policy library and its bindings are printed or written to a file;
the User applies them to a cluster.
