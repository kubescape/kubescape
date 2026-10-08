---
appliesTo:
  - type: entity
    id: exception
references:
  - kind: code
    role: implementation
    target: core/cautils/getter/mergedexceptionsgetter.go
---

# Exceptions from a file or the account take precedence over cluster exceptions

Where an exception resource kept in the cluster covers the same control and
resource as an exception from the exceptions file or the Kubescape Cloud
account, only the latter applies; the cluster exception's other resources still
apply. When the cluster's exceptions cannot be read, the scan warns and goes on
with the others.
