---
appliesTo:
  - type: entity
    id: scan-request
    effect: creates
  - type: entity
    id: microservice-configuration
    facts: [Account]
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/datastructuremethods.go
---

# A scan request never chooses the Kubescape Cloud account

An account or access key sent with a scan request is ignored; results are
submitted only to the account the Kubescape Microservice is configured with.

## Rationale

Results can include cluster secrets and RBAC data, so a caller must not be able
to redirect them to an account of its choosing.
