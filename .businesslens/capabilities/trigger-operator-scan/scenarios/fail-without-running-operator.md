---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User asks the Kubescape Operator for a scan
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: No operator is installed in the namespace, none of its pods is running and ready, or it does not accept the request
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product fails the command, saying which
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fail when the operator is not available

## Trigger

The operator cannot take the request.

## Outcome

No scan is requested and the command fails with the reason.
