---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks the Kubescape Operator for a configuration scan, optionally naming frameworks and namespaces
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli } }
  - text: The Product finds the running operator in the cluster and sends it the request to scan
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product reports that the operator accepted the request
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Trigger a configuration scan

## Trigger

The User wants fresh in-cluster results after a change.

## Outcome

The operator runs the scan and keeps its results in the cluster; without named
frameworks it scans against all of them.

## Edge cases

- Including and excluding namespaces in one request is refused.
- Host scanning can be requested with the scan.
