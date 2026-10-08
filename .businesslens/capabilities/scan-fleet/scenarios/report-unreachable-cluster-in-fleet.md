---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User scans several kube contexts with a combined report
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: One of the clusters cannot be reached
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product scans the others and writes the Fleet report marking that cluster unreachable and leaving it out of the rollup
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
      - { entity: fleet-report, effect: creates, facts: [Cluster statuses, Compliance rollup, Control matrix, Divergence] }
    contexts: { cli: { place: cli } }
  - text: The Product fails the command, saying how many contexts failed
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fleet scan with an unreachable cluster

## Trigger

A cluster in the fleet is down or its context is wrong.

## Outcome

The reachable clusters are still reported, and the command fails.
