---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a namespace and a level, optionally one Workload
    kind: actor
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Workload in the namespace, counting a managed one only through its owner when the owner is evaluated too
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { cli: { place: cli } }
  - text: The Product reports each failing Workload with the checks it would violate
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name] }
    contexts: { cli: { place: cli } }
---

# Predict a namespace's compliance

## Trigger

The User considers enforcing a Pod Security Standard on a namespace.

## Outcome

The User sees which workloads would fail and why; the command fails when any
workload fails or cannot be evaluated, which suits pipeline gating. Without a
level, Restricted is evaluated.

## Edge cases

- A workload the User names that is not found is an error.
- An unknown level is refused, and a namespace is required when no files are named.
