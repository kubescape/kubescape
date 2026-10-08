---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a Workload by kind, name and namespace, gives a reason and confirms
    kind: actor
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { cli: { place: cli } }
  - text: The Product has the Kubescape Operator isolate the Workload with a deny-all network policy
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: changes, facts: [Quarantine] }
    contexts: { cli: { place: cli } }
---

# Quarantine a named workload

## Trigger

A workload is judged too risky to keep reachable.

## Outcome

The operator isolates the workload asynchronously and records the outcome as
remediation events; without confirmation the request is only a dry run.

## Edge cases

- When no running, ready Kubescape Operator can be reached, or it refuses the request, the command fails and nothing changes.
