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
  - text: The Product has the Kubescape Operator annotate the Workload with the reason
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: changes, facts: [Remediation annotation] }
    contexts: { cli: { place: cli } }
---

# Annotate a named workload

## Trigger

The User records that a finding on a workload is being acted on.

## Outcome

The operator annotates the workload asynchronously and records the outcome as
remediation events in the cluster.

## Edge cases

- Selecting by control or severity applies cluster-wide, and the Product warns before a confirmed run does so.
- Leaving out the reason is allowed with a warning.
- When no running, ready Kubescape Operator can be reached, or it refuses the request, the command fails and nothing changes.
