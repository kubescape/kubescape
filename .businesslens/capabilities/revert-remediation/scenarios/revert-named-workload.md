---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a Workload by kind, name and namespace and confirms the revert
    kind: actor
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { cli: { place: cli } }
  - text: The Product has the Kubescape Operator remove the Workload's remediation annotation and quarantine
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: changes, facts: [Remediation annotation, Quarantine] }
    contexts: { cli: { place: cli } }
---

# Revert a named workload

## Trigger

A remediation is no longer wanted.

## Outcome

The operator removes what it applied, asynchronously; without confirmation the
request is only a dry run.

## Edge cases

- When no running, ready Kubescape Operator can be reached, or it refuses the request, the command fails and nothing changes.
