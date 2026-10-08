---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks to annotate workloads without confirming
    kind: actor
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { cli: { place: cli } }
  - text: The Product has the Kubescape Operator report what it would annotate, changing nothing
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { cli: { place: cli } }
---

# Preview an annotation

## Trigger

The User checks which workloads a selection reaches.

## Outcome

Nothing changes; the User sees what a confirmed run would annotate.

## Edge cases

- A named workload combined with a control or severity selection is refused.
- A selection combined with a target namespace is refused.
- A request with no target at all is refused.
