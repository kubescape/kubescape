---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User asks for a binding with an invalid name, both or neither of a policy and a control, an unknown control, or a parameter reference the policy does not match
    kind: actor
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product refuses, saying what is wrong, and prints nothing
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse an invalid binding

## Trigger

The binding cannot be generated as asked.

## Outcome

No binding is printed and the command fails. A policy that reads a parameter
object requires a parameter reference, and one that does not refuses it.
