---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks for the admission policies, optionally only those that implement a control
    kind: actor
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product lists each library policy with its control ID, parameter use and duplicate markers
    kind: product
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
---

# List the library's policies

## Trigger

The User looks for the policy to bind.

## Outcome

The User sees the policy names and control IDs a binding accepts, and which of
them cannot be used because they are claimed more than once.
