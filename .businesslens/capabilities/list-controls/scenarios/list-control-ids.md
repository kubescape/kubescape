---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks for the controls, optionally of one Framework or matching a search
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
      - { entity: control, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product lists each Control with its ID, name and frameworks
    kind: product
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID, Name, Frameworks] }
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli::controls } }
---

# List control IDs

## Trigger

The User looks for the control that covers a concern.

## Outcome

The User sees each matching control's ID, name and frameworks, as a table, JSON,
YAML or CSV.
