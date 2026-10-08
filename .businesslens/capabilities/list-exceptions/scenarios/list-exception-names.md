---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks for the exceptions
    kind: actor
    actor: user
    entities:
      - { entity: exception, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli::exceptions } }
  - text: The Product lists the name of each Exception
    kind: product
    actor: user
    entities:
      - { entity: exception, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli::exceptions } }
---

# List exception names

## Trigger

The User wants to know which exceptions a scan would apply.

## Outcome

The User sees the exception names.
