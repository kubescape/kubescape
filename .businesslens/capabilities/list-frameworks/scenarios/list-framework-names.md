---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks for the frameworks
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product lists each Framework's name
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli::frameworks } }
---

# List framework names

## Trigger

The User wants to know which frameworks a scan can use.

## Outcome

The User sees the framework names, as a table, JSON, YAML or CSV.

## Edge cases

- When the frameworks cannot be fetched, the built-in names are listed.
