---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User validates the settings
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: A required setting is missing or a URL is invalid
    kind: condition
    entities:
      - { entity: cached-configuration, effect: reads, facts: [Account ID, Access key, Cloud API URL, Cloud report URL] }
    contexts: { cli: { place: cli } }
  - text: The Product lists each failed check and fails the command
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Report an invalid configuration

## Trigger

The settings are not ready for the chosen use.

## Outcome

The User sees which checks failed, and the command fails.
