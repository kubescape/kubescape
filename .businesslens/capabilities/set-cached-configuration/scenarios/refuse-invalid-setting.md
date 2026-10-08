---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User sets an unknown key, an empty value, or a URL that is not http or https with a host
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product refuses and leaves the Cached configuration unchanged
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
---

# Refuse an invalid setting

## Trigger

The setting cannot be saved as given.

## Outcome

Nothing is saved and the command fails.
