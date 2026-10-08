---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User deletes named cached settings
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product clears those settings and keeps the others
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: changes, facts: [Access key] }
    contexts: { cli: { place: cli } }
---

# Delete named settings

## Trigger

The User removes one credential, such as the access key, and keeps the rest.

## Outcome

Only the named settings are cleared; an unknown key is an error.
