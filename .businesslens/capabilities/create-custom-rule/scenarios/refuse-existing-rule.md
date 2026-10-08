---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User names a rule directory that already exists, or a name that is not lowercase letters, digits and dashes
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product refuses and writes nothing
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse to overwrite a rule

## Trigger

The rule cannot be created as named.

## Outcome

Nothing is written; an existing rule is overwritten only when the User forces
it.
