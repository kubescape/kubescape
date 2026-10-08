---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User runs a fix of local files without skipping confirmation
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: Confirmation is declined, or the command is not attached to an interactive terminal
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product applies nothing
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Apply nothing without confirmation

## Trigger

An in-place fix is not confirmed.

## Outcome

No file changes; in a pipeline the User must skip confirmation explicitly for
fixes to be applied.
