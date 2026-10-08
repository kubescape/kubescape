---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks to delete the incremental scan cache
    kind: actor
    actor: user
    entities:
      - { entity: incremental-scan-cache, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product clears the Incremental scan cache
    kind: product
    actor: user
    entities:
      - { entity: incremental-scan-cache, effect: changes, facts: [Cached results] }
    contexts: { cli: { place: cli } }
---

# Clear incremental results

## Trigger

The User wants the next incremental scan to start from nothing, for example
after changing exceptions.

## Outcome

No cached results remain; the cached Kubescape Cloud settings are untouched.
