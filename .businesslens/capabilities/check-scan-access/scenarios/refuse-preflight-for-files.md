---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User asks for a dry run of a scan of local files
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product refuses, since only cluster scans can be checked
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse a preflight of local files

## Trigger

The scan target is local files, which have no cluster permissions to check.

## Outcome

Nothing is checked or scanned and the command fails.
