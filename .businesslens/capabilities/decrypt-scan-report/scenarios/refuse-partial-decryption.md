---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User decrypts a Scan report
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: Some encrypted value cannot be restored, such as a one-way resource ID from an older report
    kind: condition
    entities:
      - { entity: scan-report, effect: reads, facts: [Resource results] }
    contexts: { cli: { place: cli } }
  - text: The Product fails, naming where the encrypted value remains, and prints nothing
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse a partial decryption

## Trigger

The report cannot be fully restored.

## Outcome

No partially decrypted report is produced.
