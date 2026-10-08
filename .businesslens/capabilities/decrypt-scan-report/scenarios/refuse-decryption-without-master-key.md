---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User names an encrypted Scan report
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: No master key is set, both kinds are set, or the key is not usable
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product refuses, naming the master key problem
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse decryption without a usable master key

## Trigger

The master key is missing or invalid.

## Outcome

Nothing is decrypted and the command fails.
