---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User asks for a scan with encrypted metadata
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: No master key is set, both kinds of master key are set, or the key is shorter than 16 bytes
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product refuses with the master key problem and produces no report
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Refuse encryption without a usable master key

## Trigger

The User asks for encryption without a usable master key.

## Outcome

The scan is refused, naming what is wrong with the master key.

## Edge cases

- Framework, control and workload scans report the master key problem after scanning rather than before.
