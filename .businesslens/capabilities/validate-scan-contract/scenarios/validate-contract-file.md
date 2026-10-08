---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks to validate a contract file, optionally naming one contract
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli::contract-validation } }
  - text: The Product checks the Scan contract and selects the named or default contract
    kind: product
    actor: user
    entities:
      - { entity: scan-contract, effect: reads, facts: [Minimum Kubescape version, Default contract, Contracts] }
    contexts: { cli: { place: cli::contract-validation } }
  - text: The User reviews the selected contract
    kind: actor
    actor: user
    entities:
      - { entity: scan-contract, effect: reads, facts: [Default contract, Contracts] }
    contexts: { cli: { place: cli::contract-validation } }
---

# Validate a contract file

## Trigger

The User edits a repository's scan contract and wants to confirm it before a
pipeline uses it.

## Outcome

The User sees that the file is valid and the contract a scan would apply, as
text, JSON or SARIF.
