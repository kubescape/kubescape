---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User asks to validate a contract file
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli::contract-validation } }
  - text: The Scan contract has the wrong kind or version, needs a newer Kubescape, names an unknown contract, or sets invalid values
    kind: condition
    entities:
      - { entity: scan-contract, effect: reads, facts: [Minimum Kubescape version, Default contract, Contracts] }
    contexts: { cli: { place: cli::contract-validation } }
  - text: The Product lists the problems and fails the command
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli::contract-validation } }
---

# Reject an invalid contract

## Trigger

The contract file is not one Kubescape can apply.

## Outcome

The problems are reported and the command fails; in SARIF form the report is
still written.

## Edge cases

- A file holding more than one YAML document is refused.
- A contract that both includes and excludes namespaces is refused.
