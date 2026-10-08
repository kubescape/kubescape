---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans a repository, pointing at its contract file and optionally naming one contract
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product validates the Scan contract and applies the chosen contract's policy, scope, evaluation settings, gates and output wherever no flag overrides them
    kind: product
    actor: user
    entities:
      - { entity: scan-contract, effect: reads, facts: [Minimum Kubescape version, Default contract, Contracts] }
    contexts: { cli: { place: cli } }
  - text: The Product writes the Scan report recording the contract applied and the flags that overrode it
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score, Scan contract] }
    contexts: { cli: { place: cli } }
---

# Scan under a scan contract

## Trigger

A repository keeps a scan contract so that every scan of it is the same.

## Outcome

The scan follows the contract, the stricter of each contract gate and its
flag decides the exit status, and the report records the contract's
provenance.

## Edge cases

- A contract's frameworks and controls apply only to the default scan command.
- A contract is refused for image scans.
- A contract that pins a controls version is refused together with an account or local artifacts.
