---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User sets a master key and asks for a scan with sensitive metadata encrypted
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product writes the Scan report with its sensitive metadata encrypted under the master key
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Encrypted, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
---

# Scan with encrypted metadata

## Trigger

The User needs a report whose metadata stays confidential until someone with
the master key restores it.

## Outcome

The report's sensitive metadata is encrypted; a JSON report can later be
decrypted with the same key.

## Edge cases

- When both hiding and encryption are asked for, encryption applies.
- Encryption is refused for SBOM output formats and fleet reports.
