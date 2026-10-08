---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User sets the master key and names an encrypted Scan report
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, as: encrypted, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product restores every encrypted field and prints the decrypted Scan report
    kind: product
    actor: user
    entities:
      - { entity: scan-report, as: encrypted, effect: reads, facts: [Scanned target, Resource results] }
      - { entity: scan-report, as: decrypted, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
---

# Decrypt an encrypted report

## Trigger

Someone holding the master key needs the report's real names.

## Outcome

The decrypted report is printed; the encrypted file is left as it was.
