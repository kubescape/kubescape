---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks for a scan with sensitive metadata hidden
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product writes the Scan report with names, namespaces, labels, paths and image references replaced by deterministic pseudonyms
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Anonymized, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
---

# Scan with anonymized metadata

## Trigger

The User wants to share a report without exposing the names in it.

## Outcome

The report keeps its results while its sensitive metadata is pseudonymized; the
same value always yields the same pseudonym.
