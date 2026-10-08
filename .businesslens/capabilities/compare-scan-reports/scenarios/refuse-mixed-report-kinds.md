---
kind: validation
routes:
  cli: CLI
steps:
  - text: The User names a Scan report and an Image vulnerability report to compare
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [] }
      - { entity: vulnerability-report, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product refuses to compare reports of different kinds
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [] }
      - { entity: vulnerability-report, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
---

# Refuse reports of different kinds

## Trigger

The two reports are not both misconfiguration reports or both image reports.

## Outcome

Nothing is compared and the command fails.
