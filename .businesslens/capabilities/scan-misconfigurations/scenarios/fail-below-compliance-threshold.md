---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans against a named Framework with a compliance threshold
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates the resources and writes the Scan report
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name, Controls] }
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
  - text: The Scan report's compliance score is below the threshold
    kind: condition
    entities:
      - { entity: scan-report, effect: reads, facts: [Compliance score] }
    contexts: { cli: { place: cli } }
  - text: The Product ends the command with a failure status
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fail a pipeline below the compliance threshold

## Trigger

The User gates a pipeline on a framework's compliance score.

## Outcome

The report is still produced, and the command fails so the pipeline stops.
