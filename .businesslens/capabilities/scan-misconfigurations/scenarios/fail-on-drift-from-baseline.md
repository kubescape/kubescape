---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans, naming a saved JSON Scan report as the baseline and asking to fail on new failures
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, as: baseline, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates the resources and writes the new Scan report
    kind: product
    actor: user
    entities:
      - { entity: scan-report, as: current, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
  - text: The Product compares the new Scan report with the baseline and prints how many findings are new, resolved, unchanged or incomparable
    kind: product
    actor: user
    entities:
      - { entity: scan-report, as: baseline, effect: reads, facts: [Control results, Resource results] }
      - { entity: scan-report, as: current, effect: reads, facts: [Control results, Resource results] }
    contexts: { cli: { place: cli } }
  - text: There is at least one new or incomparable failure at or above the baseline severity threshold
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product ends the command with a failure status
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fail on drift from a baseline

## Trigger

A pipeline must stop only when a change introduces findings that a saved report
did not have.

## Outcome

The report is still produced, the drift summary is printed, and the command
fails; without such failures it succeeds. Findings are compared by failing
evidence unless the User chooses to compare by control.
