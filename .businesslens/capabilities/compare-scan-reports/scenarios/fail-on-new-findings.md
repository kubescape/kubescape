---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User compares a base and a head Scan report, asking to fail on new findings at or above a severity
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [] }
      - { entity: scan-report, as: head, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product compares the reports
    kind: product
    actor: user
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [Control results, Resource results] }
      - { entity: scan-report, as: head, effect: reads, facts: [Control results, Resource results] }
    contexts: { cli: { place: cli } }
  - text: There is at least one new or incomparable finding at or above that severity
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product prints the changes and fails the command
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fail on new findings

## Trigger

A pipeline must stop when a change introduces findings.

## Outcome

The changes are printed and the command fails; without such findings it
succeeds.
