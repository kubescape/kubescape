---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a base and a head Scan report
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [] }
      - { entity: scan-report, as: head, effect: reads, facts: [] }
    contexts: { cli: { place: cli } }
  - text: The Product classifies each finding as new, resolved, unchanged or incomparable
    kind: product
    actor: user
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [Scanned target, Control results, Resource results] }
      - { entity: scan-report, as: head, effect: reads, facts: [Scanned target, Control results, Resource results] }
    contexts: { cli: { place: cli } }
  - text: The Product prints the changes in the chosen format
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Compare misconfiguration reports

## Trigger

The User wants to know what a change introduced or resolved.

## Outcome

The User sees the new, resolved, unchanged and incomparable findings; a finding
whose scope, status or evidence makes the comparison unsafe is never counted as
resolved.

## Edge cases

- Two image vulnerability reports are compared by CVE, package and package type across all images, in a narrower set of formats.
