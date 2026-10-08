---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans, asking for a baseline file as output
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product evaluates the resources and writes the Scan report
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
  - text: The Product writes one Exception per failed control that suppresses exactly the resources that failed it
    kind: product
    actor: user
    entities:
      - { entity: exception, effect: creates, facts: [Name, Action, Controls, Resources] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
---

# Capture an exceptions baseline

## Trigger

The User wants to accept today's findings so that only new findings fail later
scans.

## Outcome

An exceptions file holds one exception per failed control, listing the failing
resources by kind, namespace, name and, for files, source path; the User reviews
it and passes it to later scans.

## Edge cases

- Output filtering by severity narrows the baseline to the findings left in view.
- The exceptions format is refused for image scans.
