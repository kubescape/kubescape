---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks for a dry run of a cluster scan against chosen frameworks or controls
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product works out the resource types the Framework's controls need and asks the cluster whether the credentials may list each
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Controls] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product reports each resource type as allowed, denied or undetermined, with the controls it affects
    kind: product
    actor: user
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
---

# Preflight cluster access

## Trigger

The User wants to know whether a scan will see everything before running it, for
example with a restricted service account in a pipeline.

## Outcome

The User sees which controls would lack data. The command fails when any
resource type is denied; checks the cluster could not answer do not fail it.
Nothing is scanned.
