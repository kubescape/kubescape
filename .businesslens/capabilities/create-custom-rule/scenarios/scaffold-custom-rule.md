---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a new rule directory, optionally with the kind of resource it targets, a description and a remediation
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product writes the Custom rule with a flagged and a clean Rule test case and records the results the rule produces for them
    kind: product
    actor: user
    entities:
      - { entity: custom-rule, effect: creates, facts: [Name, Rule source, Matched kinds, Description, Remediation] }
      - { entity: rule-test-case, effect: creates, with: custom-rule, facts: [Name, Input, Expected result] }
    contexts: { cli: { place: cli } }
---

# Scaffold a rule

## Trigger

The User starts writing a check of their own.

## Outcome

The new rule passes its own tests from the start and can be passed to a scan
as-is. Without a kind, it targets Deployments.
