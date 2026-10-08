---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User runs the tests of a Custom rule or a directory of them, asking to update the expected results
    kind: actor
    actor: user
    entities:
      - { entity: custom-rule, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Rule test case and records the result as expected
    kind: product
    actor: user
    entities:
      - { entity: custom-rule, effect: reads, facts: [Rule source, Matched kinds] }
      - { entity: rule-test-case, effect: changes, facts: [Expected result] }
    contexts: { cli: { place: cli } }
  - text: The Product reports which cases changed, which were unchanged and which could not be evaluated
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Rewrite expected results

## Trigger

The User changed a rule on purpose and wants its test cases to follow.

## Outcome

Each case's expected results match what the rule now produces; the command fails
only when a case cannot be evaluated.
