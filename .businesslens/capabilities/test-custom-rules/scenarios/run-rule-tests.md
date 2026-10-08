---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a Custom rule directory or a directory of them
    kind: actor
    actor: user
    entities:
      - { entity: custom-rule, effect: reads, facts: [Name] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Rule test case and compares the result with the expected one
    kind: product
    actor: user
    entities:
      - { entity: custom-rule, effect: reads, facts: [Rule source, Matched kinds] }
      - { entity: rule-test-case, effect: reads, facts: [Name, Input, Expected result] }
    contexts: { cli: { place: cli } }
  - text: The Product reports each case as passed or failed, with the difference, and how many passed
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Run rule tests

## Trigger

The User changed a rule and wants to know it still behaves.

## Outcome

The User sees each case's result; the command fails when any case fails or no
rule is found.
