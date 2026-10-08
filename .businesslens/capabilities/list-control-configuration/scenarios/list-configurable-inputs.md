---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks for the configurable inputs, optionally with a local configuration file
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli::control-configuration } }
  - text: The Product resolves the inputs as a scan would and lists each key with its value and the controls that read it
    kind: product
    actor: user
    entities:
      - { entity: control-configuration, effect: reads, facts: [Inputs] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli::control-configuration } }
---

# List configurable inputs

## Trigger

The User wants to confirm what a configurable control will be evaluated against.

## Outcome

The User sees each input's value in effect, empty where a control will fall back
to its own default.
