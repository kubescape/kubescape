---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User asks to download one Framework or one Control by name, optionally to a file
    kind: actor
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { cli: { place: cli } }
  - text: The Product saves it as a JSON file named after it
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name, Controls] }
    contexts: { cli: { place: cli } }
---

# Download one framework or control

## Trigger

The User wants a pinned copy of one policy.

## Outcome

The file can be passed to a scan in place of a download. Without a name, every
framework or every control is saved, one file each.
