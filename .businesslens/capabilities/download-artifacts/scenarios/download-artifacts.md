---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User asks to download all artifacts, optionally into a directory
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product saves every Framework, the Control configuration, the exceptions and the attack tracks as files
    kind: product
    actor: user
    entities:
      - { entity: framework, effect: reads, facts: [Name, Controls] }
      - { entity: control-configuration, effect: reads, facts: [Inputs] }
      - { entity: exception, effect: reads, facts: [Name, Action, Controls, Resources, Expiry] }
    contexts: { cli: { place: cli } }
---

# Download artifacts for offline scans

## Trigger

The User prepares to scan where Kubescape cannot reach the internet.

## Outcome

The directory, by default the Kubescape cache, holds the files a scan can load
instead of downloading.

## Edge cases

- A failure to save one artifact is reported after the others are saved, and fails the command.
- Downloading every framework or every control stops at the first file that cannot be saved.
