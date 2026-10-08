---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User runs a fix with a Scan report of local files and an output directory
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Scanned target] }
    contexts: { cli: { place: cli } }
  - text: The Product writes a fixed copy of each affected Manifest into the directory, mirroring the scanned tree
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Resource results] }
      - { entity: manifest, effect: creates, facts: [Path, Kind, Name, Namespace, Configuration] }
    contexts: { cli: { place: cli } }
---

# Write fixed copies

## Trigger

The User wants to review fixes beside the originals.

## Outcome

Fixed copies sit in the output directory in the same layout as the scanned tree,
and the originals are untouched.

## Edge cases

- A non-empty output directory is refused unless the User skips confirmation.
- The scanned directory itself is refused as the output directory.
- Two sources that would land on the same copy are refused.
