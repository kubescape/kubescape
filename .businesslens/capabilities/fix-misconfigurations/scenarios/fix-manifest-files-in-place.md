---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User runs a fix with a JSON Scan report of local files
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Scanned target] }
    contexts: { cli: { place: cli } }
  - text: The Product works out the remediation for each failed control and prints the planned changes to each Manifest
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Scanned target, Resource results] }
      - { entity: manifest, effect: reads, facts: [Path, Configuration] }
      - { entity: control, effect: reads, facts: [Control ID, Remediation] }
    contexts: { cli: { place: cli } }
  - text: The User confirms the changes
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product rewrites each affected Manifest in place and reports how many flagged findings it fixed
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: changes, facts: [Configuration] }
    contexts: { cli: { place: cli } }
---

# Fix manifest files in place

## Trigger

A scan of local files found misconfigurations the User wants fixed.

## Outcome

The manifests are fixed where they are, YAML keeping its comments and layout and
JSON its indentation, and the User is told how many flagged findings were fixed
across how many files.

## Edge cases

- With nothing fixable the Product says so and succeeds.
- A dry run prints the planned changes and applies nothing.
- In interactive mode the User accepts or rejects each resource's changes, and only accepted ones are applied.
- When the User names a base directory, a report whose recorded scan location lies outside it is refused.
- Fixes that need a value only the User can supply are skipped by default.
- Findings in Helm charts are printed as suggestions; chart files are never edited.
- A manifest wrapping several resources in one document is left alone.
- A report that is not a Kubescape JSON report, or whose scanned path no longer exists, is refused.
- A file that cannot be fixed fails the command after the others are fixed.
