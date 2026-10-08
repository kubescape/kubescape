---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User names manifest files or directories and a level
    kind: actor
    actor: user
    entities:
      - { entity: manifest, effect: reads, facts: [Path] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Manifest's pod settings against the level
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: reads, facts: [Path, Kind, Name, Namespace, Configuration] }
    contexts: { cli: { place: cli } }
  - text: The Product reports each failing Manifest with the checks it would violate
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: reads, facts: [Path, Kind, Name] }
    contexts: { cli: { place: cli } }
---

# Predict compliance of local manifests

## Trigger

The User checks manifests before deploying to a namespace that enforces a Pod
Security Standard.

## Outcome

The User sees which manifests would be rejected, in a format a pipeline can
read.
