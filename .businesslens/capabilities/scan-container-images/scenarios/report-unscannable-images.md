---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User names several container images
    kind: actor
    actor: user
    entities:
      - { entity: container-image, effect: reads, facts: [Reference] }
    contexts: { cli: { place: cli } }
  - text: One of the images cannot be pulled or its reference is invalid
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product scans the remaining images and prints the Image vulnerability report with the failures listed
    kind: product
    actor: user
    entities:
      - { entity: vulnerability-report, effect: creates, facts: [Images, Vulnerabilities, Failed images, Vulnerability database age] }
    contexts: { cli: { place: cli } }
  - text: The Product ends the command with a failure status
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Report images that cannot be scanned

## Trigger

Part of a multi-image run fails.

## Outcome

Every image that could be scanned is reported, the failures are summarized at
the end, and the command fails.
