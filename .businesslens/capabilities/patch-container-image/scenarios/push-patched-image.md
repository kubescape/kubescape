---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User patches a Container image and asks to push the result
    kind: actor
    actor: user
    entities:
      - { entity: container-image, as: source, effect: reads, facts: [Reference] }
    contexts: { cli: { place: cli } }
  - text: The Product patches the Container image and pushes the patched copy to the source repository under the new tag
    kind: product
    actor: user
    entities:
      - { entity: container-image, as: source, effect: reads, facts: [Reference, Platform] }
      - { entity: container-image, as: patched, effect: creates, facts: [Reference, Platform] }
    contexts: { cli: { place: cli } }
  - text: The Product rescans the pushed image and prints the Image vulnerability report
    kind: product
    actor: user
    entities:
      - { entity: vulnerability-report, effect: creates, facts: [Images, Vulnerabilities, Vulnerability database age] }
    contexts: { cli: { place: cli } }
---

# Push a patched image

## Trigger

The User wants the patched image available to the cluster.

## Outcome

The patched copy is in the source registry repository under the new tag.

## Edge cases

- Pushing cannot be combined with exporting to an OCI layout or a local directory.
