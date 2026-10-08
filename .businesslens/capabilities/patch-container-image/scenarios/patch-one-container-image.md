---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names a Container image to patch, optionally with the tag for the patched copy
    kind: actor
    actor: user
    entities:
      - { entity: container-image, as: source, effect: reads, facts: [Reference] }
    contexts: { cli: { place: cli } }
  - text: The Product scans the Container image and patches its fixable operating-system packages through BuildKit
    kind: product
    actor: user
    entities:
      - { entity: container-image, as: source, effect: reads, facts: [Reference, Platform] }
      - { entity: container-image, as: patched, effect: creates, facts: [Reference, Platform] }
    contexts: { cli: { place: cli } }
  - text: The Product loads the patched image into the local image store, rescans it and prints the Image vulnerability report
    kind: product
    actor: user
    entities:
      - { entity: vulnerability-report, effect: creates, facts: [Images, Vulnerabilities, Vulnerability database age] }
    contexts: { cli: { place: cli } }
---

# Patch an image

## Trigger

An image the User runs has fixable operating-system vulnerabilities.

## Outcome

A patched copy tagged with the chosen tag, or the original tag with a
`-patched` suffix, is in the local image store, and the User sees what
vulnerabilities remain. The command fails when a severity threshold the User set
is reached.

## Edge cases

- The patched image can instead be exported as an OCI layout or a local directory, which is not rescanned.
- An image without a tag is treated as `latest`.
