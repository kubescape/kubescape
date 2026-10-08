---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names one or more container images, with registry credentials and a platform where needed
    kind: actor
    actor: user
    entities:
      - { entity: container-image, effect: reads, facts: [Reference] }
    contexts: { cli: { place: cli } }
  - text: The Product updates its vulnerability database and analyses each Container image's packages
    kind: product
    actor: user
    entities:
      - { entity: container-image, effect: reads, facts: [Reference, Platform] }
    contexts: { cli: { place: cli } }
  - text: The Product prints one Image vulnerability report covering every image
    kind: product
    actor: user
    entities:
      - { entity: vulnerability-report, effect: creates, facts: [Images, Vulnerabilities, Failed images, Vulnerability database age] }
    contexts: { cli: { place: cli } }
---

# Scan container images

## Trigger

The User wants to know which known vulnerabilities an image carries before
running it.

## Outcome

The report lists each image's vulnerabilities by severity, with whether a fix
exists. The command fails when a severity threshold the User set is reached by
any image; vulnerabilities of unknown severity count as reaching every
threshold.

## Edge cases

- Repeated images are scanned once, and several images can be scanned in parallel.
- Using the cached database without one fails the scan.
- A database older than the allowed age only warns, unless the User asked to fail on a stale database.
- Exceptions from an exceptions file are matched per image reference.
- The report can also be written as a CycloneDX or SPDX software bill of materials.
- Hiding or encrypting metadata is refused for image scans.
- A platform the User names that an image does not exist for is an error, never replaced by another platform.
