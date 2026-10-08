---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User runs a fix of local files with a Container profile exported from the cluster
    kind: actor
    actor: user
    entities:
      - { entity: container-profile, effect: reads, facts: [Workload] }
    contexts: { cli: { place: cli } }
  - text: The Product compares what the container did at runtime with its Manifest
    kind: product
    actor: user
    entities:
      - { entity: container-profile, effect: reads, facts: [Workload, Files opened, Capabilities used] }
      - { entity: manifest, effect: reads, facts: [Kind, Name, Configuration] }
    contexts: { cli: { place: cli } }
  - text: The Product makes the root filesystem read-only when nothing was written, and drops every capability when none was used, or SYS_ADMIN and NET_ADMIN when unused
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: changes, facts: [Configuration] }
    contexts: { cli: { place: cli } }
---

# Harden from a container profile

## Trigger

The User wants a workload restricted to what it actually does.

## Outcome

The manifest drops what the container never used, alongside the report's other
fixes.

## Edge cases

- Profile hardening is skipped, with a warning, while the fix is narrowed to chosen controls.
- A profile that cannot be read only produces a warning.
- Multi-container workloads whose profile names no container are not hardened.
