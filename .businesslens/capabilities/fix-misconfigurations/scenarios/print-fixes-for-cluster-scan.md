---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User runs a fix with a Scan report of a cluster
    kind: actor
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Scanned target] }
    contexts: { cli: { place: cli } }
  - text: The Product patches each fixable scanned resource as recorded in the Scan report and prints it as a Manifest, without server-managed fields
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: reads, facts: [Resource results] }
      - { entity: manifest, effect: creates, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { cli: { place: cli } }
  - text: The Product lists each resource it declined, with the reason
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Print fixes for a cluster scan

## Trigger

A cluster scan found misconfigurations the User wants to remediate.

## Outcome

The patched manifests are printed as one stream ready to pipe to `kubectl
apply`, or written one file per resource into an output directory; nothing is
applied to the cluster.

## Edge cases

- Secrets, ConfigMaps and workloads with container environment variables are declined because their scan record is redacted.
- Resources owned by another resource are declined; the owner is the one to fix.
- RBAC and cloud findings are declined because no single manifest expresses them.
