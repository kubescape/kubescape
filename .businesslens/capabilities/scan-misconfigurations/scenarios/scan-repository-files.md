---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User starts a scan of a local directory, file or Git repository
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product renders Kustomize directories and Helm charts and reads each Manifest it finds
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: reads, facts: [Path, Kind, Name, Namespace, Configuration] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Manifest against the default file frameworks, honouring skip annotations in it
    kind: product
    actor: user
    entities:
      - { entity: manifest, effect: reads, facts: [Configuration] }
      - { entity: framework, effect: reads, facts: [Controls] }
      - { entity: exception, effect: reads, facts: [Controls, Resources, Expiry] }
    contexts: { cli: { place: cli } }
  - text: The Product writes the Scan report, citing each failing resource's source path
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
---

# Scan manifests and repositories

## Trigger

The User wants to check Kubernetes configuration before it reaches a cluster,
locally or in a pipeline.

## Outcome

The scan report lists the failing resources with the files they are declared
in, in the output formats the User chose, including formats for code scanning
and pipeline annotations.

## Edge cases

- A Git repository URL is cloned first; a repository that cannot be cloned fails the scan.
- Manifests that cannot be parsed are skipped with a warning and lower the scan coverage score; a single file that cannot be parsed, or input from which nothing loads, fails the scan.
- Skip annotations on a manifest exclude it from the controls they name, unless the User turns inline exceptions off.
- Framework, control and workload scans read manifests from standard input when given `-`.
