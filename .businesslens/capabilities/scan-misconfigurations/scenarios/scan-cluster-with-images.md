---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans the cluster and asks for the images running in it to be scanned too
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product evaluates each Workload and scans each Container image it runs, for the platform its scheduling constraints imply unless the User names one
    kind: product
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
      - { entity: container-image, effect: reads, facts: [Reference, Platform] }
    contexts: { cli: { place: cli } }
  - text: The Product prints the Scan report with the image vulnerabilities
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score, Image scan results] }
    contexts: { cli: { place: cli } }
---

# Scan a cluster with its images

## Trigger

The User wants misconfigurations and image vulnerabilities in one report.

## Outcome

The report covers both; an image that cannot be scanned is reported and fails the
command after the rest of the report is produced.

## Edge cases

- An image that does not exist for the inferred platform is skipped with a warning; a platform the User named explicitly is never replaced, and its absence is an error.
- Registry credentials the User gives apply only to the registry they name.
