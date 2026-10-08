---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User names one Workload by kind and name, with its namespace
    kind: actor
    actor: user
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { cli: { place: cli } }
  - text: The Product evaluates the Workload and its images
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
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Image scan results] }
    contexts: { cli: { place: cli } }
---

# Scan one workload

## Trigger

The User wants the misconfigurations and image vulnerabilities of a single
workload.

## Outcome

The report covers only that workload, including its images' vulnerabilities.

## Edge cases

- Without a namespace the workload is looked up in `default`; `*` searches every namespace.
- A namespace in the workload name that conflicts with the namespace option is refused.
- The workload can be scanned from a manifest file or a Helm chart instead of the cluster.
