---
kind: primary
routes:
  cli: CLI
steps:
  - text: The User names several kube contexts, an output file and a combined report file
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product scans each cluster and writes its Scan report to a file named after the context
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
  - text: The Product writes the Fleet report and prints a fleet summary
    kind: product
    actor: user
    entities:
      - { entity: fleet-report, effect: creates, facts: [Cluster statuses, Compliance rollup, Control matrix, Divergence] }
    contexts: { cli: { place: cli } }
---

# Scan clusters as a fleet

## Trigger

The User runs several clusters and wants to compare their posture.

## Outcome

Each cluster has its own report, and the fleet report shows each cluster's
status, the fleet's compliance rollup, each control's status per cluster and the
divergence between clusters.

## Edge cases

- A reference cluster, when named, must be one of the contexts, and the others are compared against it.
- Contexts whose report files would collide are refused.
- A fleet report is refused when metadata is hidden or encrypted.
- Fleet scans are offered for the default scan and for framework, control and workload scans, of live clusters only.
