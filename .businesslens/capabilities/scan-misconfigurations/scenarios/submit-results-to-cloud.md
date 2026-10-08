---
kind: alternative
routes:
  cli: CLI
steps:
  - text: The User scans the cluster after connecting Kubescape to a Kubescape Cloud account
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product evaluates the cluster and prints the Scan report
    kind: product
    actor: user
    entities:
      - { entity: scan-report, effect: creates, to: Plain, facts: [Scanned target, Frameworks, Control results, Resource results, Compliance score, Scan coverage score] }
    contexts: { cli: { place: cli } }
  - text: The Product submits the Scan report to the account in the Cached configuration
    kind: product
    actor: user
    entities:
      - { entity: cached-configuration, effect: reads, facts: [Account ID, Cloud report URL] }
      - { entity: scan-report, effect: reads, facts: [Scanned target, Control results, Resource results] }
    contexts: { cli: { place: cli } }
  - text: The Product shows where to view the submitted results
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Submit results to Kubescape Cloud

## Trigger

The User has connected Kubescape to a Kubescape Cloud account and scans.

## Outcome

The results are kept in the Kubescape Cloud account and the User is told where
to view them.

## Edge cases

- A failed submission fails the command after the report has been printed.
- Without an account ID, Kubescape Cloud assigns one when results are submitted.
- A cluster whose name cannot be determined is not submitted.
