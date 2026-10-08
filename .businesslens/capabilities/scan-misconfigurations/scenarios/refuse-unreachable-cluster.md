---
kind: edge
routes:
  cli: CLI
steps:
  - text: The User starts a cluster scan
    kind: actor
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
  - text: The cluster of the chosen kube context cannot be reached, or the context does not exist
    kind: condition
    entities: []
    contexts: { cli: { place: cli } }
  - text: The Product fails the command without a report
    kind: product
    actor: user
    entities: []
    contexts: { cli: { place: cli } }
---

# Fail when the cluster cannot be reached

## Trigger

The User scans while the cluster is unreachable.

## Outcome

The command fails, saying it could not connect to the Kubernetes cluster or that
the context does not exist in the kubeconfig.
