---
appliesTo:
  - type: entity
    id: workload
    effect: changes
    contexts:
      - { place: cli }
permits:
  - actors: [user]
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
  - kind: code
    role: implementation
    target: core/core/clusterconnector.go#NewOperatorAdapter
---

# A User asks the Kubescape Operator to remediate a workload

Annotating, quarantining and reverting a workload are requests a User sends to
the Kubescape Operator through the cluster credentials Kubescape runs with;
Kubescape adds no permission check of its own, and the cluster decides what
those credentials may reach.
