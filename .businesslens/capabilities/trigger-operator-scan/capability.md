---
domain: operator
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/operator/scan.go
  - kind: code
    role: implementation
    target: core/core/clusterconnector.go#NewOperatorAdapter
  - kind: code
    role: implementation
    target: core/cautils/operatorscaninfo.go
---

# Trigger an operator scan

Ask the Kubescape Operator running in the cluster to run a configuration scan or
an image vulnerability scan now, instead of waiting for its schedule.
