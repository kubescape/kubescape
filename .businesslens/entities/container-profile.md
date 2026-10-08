---
references:
  - kind: code
    role: implementation
    target: core/pkg/fixhandler/prioritizationhandler.go#DetectProfileDrift
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#CallTool
---

# Container profile

What a container actually did at runtime, as recorded by the Kubescape Operator
in the cluster's Kubescape storage.

## Information kept

- **Workload** — the workload and container it describes
- **Files opened** — the files the container opened, and whether for writing
- **Capabilities used** — the Linux capabilities the container used
