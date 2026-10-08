---
references:
  - kind: code
    role: implementation
    target: httphandler/storage/apiserver.go#StoreWorkloadConfigurationScanResult
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#CallTool
---

# Workload configuration scan

The detailed misconfiguration results for one workload, kept in the cluster's
Kubescape storage.

## Information kept

- **Workload** — the workload the results describe
- **Control results** — each control evaluated against it, with its status, severity, failing rules and paths
- **Related objects** — the other resources the results depend on
