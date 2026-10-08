---
references:
  - kind: code
    role: implementation
    target: httphandler/storage/apiserver.go#StoreWorkloadConfigurationScanResultSummary
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandlerutils.go
---

# Workload configuration scan summary

The summary of one workload's misconfiguration results, kept in the cluster's
Kubescape storage.

## Information kept

- **Workload** — the workload the summary describes
- **Control statuses** — each control evaluated against it, with its name, status and severity
