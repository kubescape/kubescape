---
singleton: true
references:
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#bearerAuthMiddleware
  - kind: code
    role: implementation
    target: httphandler/config/namespacefilters.go
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/datastructuremethods.go
  - kind: doc
    role: context
    target: httphandler/examples/microservice/README.md
---

# Microservice configuration

The settings the Kubescape Microservice is deployed with, set by whoever runs
it in the cluster and not through the API.

## Information kept

- **API token** — the token every scan, status, results and metrics request must present, when one is set
- **Namespace filters** — the namespaces scans include or exclude by default, reloaded from a file before each new scan
- **Account** — the Kubescape Cloud account and access key results are submitted to
- **Offline mode** — whether results can be collected without a scan ID, as the latest scan's
- **Continuous posture scanning** — whether detailed per-workload results are kept beside their summaries
- **Callbacks** — whether a client may register a callback URL, and to which addresses
- **Queue capacity** — how many scans may wait behind the running one, ten by default
