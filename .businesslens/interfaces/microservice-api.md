---
type: api
actors: [api-client]
references:
  - kind: doc
    role: intent
    target: httphandler/docs/swagger.yaml
  - kind: doc
    role: context
    target: httphandler/README.md
  - kind: doc
    role: context
    target: httphandler/examples/microservice/README.md
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#SetupHTTPListener
---

# Kubescape Microservice API

The REST API of Kubescape deployed as a microservice in a cluster. An API client
requests misconfiguration scans of that cluster, follows them by scan ID,
collects or deletes their results, cancels them, and scrapes posture metrics.
The service keeps per-workload results in the cluster's Kubescape storage.
