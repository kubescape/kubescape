---
appliesTo:
  - type: entity
    id: workload-configuration-scan-summary
    effect: creates
  - type: capability
    id: get-scan-metrics
  - type: capability
    id: scan-misconfigurations
    contexts:
      - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandlerutils.go
  - kind: code
    role: implementation
    target: httphandler/storage/apiserver.go
---

# Results are kept in the cluster only without a Kubescape Cloud account

The Kubescape Microservice keeps per-workload results in the cluster's Kubescape
storage only after a successful scan, when no Kubescape Cloud account is
configured and the client has not asked to skip persistence; detailed results
are kept beside the summaries only while continuous posture scanning is on.
