---
availability:
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/prometheus.go#Metrics
  - kind: doc
    role: context
    target: httphandler/examples/prometheus/README.md
---

# Get scan metrics

Scan the cluster on request and answer with its posture as Prometheus metrics,
for a metrics scraper to collect.
