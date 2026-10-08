---
availability:
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#Status
  - kind: doc
    role: intent
    target: httphandler/docs/swagger.yaml
---

# Check scan status

Ask whether a requested scan is still queued or running.
