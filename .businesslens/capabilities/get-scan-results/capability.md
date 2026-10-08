---
availability:
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#GetResults
  - kind: doc
    role: intent
    target: httphandler/docs/swagger.yaml
---

# Get scan results

Collect the results of a finished scan by its scan ID, removing them from the
service unless the client asks to keep them.
