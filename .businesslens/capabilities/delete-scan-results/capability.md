---
availability:
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#DeleteResults
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/serverstate.go
---

# Delete scan results

Discard the results of one finished scan, or of all of them while no scan is
queued or running.
