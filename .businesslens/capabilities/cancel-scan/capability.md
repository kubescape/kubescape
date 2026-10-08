---
availability:
  - { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#CancelScan
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/serverstate.go
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#SetupHTTPListener
---

# Cancel a scan

Stop a queued or running scan so that it produces no results.
