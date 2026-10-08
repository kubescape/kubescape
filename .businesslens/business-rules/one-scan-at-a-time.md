---
appliesTo:
  - type: context
    context: { place: microservice-api }
references:
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandlerutils.go#watchForScan
---

# The scanning API runs one scan at a time

Requested scans and metrics scans run one at a time in the order received, and
the service accepts no more than ten waiting scans by default.
