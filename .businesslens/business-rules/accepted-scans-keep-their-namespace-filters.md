---
appliesTo:
  - type: entity
    id: scan-request
    facts: [Namespaces]
  - type: entity
    id: microservice-configuration
    facts: [Namespace filters]
references:
  - kind: code
    role: implementation
    target: httphandler/config/namespacefilters.go
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/datastructuremethods.go
---

# A scan keeps the namespace filters in effect when it was accepted

The namespace filters are read again before each new scan, and a scan already
accepted keeps the ones it started with. Namespaces a client names replace them
for that scan. An invalid filters file stops the service from starting; a later
invalid change is ignored and the last valid filters stay in effect.
