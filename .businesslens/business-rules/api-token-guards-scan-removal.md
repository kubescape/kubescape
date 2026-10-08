---
appliesTo:
  - type: entity
    id: scan-request
    effect: removes
permits:
  - actors: [api-client]
    when:
      - { entity: microservice-configuration, fact: API token, absent: true }
  - actors: [api-client]
    when:
      - { entity: api-client, fact: Bearer token, is: { entity: microservice-configuration, fact: API token } }
  - unattended: true
references:
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#bearerAuthMiddleware
  - kind: code
    role: implementation
    target: httphandler/handlerequests/v1/requestshandler.go#CancelScan
---

# Only a client presenting the configured API token collects, deletes or cancels a scan

Collecting, deleting and cancelling scans need the API token when one is
configured; without one, any client may. The Product also cancels outstanding
scans on its own when the service shuts down.
