---
appliesTo:
  - type: entity
    id: scan-request
    effect: creates
permits:
  - actors: [api-client]
    when:
      - { entity: microservice-configuration, fact: API token, absent: true }
  - actors: [api-client]
    when:
      - { entity: api-client, fact: Bearer token, is: { entity: microservice-configuration, fact: API token } }
references:
  - kind: code
    role: implementation
    target: httphandler/listener/setup.go#bearerAuthMiddleware
---

# Only a client presenting the configured API token requests a scan

When the Kubescape Microservice is deployed with an API token, a scan request
must carry it as a bearer token; without one configured, any client may request
scans. Health checks and the API description stay open either way.
