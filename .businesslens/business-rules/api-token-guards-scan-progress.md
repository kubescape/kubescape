---
appliesTo:
  - type: entity
    id: scan-request
    effect: changes
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

# Only a client presenting the configured API token has a scan completed or failed

A scan runs to completion or failure only for a request the API token admitted;
without an API token configured, any client's request does.
