---
appliesTo:
  - type: entity
    id: scan-request
    effect: reads
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

# Only a client presenting the configured API token reads a scan's status or results

Status and results requests need the API token when one is configured; without
one, any client may read them.
