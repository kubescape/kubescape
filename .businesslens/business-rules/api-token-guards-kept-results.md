---
appliesTo:
  - type: entity
    id: workload-configuration-scan-summary
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

# Only a client presenting the configured API token has results kept in the cluster

Scans and metrics requests that keep per-workload results in the cluster need
the API token when one is configured; without one, any client's may.
