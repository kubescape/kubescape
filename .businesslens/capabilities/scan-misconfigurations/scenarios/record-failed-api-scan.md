---
kind: edge
routes:
  api: API
steps:
  - text: The API client requests a scan
    kind: actor
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product accepts the Scan request
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: creates, to: Running, facts: [Scan ID, Targets, Namespaces] }
    contexts: { api: { place: microservice-api } }
  - text: The scan cannot finish
    kind: condition
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product records the Scan request as failed with its error
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: changes, from: Running, to: Failed, facts: [Error] }
    contexts: { api: { place: microservice-api } }
---

# Record a failed API scan

## Trigger

A requested scan fails while running.

## Outcome

Collecting the results returns the error, with file paths removed from it.
