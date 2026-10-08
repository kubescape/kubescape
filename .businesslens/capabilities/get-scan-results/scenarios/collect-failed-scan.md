---
kind: edge
routes:
  api: API
steps:
  - text: The API client asks for the results of a Scan request by its scan ID
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product answers with the failed Scan request's error and removes it
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: removes, from: Failed }
    contexts: { api: { place: microservice-api } }
---

# Collect a failed scan

## Trigger

A requested scan failed.

## Outcome

The client receives the error, with file paths removed from it, and the service
no longer holds it unless the client asked to keep it.
