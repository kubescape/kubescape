---
kind: alternative
routes:
  api: API
steps:
  - text: The API client asks to delete all results
    kind: actor
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: No scan is queued or running
    kind: condition
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product removes every finished Scan request
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: removes, from: Completed }
    contexts: { api: { place: microservice-api } }
---

# Delete all results

## Trigger

The client clears the service's stored results.

## Outcome

No results remain. While any scan is queued or running, metrics scans included,
the request is refused and nothing is deleted.
