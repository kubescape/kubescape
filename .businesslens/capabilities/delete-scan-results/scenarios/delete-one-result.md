---
kind: primary
routes:
  api: API
steps:
  - text: The API client deletes the results of a Scan request by its scan ID
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product removes the completed Scan request
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: removes, from: Completed }
    contexts: { api: { place: microservice-api } }
---

# Delete one scan's results

## Trigger

The client no longer needs a scan's results.

## Outcome

The service no longer holds them.

## Edge cases

- A scan still queued or running is answered as busy and nothing is deleted.
- A request with neither a scan ID nor a request to delete everything is refused; the latest results are never deleted implicitly.
