---
kind: primary
routes:
  api: API
steps:
  - text: The API client asks for the results of a Scan request by its scan ID
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product returns the completed Scan request's report and removes it
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: removes, from: Completed }
    contexts: { api: { place: microservice-api } }
---

# Collect a scan's results

## Trigger

A requested scan has finished.

## Outcome

The client has the report, and the service no longer holds it.

## Edge cases

- A scan still queued or running is answered as busy and keeps running.
- An unknown scan ID is answered with no content.
- A request without a scan ID is refused, except in offline mode, where it returns the latest scan's results and keeps them.
