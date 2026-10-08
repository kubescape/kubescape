---
kind: alternative
routes:
  api: API
steps:
  - text: The API client asks for the results of a Scan request and asks to keep them
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product returns the completed Scan request's report and keeps it
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Report] }
    contexts: { api: { place: microservice-api } }
---

# Collect results and keep them

## Trigger

Several readers need the same results.

## Outcome

The client has the report and the service still holds it.
