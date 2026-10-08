---
kind: alternative
routes:
  api: API
steps:
  - text: The API client requests a scan and asks to wait for its results
    kind: actor
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product accepts the Scan request and scans the cluster
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: creates, to: Running, facts: [Scan ID, Targets, Namespaces] }
    contexts: { api: { place: microservice-api } }
  - text: The Product completes the Scan request and returns its report in the response
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: changes, from: Running, to: Completed, facts: [Report] }
    contexts: { api: { place: microservice-api } }
---

# Wait for a scan's results

## Trigger

An API client wants the results in the same request.

## Outcome

The response carries the scan report; unless the client asked to keep them, the
results are then removed, including when the client disconnected before the scan
finished.
