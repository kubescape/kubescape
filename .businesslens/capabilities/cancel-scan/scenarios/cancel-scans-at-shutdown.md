---
kind: edge
routes:
  api: API
steps:
  - text: The service is shutting down and accepted scans are still queued or running after the drain period
    kind: condition
    unattended: true
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product cancels every outstanding Scan request
    kind: product
    entities:
      - { entity: scan-request, effect: removes, from: Running }
    contexts: { api: { place: microservice-api } }
---

# Cancel outstanding scans at shutdown

## Trigger

The Kubescape Microservice is stopped while scans are outstanding.

## Outcome

New scans are refused as unavailable, outstanding scans are cancelled and leave
no results; a client waiting on one is told it was cancelled, and a registered
callback may be told it failed.
