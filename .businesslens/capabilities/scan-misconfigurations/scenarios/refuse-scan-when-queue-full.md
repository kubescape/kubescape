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
  - text: The scan queue is full, the request is malformed or too large, or the service is shutting down
    kind: condition
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product refuses the request and accepts nothing
    kind: product
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
---

# Refuse a scan the service cannot take

## Trigger

The service cannot accept another scan.

## Outcome

A full queue answers "too many requests" with a retry hint, a malformed request
"bad request", an oversized one "payload too large", and a shutting-down service "unavailable". By default ten
scans may wait and a request may be at most 1 MiB.
