---
kind: primary
routes:
  api: API
steps:
  - text: The API client asks for the status of a Scan request by its scan ID
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product answers busy while the Scan request is running, and not busy otherwise
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
---

# Check a scan's status

## Trigger

An API client polls a scan it requested.

## Outcome

The client knows whether to collect the results yet. A queued scan and a
running one both answer busy; an unknown scan ID answers not busy, and whether a
finished scan succeeded shows only when its results are collected.

## Edge cases

- Without a scan ID, the latest scan a client requested is checked; metrics scans never count as the latest.
