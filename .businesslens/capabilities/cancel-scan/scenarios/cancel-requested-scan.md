---
kind: primary
routes:
  api: API
steps:
  - text: The API client cancels a Scan request by its scan ID
    kind: actor
    actor: api-client
    entities:
      - { entity: scan-request, effect: reads, facts: [Scan ID] }
    contexts: { api: { place: microservice-api } }
  - text: The Product stops the scan or drops it from the queue and discards the Scan request
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: removes, from: Running }
    contexts: { api: { place: microservice-api } }
---

# Cancel a requested scan

## Trigger

A requested scan is no longer needed.

## Outcome

The scan leaves no results to collect; it reads as busy until it has actually
stopped. A registered callback is told the scan failed.

## Edge cases

- Without a scan ID, the scan that is running is cancelled; queued scans and metrics scans are not.
- A scan ID that is not queued or running is answered as not found.
