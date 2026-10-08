---
kind: primary
routes:
  api: API
steps:
  - text: The API client requests metrics, optionally for named frameworks
    kind: actor
    actor: api-client
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { api: { place: microservice-api } }
  - text: The Product scans the cluster and keeps a Workload configuration scan summary for each scanned workload
    kind: product
    actor: api-client
    entities:
      - { entity: framework, effect: reads, facts: [Controls] }
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
      - { entity: workload-configuration-scan-summary, effect: creates, facts: [Workload, Control statuses] }
    contexts: { api: { place: microservice-api } }
  - text: The Product answers with the posture as Prometheus metrics
    kind: product
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
---

# Scrape posture metrics

## Trigger

A metrics scraper collects the cluster's posture.

## Outcome

The response carries the metrics; nothing is submitted to Kubescape Cloud and no
results wait to be collected. Without named frameworks, all of them are scanned.

## Edge cases

- The metrics scan waits in the same queue as requested scans and is refused the same way when the queue is full.
- Nothing is kept in the cluster when the client skips persistence or a Kubescape Cloud account is configured.
