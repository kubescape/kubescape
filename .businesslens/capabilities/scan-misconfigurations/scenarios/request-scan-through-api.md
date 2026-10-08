---
kind: primary
routes:
  api: API
steps:
  - text: The API client requests a scan, optionally naming what to evaluate and which namespaces
    kind: actor
    actor: api-client
    entities: []
    contexts: { api: { place: microservice-api } }
  - text: The Product accepts the Scan request, queues it and returns its scan ID as busy
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: creates, to: Running, facts: [Scan ID, Targets, Namespaces] }
    contexts: { api: { place: microservice-api } }
  - text: The Product scans the cluster in the order requested, one scan at a time
    kind: product
    actor: api-client
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { api: { place: microservice-api } }
  - text: No Kubescape Cloud account is configured and the client did not skip persistence
    kind: condition
    entities:
      - { entity: microservice-configuration, effect: reads, facts: [Account] }
    contexts: { api: { place: microservice-api } }
  - text: The Product keeps a Workload configuration scan summary for each scanned workload
    kind: product
    actor: api-client
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
      - { entity: workload-configuration-scan-summary, effect: creates, facts: [Workload, Control statuses] }
    contexts: { api: { place: microservice-api } }
  - text: The Product completes the Scan request with its results
    kind: product
    actor: api-client
    entities:
      - { entity: scan-request, effect: changes, from: Running, to: Completed, facts: [Report] }
    contexts: { api: { place: microservice-api } }
---

# Request a scan through the API

## Trigger

An API client wants the cluster's posture without waiting on the request.

## Outcome

The scan runs in the background, even if the client disconnects, and its results
wait to be collected by scan ID; each scanned workload's summary is kept in the
cluster's Kubescape storage.

## Decision points

### Are detailed results kept?

Is continuous posture scanning configured for the service?

- Continuous posture scanning is on → a Workload configuration scan with the detailed results is also kept for each workload.
- Continuous posture scanning is off → only the summaries are kept.

## Edge cases

- Namespaces the client names replace the configured namespace filters; otherwise the filters in effect when the scan is accepted apply.
- An account or access key in the request is ignored; results are submitted only to the account the service is configured with.
- When callbacks are enabled, a registered callback URL is told of the scan's completion or failure on a best-effort basis; when they are not, a request naming one is refused.
