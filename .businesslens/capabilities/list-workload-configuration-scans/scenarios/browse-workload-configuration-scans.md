---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent lists the workload configuration scans of a namespace
    kind: actor
    actor: ai-agent
    entities:
      - { entity: workload-configuration-scan, effect: reads, facts: [] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the Workload configuration scans it finds
    kind: product
    actor: ai-agent
    entities:
      - { entity: workload-configuration-scan, effect: reads, facts: [Workload] }
    contexts: { mcp: { place: mcp-server } }
  - text: The AI agent opens one Workload configuration scan and reads its results
    kind: actor
    actor: ai-agent
    entities:
      - { entity: workload-configuration-scan, effect: reads, facts: [Workload, Control results] }
    contexts: { mcp: { place: mcp-server::workload-configuration-scan } }
---

# Browse configuration scan results

## Trigger

An AI agent is asked how a workload is misconfigured.

## Outcome

The agent has the workload's detailed results. Without a namespace, the
Kubescape namespace is used.

## Edge cases

- Results are listed 100 at a time with a token for the next page.
- Without the stored results in the cluster, or without permission to read them, the agent receives a structured error.
