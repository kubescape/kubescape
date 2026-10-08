---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a namespace and optionally a level
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product evaluates each Workload in the namespace and returns the failing ones
    kind: product
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { mcp: { place: mcp-server } }
---

# Predict compliance for an AI agent

## Trigger

An AI agent is asked whether a namespace is ready for a stricter standard.

## Outcome

The agent receives the workloads that would fail; without a level, Restricted is
evaluated.
