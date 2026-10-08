---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for one kind of Workload, optionally a page size and a continuation token
    kind: actor
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Kind] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns a page of each Workload's specification
    kind: product
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { mcp: { place: mcp-server } }
---

# Page through workloads

## Trigger

An AI agent needs the workloads' settings to reason about them.

## Outcome

The agent receives a page of 10 workloads by default and at most 500, with a
token for the next page.
