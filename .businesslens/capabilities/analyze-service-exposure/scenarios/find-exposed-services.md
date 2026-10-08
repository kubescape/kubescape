---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a namespace
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns each externally exposed service with the route that exposes it
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Find exposed services

## Trigger

An AI agent is asked what in a namespace is reachable from outside.

## Outcome

The agent receives each exposure path; nothing in the cluster changes.

## Edge cases

- A route that references a service in another namespace is reported as unclear rather than safe.
