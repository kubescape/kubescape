---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names an object by name, API version, resource and namespace, and an admission operation
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the mutating admission policies and bindings that could apply to it, with their mutation expressions
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Find the policies that would mutate an object

## Trigger

An AI agent is asked why an object changes on admission.

## Outcome

The agent receives the matching policies and whether their applicability could
be determined; the mutated object itself is not computed. The operation defaults
to create. When the cluster does not serve mutating admission policies, the agent
is told they are not supported.
