---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a subject by kind and name, with the namespace of a service account
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product builds the escalation graph from the cluster's roles and bindings and returns the paths from that subject
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Find escalation paths

## Trigger

An AI agent is asked how dangerous an identity's permissions are.

## Outcome

The agent receives the identities the subject can reach and whether it is
equivalent to a cluster administrator; nothing in the cluster changes.

## Edge cases

- When the search reaches its safety bound, the result is marked truncated, as a possibly incomplete negative.
