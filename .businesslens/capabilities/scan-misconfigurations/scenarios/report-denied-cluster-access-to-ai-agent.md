---
kind: edge
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for a cluster scan
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The kubeconfig's permissions do not allow reading the resources the scan needs
    kind: condition
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns a permission-denied error the agent can tell apart from other failures
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Report a scan the cluster's permissions deny

## Trigger

The cluster refuses the access the scan needs.

## Outcome

The agent receives a structured error classifying the failure as denied access,
distinct from missing resources, timeouts and other failures.
