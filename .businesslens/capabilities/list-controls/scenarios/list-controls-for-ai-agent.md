---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for the controls
    kind: actor
    actor: ai-agent
    entities:
      - { entity: control, effect: reads, facts: [] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns each Control's ID and name
    kind: product
    actor: ai-agent
    entities:
      - { entity: control, effect: reads, facts: [Control ID, Name] }
    contexts: { mcp: { place: mcp-server } }
---

# List controls for an AI agent

## Trigger

An AI agent chooses controls to scan against.

## Outcome

The agent receives the controls; when they cannot be fetched, the agent receives
an error.
