---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for the frameworks
    kind: actor
    actor: ai-agent
    entities:
      - { entity: framework, effect: reads, facts: [] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns each Framework's name
    kind: product
    actor: ai-agent
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { mcp: { place: mcp-server } }
---

# List frameworks for an AI agent

## Trigger

An AI agent chooses a framework to scan against.

## Outcome

The agent receives the framework names; when they cannot be fetched, the
built-in names are returned.
