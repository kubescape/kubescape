---
kind: alternative
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for a scan of a local path
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product evaluates each Manifest at that path
    kind: product
    actor: ai-agent
    entities:
      - { entity: manifest, effect: reads, facts: [Path, Kind, Name, Namespace, Configuration] }
      - { entity: framework, effect: reads, facts: [Controls] }
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the failed resources without keeping them
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Scan local manifests for an AI agent

## Trigger

An AI agent reviews infrastructure-as-code on the machine it runs on, against a
framework or named controls.

## Outcome

The agent receives the failing resources; without a framework the NSA framework
is used.
