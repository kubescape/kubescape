---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for the fixes of named controls for a local path
    kind: actor
    actor: ai-agent
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product scans each Manifest at that path and works out the fixes
    kind: product
    actor: ai-agent
    entities:
      - { entity: manifest, effect: reads, facts: [Path, Kind, Name, Configuration] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the patched YAML and the controls it could not fix, leaving the files unchanged
    kind: product
    actor: ai-agent
    entities:
      - { entity: control, effect: reads, facts: [Control ID] }
    contexts: { mcp: { place: mcp-server } }
---

# Fix manifests for an AI agent

## Trigger

An AI agent wants to propose fixes to the person it works for.

## Outcome

The agent receives the patched YAML to offer, and the User's files are not
changed.
