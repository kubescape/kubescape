---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a base and a head Scan report on the local machine
    kind: actor
    actor: ai-agent
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [] }
      - { entity: scan-report, as: head, effect: reads, facts: [] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product compares them and returns the changes
    kind: product
    actor: ai-agent
    entities:
      - { entity: scan-report, as: base, effect: reads, facts: [Control results, Resource results] }
      - { entity: scan-report, as: head, effect: reads, facts: [Control results, Resource results] }
    contexts: { mcp: { place: mcp-server } }
---

# Compare reports for an AI agent

## Trigger

An AI agent is asked what changed between two scans.

## Outcome

The agent receives the new, resolved, unchanged and incomparable findings;
reports of different kinds are refused.
