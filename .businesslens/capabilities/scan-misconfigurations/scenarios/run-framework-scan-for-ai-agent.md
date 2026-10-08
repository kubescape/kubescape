---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent asks for a scan of the cluster or one namespace against a named Framework
    kind: actor
    actor: ai-agent
    entities:
      - { entity: framework, effect: reads, facts: [Name] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product evaluates the cluster's resources against the Framework's controls
    kind: product
    actor: ai-agent
    entities:
      - { entity: framework, effect: reads, facts: [Name, Controls] }
      - { entity: control, effect: reads, facts: [Control ID] }
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace, Configuration] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the compliance score and up to 100 failed resources, keeping nothing
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Scan the cluster for an AI agent

## Trigger

An AI agent needs the cluster's posture against a framework to answer the
person it works for.

## Outcome

The agent receives the compliance score and the failed resources, marked as
truncated when there were more than 100.

## Edge cases

- The agent can instead scan named controls, one workload, or the RBAC or network controls alone.
- Scanning against every control at once is refused.
- At most two scans run at once, and identical concurrent requests share one scan.
- A scan that exceeds its time limit returns a timeout error.
