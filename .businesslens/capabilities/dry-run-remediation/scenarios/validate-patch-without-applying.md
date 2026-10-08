---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a Workload and a patch
    kind: actor
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Kind, Name, Namespace] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product submits the patch to the cluster as a dry run, so nothing is saved
    kind: product
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Configuration] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns whether the cluster would accept it and the resulting configuration
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Validate a patch without applying it

## Trigger

An AI agent wants to confirm a fix before proposing it.

## Outcome

The agent knows whether the patch would be accepted; the workload is unchanged.

## Edge cases

- Only Pods, Deployments, DaemonSets and StatefulSets can be patched this way.
