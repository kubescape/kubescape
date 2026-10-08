---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent lists the container profiles of a namespace
    kind: actor
    actor: ai-agent
    entities:
      - { entity: container-profile, effect: reads, facts: [] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns which container each Container profile describes
    kind: product
    actor: ai-agent
    entities:
      - { entity: container-profile, effect: reads, facts: [Workload] }
    contexts: { mcp: { place: mcp-server } }
  - text: The AI agent opens one Container profile and reads what the container did
    kind: actor
    actor: ai-agent
    entities:
      - { entity: container-profile, effect: reads, facts: [Workload, Files opened, Capabilities used] }
    contexts: { mcp: { place: mcp-server::container-profile } }
---

# Browse container profiles

## Trigger

An AI agent is asked what a container actually does.

## Outcome

The agent has the container's recorded runtime behaviour.

## Edge cases

- Profiles are listed 100 at a time with a token for the next page; without a namespace, every namespace is listed.
- Without the operator's data in the cluster, or without permission to read it, the agent receives a structured error.
