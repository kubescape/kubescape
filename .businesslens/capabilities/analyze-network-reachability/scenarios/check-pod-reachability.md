---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a source pod and a destination pod, optionally a port and protocol
    kind: actor
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
  - text: The Product evaluates every network policy that selects either pod
    kind: product
    actor: ai-agent
    entities:
      - { entity: workload, effect: reads, facts: [Name, Namespace, Configuration] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns whether traffic is allowed, denied or unknown, with the policies that decide it
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Check whether one pod can reach another

## Trigger

An AI agent is asked whether a service is reachable from another.

## Outcome

The agent receives the verdict for egress from the source and ingress to the
destination, with the deciding policies; nothing in the cluster changes.
Without a port any port is considered, and the protocol defaults to TCP.

## Edge cases

- When a network policy cannot be read, the verdict is unknown rather than allowed or denied.
