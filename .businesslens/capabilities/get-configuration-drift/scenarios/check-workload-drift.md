---
kind: primary
routes:
  mcp: MCP
steps:
  - text: The AI agent names a Container profile and the Workload it describes
    kind: actor
    actor: ai-agent
    entities:
      - { entity: container-profile, effect: reads, facts: [Workload] }
      - { entity: workload, effect: reads, facts: [Kind, Name] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product compares the profile with the Workload's live configuration
    kind: product
    actor: ai-agent
    entities:
      - { entity: container-profile, effect: reads, facts: [Files opened, Capabilities used] }
      - { entity: workload, effect: reads, facts: [Configuration] }
    contexts: { mcp: { place: mcp-server } }
  - text: The Product returns the suggested changes, changing nothing
    kind: product
    actor: ai-agent
    entities: []
    contexts: { mcp: { place: mcp-server } }
---

# Check a workload's drift

## Trigger

An AI agent looks for privileges a workload holds but never uses.

## Outcome

The agent receives the changes that would tighten the workload: a read-only root
filesystem when the container never wrote a file, dropping every capability when
it used none, or SYS_ADMIN and NET_ADMIN when it did not use them.

## Edge cases

- Kinds other than Pods, Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs and CronJobs are refused as unsupported.
- A workload kind or name that does not match the profile is refused as an invalid argument.
