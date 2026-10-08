---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#CallTool
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#ReadConfigurationResource
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# List workload configuration scans

Browse the per-workload configuration scan results kept in the cluster, and open
one workload's detailed results.
