---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#CallTool
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#ReadContainerProfileResource
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# List container profiles

Browse the container profiles the Kubescape Operator recorded in the cluster and
open one.
