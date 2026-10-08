---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/advanced_tools.go
---

# Scan a resource slice

Page through the cluster's Pods, Deployments, DaemonSets or StatefulSets and
return their specifications in small, token-budgeted chunks for an agent to
inspect. No control is evaluated.
