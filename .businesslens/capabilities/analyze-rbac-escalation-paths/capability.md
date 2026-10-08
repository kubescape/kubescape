---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/rbac_escalation.go
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# Analyze RBAC escalation paths

Work out how a user, group or service account could escalate its privileges
through the cluster's RBAC configuration.
