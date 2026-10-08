---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/advanced_tools.go
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# Dry-run a remediation

Have the cluster validate a proposed patch to a workload without saving it, to
show whether it would be accepted.
