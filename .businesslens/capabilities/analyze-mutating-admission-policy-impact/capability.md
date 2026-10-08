---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/mutating_policy_impact.go
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# Analyze mutating admission policy impact

Tell which mutating admission policies would change a given object when it is
admitted.
