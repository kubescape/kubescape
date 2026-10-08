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

# Evaluate a CEL rule

Evaluate a CEL expression against a resource the agent supplies, as an
admission policy would, to test a rule before deploying it.
