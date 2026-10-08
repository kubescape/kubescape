---
appliesTo:
  - type: entity
    id: workload
    effect: changes
    contexts:
      - { place: mcp-server }
permits: []
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/advanced_tools.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/remediation.go#runApplyRemediation
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# No one changes a workload through the MCP server

Every MCP tool only reads the cluster or the local files it names. A proposed
patch is submitted to the cluster only as a dry run, and proposed fixes are
returned as patched YAML without writing any file.
