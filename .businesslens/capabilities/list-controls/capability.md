---
availability:
  - { place: cli }
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/list/list.go
  - kind: code
    role: implementation
    target: core/core/list.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/list_policies.go
---

# List controls

List the controls a scan can evaluate, with their IDs, names and the frameworks
that include them. Controls come from the release or the local cache.
