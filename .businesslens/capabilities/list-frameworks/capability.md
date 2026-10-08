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
    target: cmd/mcpserver/list_policies.go#ListFrameworks
---

# List frameworks

List the frameworks a scan can be asked to evaluate. They come from the
Kubescape Cloud account when one is configured, otherwise from the release; when
neither can be fetched, the built-in framework names are listed.
