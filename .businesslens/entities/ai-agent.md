---
kind: system
acts: external
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#mcpServerEntrypoint
  - kind: doc
    role: context
    target: docs/mcp-server.md
---

# AI agent

The AI assistant harness — Claude, ChatGPT or a custom tool — connected to the
Kubescape MCP server, which calls its tools and reads its resources to answer a
person's questions about a cluster's security.
