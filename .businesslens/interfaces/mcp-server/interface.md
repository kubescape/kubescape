---
type: agent
actors: [ai-agent]
references:
  - kind: doc
    role: intent
    target: docs/mcp-server.md
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#mcpServerEntrypoint
  - kind: code
    role: implementation
    target: cmd/mcpserver/sse_transport.go#newSSEServer
---

# Kubescape MCP server

A Model Context Protocol server, started with `kubescape mcpserver`, through
which an AI agent scans the cluster of the kubeconfig it runs with and local
manifests, analyses the cluster's network, RBAC and admission configuration,
and reads the vulnerability, configuration and runtime data the Kubescape
Operator keeps there. It is served over standard input and output, or over
server-sent events on the local machine only, and acts with the permissions of
that kubeconfig.
