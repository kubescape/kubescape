---
appliesTo:
  - type: context
    context: { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/sse_transport.go#rejectCrossOriginRequests
---

# The MCP server is reachable only from the local machine

Served over server-sent events, the MCP server listens on the loopback address
only and refuses browser requests from any origin other than the local machine.
