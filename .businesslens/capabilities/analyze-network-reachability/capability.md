---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/network_reachability.go
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# Analyze network reachability

Work out whether one pod can reach another under the cluster's network
policies, on a given port and protocol.
