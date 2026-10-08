---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/service_exposure.go
  - kind: doc
    role: intent
    target: docs/mcp-server.md
---

# Analyze service exposure

Find how a namespace's services are exposed outside the cluster: load
balancers, node ports, external IPs, ingresses and gateway routes.
