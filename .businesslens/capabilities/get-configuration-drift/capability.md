---
availability:
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/mcpserver.go#CallTool
  - kind: code
    role: implementation
    target: core/pkg/fixhandler/prioritizationhandler.go#DetectProfileDrift
---

# Get configuration drift

Compare what a container was recorded doing with its workload's live
configuration, and return the changes that would restrict the workload to that
behaviour — a read-only root filesystem and dropped capabilities.
