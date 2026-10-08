---
availability:
  - { place: cli }
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/fix/fix.go
  - kind: code
    role: implementation
    target: core/core/fix.go
  - kind: code
    role: implementation
    target: core/core/clusterfix.go#emitClusterFixes
  - kind: code
    role: implementation
    target: core/pkg/fixhandler/fixhandler.go#NewFixHandler
  - kind: code
    role: implementation
    target: cmd/mcpserver/remediation.go#runApplyRemediation
  - kind: doc
    role: intent
    target: docs/cli-reference.md
---

# Fix misconfigurations

Propose and apply the remediations a scan report calls for. Manifest files are fixed where
they are, keeping YAML comments and layout, or copied fixed into another
directory; a cluster scan's fixes are printed as manifests to review and apply.
The fix can be narrowed to chosen controls, and a container profile can harden
workloads to what they were seen doing at runtime.
