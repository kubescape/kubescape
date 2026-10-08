---
availability:
  - { place: cli }
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/diff/diff.go#GetDiffCmd
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/diff/diff.go#CompareReports
  - kind: code
    role: implementation
    target: core/core/diff.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/diff_reports.go
---

# Compare scan reports

Show what changed between a base and a head report: findings that are new,
resolved, unchanged, or cannot be compared safely. Misconfiguration reports are
compared down to the failing evidence or by resource and control; image
vulnerability reports by CVE and package.
