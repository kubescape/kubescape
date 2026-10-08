---
appliesTo:
  - type: capability
    id: scan-misconfigurations
  - type: entity
    id: scan-report
    facts: [Control results]
references:
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/results.go#HandleResults
---

# Exit thresholds read the full report

Severity, compliance and coverage thresholds are evaluated on the complete
report, whatever severity filters narrow the printed output to.
