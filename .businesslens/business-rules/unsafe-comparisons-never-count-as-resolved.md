---
appliesTo:
  - type: capability
    id: compare-scan-reports
  - type: capability
    id: scan-misconfigurations
    contexts:
      - { place: cli }
references:
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/diff/diff.go#CompareReports
  - kind: code
    role: implementation
    target: core/core/baseline.go#EnforceBaseline
---

# A finding that cannot be compared safely never counts as resolved

Reports are compared only when both are misconfiguration reports or both are
image vulnerability reports. A finding whose scope, status or evidence makes the
comparison unsafe is reported as incomparable, and a gate on new findings counts
it as new.
