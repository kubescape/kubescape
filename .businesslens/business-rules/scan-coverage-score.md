---
appliesTo:
  - type: entity
    id: scan-report
    facts: [Scan coverage score]
references:
  - kind: code
    role: implementation
    target: core/cautils/scancoverage.go#ComputeCoverageScore
  - kind: doc
    role: context
    target: docs/scan-coverage.md
---

# The scan coverage score is lowered by every gap

The scan coverage score starts from the share of controls evaluated and loses 3
points for each resource type that failed to collect while its controls still
evaluated, 2 for each partly
collected, 5 for each policy input served from a fallback and 5 for each skipped
manifest, never going below 0.
