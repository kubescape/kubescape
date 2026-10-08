---
availability:
  - { place: cli }
  - { place: mcp-server }
references:
  - kind: code
    role: implementation
    target: cmd/predict/pss.go#runPSS
  - kind: code
    role: implementation
    target: core/pkg/pss/fetch.go#DefaultWorkloadTargets
  - kind: code
    role: implementation
    target: cmd/mcpserver/pss_predictor.go
  - kind: doc
    role: intent
    target: docs/pss-predictor.md
---

# Predict Pod Security Standards compliance

Tell what would break if a namespace enforced the Privileged, Baseline or
Restricted Pod Security Standard, evaluating its workloads or local manifests
without changing any admission configuration.
