---
appliesTo:
  - type: capability
    id: scan-misconfigurations
  - type: entity
    id: cached-configuration
    facts: [Cloud report URL]
references:
  - kind: code
    role: implementation
    target: core/core/initutils.go#setSubmitBehavior
---

# Framework scans submit to Kubescape Cloud whenever a report URL is configured

Results of default and framework scans are submitted to Kubescape Cloud whenever
a cloud report URL is configured, unless the User keeps results local or turns
submission off. Control and workload scans, image scans and scans with an
invalid account ID are never submitted.
