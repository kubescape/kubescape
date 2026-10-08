---
appliesTo:
  - type: capability
    id: scan-misconfigurations
    contexts:
      - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/scan/scan.go#runSecurityScan
  - kind: doc
    role: intent
    target: docs/cli-reference.md
---

# The compliance threshold gates only framework, control and workload scans

A compliance threshold decides the exit status of framework, control and
workload scans and of the control and resource views; the default security view
ignores it.
