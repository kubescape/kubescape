---
appliesTo:
  - type: capability
    id: scan-misconfigurations
    contexts:
      - { place: cli }
references:
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/notification/notification.go
---

# Webhook notifications never change a scan's exit status

A scan summary sent to a webhook is delivered on a best-effort basis; a failed
or slow delivery is only a warning.
