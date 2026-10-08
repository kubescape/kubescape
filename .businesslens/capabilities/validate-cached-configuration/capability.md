---
domain: config
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/config/validate.go
  - kind: code
    role: implementation
    target: core/cautils/config_validation.go
---

# Validate the cached configuration

Check that the settings in effect are complete and well formed for connecting
to Kubescape Cloud, or for offline use.
