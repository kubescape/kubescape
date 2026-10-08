---
domain: config
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/config/set.go
  - kind: code
    role: implementation
    target: core/cautils/customerloader.go
---

# Set the cached configuration

Save a Kubescape Cloud account ID, access key, API URL or report URL on the
User's machine for later commands.
