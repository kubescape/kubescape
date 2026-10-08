---
domain: config
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/config/view.go
  - kind: code
    role: implementation
    target: core/core/cachedconfig.go#ViewCachedConfig
  - kind: code
    role: implementation
    target: core/cautils/config_output.go
---

# View the cached configuration

Show the Kubescape Cloud connection settings in effect, combining the cached
configuration, the configuration and credentials kept in the cluster, and the
environment.
