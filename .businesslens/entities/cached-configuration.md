---
domain: config
singleton: true
references:
  - kind: code
    role: implementation
    target: core/cautils/customerloader.go#ConfigFileFullPath
  - kind: code
    role: implementation
    target: core/core/cachedconfig.go#ViewCachedConfig
---

# Cached configuration

The Kubescape Cloud connection settings Kubescape keeps on the User's machine,
combined when read with the Kubescape configuration and credentials kept in the
cluster and with environment settings.

## Information kept

- **Account ID** — the Kubescape Cloud account results are submitted to
- **Access key** — the credential for that account
- **Cloud API URL** — where Kubescape Cloud's API is reached
- **Cloud report URL** — where scan results are submitted
