---
references:
  - kind: code
    role: implementation
    target: cmd/config/config.go
---

# Config

The Kubescape Cloud connection settings and the incremental scan cache Kubescape
keeps on the User's machine.

## Boundary

Config does not own the configuration and credentials kept in the cluster by the
Kubescape Operator's installation, which it only reads, nor control
configuration, which belongs to the policies a scan evaluates.
