---
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/decrypt/decrypt.go
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/report.go#DecryptReport
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/masterkey.go#GetMasterKeyFromEnv
---

# Decrypt a scan report

Restore the metadata of a JSON scan report that was encrypted at scan time,
using the same master key.
