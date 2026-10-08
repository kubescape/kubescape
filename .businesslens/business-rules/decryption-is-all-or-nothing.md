---
appliesTo:
  - type: capability
    id: decrypt-scan-report
  - type: entity
    id: scan-report
references:
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/report.go#DecryptReport
---

# A report is decrypted completely or not at all

Decryption fails rather than return a report in which any encrypted value
remains.
