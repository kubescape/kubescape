---
domain: scan
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/scan/validate_contract.go#getValidateContractCmd
  - kind: code
    role: implementation
    target: core/pkg/scancontract/v1alpha1/loader.go#Load
---

# Validate a scan contract

Check a scan contract file and show which contract a scan of it would select,
without scanning.
