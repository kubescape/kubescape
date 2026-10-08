---
appliesTo:
  - type: capability
    id: scan-misconfigurations
  - type: entity
    id: scan-contract
    facts: [Contracts]
references:
  - kind: code
    role: implementation
    target: cmd/scan/apply_contract.go#applyContractGateFloors
---

# The stricter of a contract gate and its flag applies

Where a scan contract and a command flag both set a failure gate, the stricter
of the two decides the exit status; other contract settings yield to flags.
