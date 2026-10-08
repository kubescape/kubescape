---
domain: scan
references:
  - kind: code
    role: implementation
    target: core/pkg/scancontract/v1alpha1/types.go#Document
  - kind: code
    role: implementation
    target: core/pkg/scancontract/v1alpha1/validation.go
  - kind: code
    role: implementation
    target: cmd/scan/apply_contract.go
---

# Scan contract

A file kept with a repository that names how it must be scanned, so that every
scan of it uses the same policy, scope, evaluation settings, failure gates and
output.

## Information kept

- **Minimum Kubescape version** — the oldest Kubescape release allowed to apply it
- **Default contract** — the named contract used when none is chosen
- **Contracts** — each named contract with its frameworks or controls, namespace scope, evaluation settings, failure gates and output formats
