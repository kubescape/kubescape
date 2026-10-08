---
references:
  - kind: code
    role: implementation
    target: core/core/list.go
  - kind: code
    role: implementation
    target: core/core/initutils.go#getPolicyGetter
---

# Framework

A named set of controls a scan evaluates against, such as NSA-CISA, MITRE
ATT&CK, the CIS Benchmark, SOC 2 or PCI DSS. Frameworks come from the
Kubescape Cloud account when an account and its API URL are configured,
otherwise from the regolibrary release, falling back to the local cache when
the release cannot be fetched.

## Information kept

- **Name** — the name a scan or download is asked for by
- **Controls** — the controls the framework contains
