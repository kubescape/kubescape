---
domain: scan
references:
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/results.go#HandleResults
  - kind: code
    role: implementation
    target: core/cautils/scancoverage.go#ComputeCoverageScore
  - kind: code
    role: implementation
    target: core/pkg/reportcrypto/report.go#DecryptReport
  - kind: code
    role: implementation
    target: core/pkg/vapreconcile/reconcile.go
  - kind: doc
    role: context
    target: docs/scan-coverage.md
---

# Scan report

The result of a misconfiguration scan: how the scanned resources fared against
each evaluated control, printed to the terminal or written in one or more
output formats (JSON, JUnit, SARIF, HTML, PDF, CSV, Markdown, Prometheus,
PolicyReport and others).

## Information kept

- **Scanned target** — the cluster, repository, files or workload that was scanned, with the cluster name or source paths
- **Frameworks** — the frameworks and controls the scan evaluated
- **Control results** — each control's status (passed, failed, skipped, excluded or needing review), severity and the resources that failed it
- **Resource results** — each scanned resource with the controls it failed and the failing paths
- **Compliance score** — the percentage of compliant resources across the evaluated controls
- **Scan coverage score** — how completely the scan evaluated, from the share of controls evaluated less penalties for resource types that failed to collect unnoticed, policy inputs served from a fallback and skipped manifests
- **Policy degradations** — exceptions or control configuration that were served from a fallback source
- **Image scan results** — vulnerabilities found in the scanned workloads' images, when images were also scanned
- **Admission policy coverage** — for a cluster that serves admission policies, which controls are already enforced or audited by a Kubescape admission policy bound there
- **Exception audit** — when requested, each loaded exception with whether it matched, went unused, expired or named an unknown control
- **Scan contract** — the contract applied, its digest, its effective settings and the flags that overrode it

## States

### Plain

All metadata appears as scanned.

### Anonymized

Sensitive metadata is replaced with deterministic pseudonyms that cannot be
reversed.

### Encrypted

Sensitive metadata is encrypted with the master key and can be restored with
the same key.
