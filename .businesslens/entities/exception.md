---
references:
  - kind: code
    role: implementation
    target: core/cautils/getter/mergedexceptionsgetter.go
  - kind: code
    role: implementation
    target: core/pkg/opaprocessor/processorhandlerutils.go#filterExpiredExceptions
  - kind: code
    role: implementation
    target: core/pkg/resultshandling/printer/v2/exceptionsprinter.go#buildExceptionPolicies
  - kind: doc
    role: context
    target: examples/exceptions/README.md
---

# Exception

An accepted deviation from one or more controls for named resources. Exceptions
come from an exceptions file, the Kubescape Cloud account or the release
defaults, merged with the exception resources kept in the cluster; scans of
files also honour skip annotations on the manifests themselves.

## Information kept

- **Name** — the exception's name
- **Action** — whether matching findings are suppressed as passed with exceptions, or acknowledged but left failed
- **Controls** — the controls it covers
- **Resources** — the resources it covers, by kind, namespace, name and source path
- **Expiry** — when it stops applying, if ever
