---
references:
  - kind: code
    role: implementation
    target: core/pkg/resourcehandler/filesloader.go#getResourcesFromPath
  - kind: code
    role: implementation
    target: core/core/fix.go
---

# Manifest

The declaration of one Kubernetes resource in a YAML or JSON file, a Helm
chart, a Kustomize directory or a Git repository — what a file scan evaluates
and what a fix rewrites.

## Information kept

- **Path** — the file the resource is declared in
- **Kind** — the resource kind
- **Name** — the resource name
- **Namespace** — the namespace it is declared in, if any
- **Configuration** — the resource's declared settings
