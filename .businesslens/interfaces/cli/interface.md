---
type: cli
actors: [user]
references:
  - kind: doc
    role: intent
    target: docs/cli-reference.md
  - kind: code
    role: implementation
    target: cmd/root.go#getRootCmd
---

# Kubescape CLI

The `kubescape` command a User runs from a terminal or a pipeline, against the
cluster of the current or a chosen kube context, local files, Git repositories
or container images. Nobody signs in: Kubescape Cloud credentials, when used,
come from the cached configuration or the environment.
