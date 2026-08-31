# Path containment checks

Kubescape resource loaders sometimes need to decide whether a source file is
owned by a renderer such as Kustomize or Helm. When a renderer succeeds, raw
inputs below that renderer-owned directory should not be scanned again as plain
manifests.

Containment checks must account for path aliases. For example, on some systems
`/tmp/repo/app/deployment.yaml` and `/private/tmp/repo/app/deployment.yaml` can
refer to the same file. A filesystem walker may keep the lexical path while a
renderer or helper returns the symlink-resolved physical path.

`IsUnderAnyDir` compares aliases for both the source and candidate directories
so these equivalent spellings still match. The check remains directory-aware:
`app/service.yaml` is under `app`, but `app-docs/policy.yaml` is not.

Tests should cover:

- direct child paths
- prefix siblings
- filesystem root containment
- lexical source paths below physical directories
- physical source paths below lexical directories

Use the shared helper for filesystem ownership decisions instead of local
`strings.HasPrefix` checks.
