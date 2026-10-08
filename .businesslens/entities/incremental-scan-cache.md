---
singleton: true
references:
  - kind: code
    role: implementation
    target: core/pkg/scancache/scancache.go
  - kind: code
    role: implementation
    target: cmd/config/delete_cache.go
---

# Incremental scan cache

The results of earlier incremental scans, kept on the User's machine so that a
later incremental scan re-evaluates only resources that changed.

## Information kept

- **Cached results** — each evaluated resource's results, keyed by its specification, its metadata and the control configuration version
