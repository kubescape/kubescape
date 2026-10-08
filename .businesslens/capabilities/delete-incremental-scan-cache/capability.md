---
domain: config
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/config/delete_cache.go
  - kind: code
    role: implementation
    target: core/pkg/scancache/scancache.go
---

# Delete the incremental scan cache

Discard the incremental scan cache, so that the next incremental scan evaluates
every resource again.
