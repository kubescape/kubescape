---
appliesTo:
  - type: capability
    id: fix-misconfigurations
  - type: entity
    id: manifest
    effect: changes
references:
  - kind: code
    role: implementation
    target: cmd/fix/fix.go
---

# Manifests are fixed in place only once confirmed

An in-place fix of manifest files changes them only after the User confirms in
an interactive terminal or has asked to skip confirmation; without a terminal,
nothing is applied.
