---
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/patch/patch.go#validateImagePatchInfo
  - kind: code
    role: implementation
    target: core/core/patch.go
  - kind: doc
    role: intent
    target: cmd/patch/README.md
---

# Patch a container image

Fix the operating-system package vulnerabilities in an image by building a
patched copy through a BuildKit daemon, then report the vulnerabilities that
remain.
