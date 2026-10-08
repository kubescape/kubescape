---
references:
  - kind: code
    role: implementation
    target: core/core/patch.go
  - kind: code
    role: implementation
    target: core/core/image_scan.go#ScanImageContext
---

# Container image

A container image in a registry, the local image store or an archive, scanned
for vulnerabilities and, where possible, patched.

## Information kept

- **Reference** — the repository, tag or digest that identifies it
- **Platform** — the operating system and architecture variant scanned or built
