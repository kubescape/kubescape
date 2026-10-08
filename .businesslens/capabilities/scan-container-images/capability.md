---
domain: scan
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/scan/image.go#getImageCmd
  - kind: code
    role: implementation
    target: core/core/image_scan.go#ScanImageContext
  - kind: code
    role: implementation
    target: pkg/imagescan/imagescan.go
  - kind: doc
    role: intent
    target: docs/image-scanning.md
  - kind: doc
    role: context
    target: docs/multi-architecture-image-scanning.md
---

# Scan images for vulnerabilities

Find the known vulnerabilities in one or more container images — from a
registry, with credentials when needed, or from a local archive — for a chosen
platform, and report them in one run. The vulnerability database is brought up
to date first unless the User asks to use the cached one.
