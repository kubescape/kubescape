---
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/download/download.go
  - kind: code
    role: implementation
    target: core/core/download.go#DownloadSupportCommands
---

# Download artifacts

Save frameworks, controls, control configuration, exceptions and attack tracks
to local files, so scans can run offline, air-gapped or from pinned copies.
