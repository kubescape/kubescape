---
domain: vap
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go#deployLibrary
---

# Deploy the admission policy library

Print the Kubescape CEL admission policy library as manifests for the User to
apply to a cluster.
