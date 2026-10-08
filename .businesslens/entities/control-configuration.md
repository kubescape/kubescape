---
references:
  - kind: code
    role: implementation
    target: core/core/initutils.go#getConfigInputsGetterForTarget
  - kind: doc
    role: context
    target: docs/cli-reference.md
---

# Control configuration

The tunable inputs some controls are evaluated against — allowed image
repositories, the capabilities considered insecure, CPU and memory bounds. A
scan takes them from a local file, the Kubescape Cloud account, the cluster's
control input resource or the release defaults, in that order.

## Information kept

- **Inputs** — each configuration key with the value in effect and the controls that read it
