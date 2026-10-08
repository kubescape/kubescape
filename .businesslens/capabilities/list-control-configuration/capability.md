---
availability:
  - { place: cli }
references:
  - kind: code
    role: implementation
    target: cmd/list/list.go
  - kind: code
    role: implementation
    target: core/core/list.go
  - kind: code
    role: implementation
    target: core/core/initutils.go#getConfigInputsGetterForTarget
---

# List control configuration

List the configurable inputs controls are evaluated against, with the value a
scan would use and the controls that read each one.
