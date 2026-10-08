---
references:
  - kind: code
    role: implementation
    target: core/core/list.go
  - kind: code
    role: implementation
    target: core/cautils/getter/customrules.go#LoadCustomRules
---

# Control

One security check evaluated against Kubernetes resources, identified by a
control ID such as C-0057. A custom rule a User supplies to a scan becomes a
control named `custom-` followed by the rule's name.

## Information kept

- **Control ID** — the identifier scans, fixes and admission policies refer to
- **Name** — what the control checks, in words
- **Severity** — low, medium, high or critical, derived from the control's base score
- **Remediation** — how to bring a failing resource into compliance
- **Frameworks** — the frameworks that include it
