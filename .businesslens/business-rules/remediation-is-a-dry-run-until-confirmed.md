---
appliesTo:
  - type: capability
    id: annotate-workload
  - type: capability
    id: quarantine-workload
  - type: capability
    id: revert-remediation
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
---

# Workload remediation is a dry run until confirmed

Annotating, quarantining and reverting change no workload unless the User
confirms the request.
