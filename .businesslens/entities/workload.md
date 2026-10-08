---
references:
  - kind: code
    role: implementation
    target: cmd/operator/remediate.go
  - kind: code
    role: implementation
    target: core/pkg/pss/fetch.go#DefaultWorkloadTargets
---

# Workload

A Kubernetes workload running in a cluster — a Deployment, StatefulSet,
DaemonSet, Job, CronJob, ReplicaSet or Pod.

## Information kept

- **Kind** — the workload kind
- **Name** — the workload name
- **Namespace** — the namespace it runs in
- **Configuration** — its live settings, including its pod and container security settings
- **Remediation annotation** — the annotation recording a finding acted on, with its reason
- **Quarantine** — whether a deny-all network policy isolates it
