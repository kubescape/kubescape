---
appliesTo:
  - type: capability
    id: analyze-network-reachability
  - type: capability
    id: analyze-rbac-escalation-paths
  - type: capability
    id: analyze-service-exposure
  - type: capability
    id: analyze-mutating-admission-policy-impact
references:
  - kind: code
    role: implementation
    target: cmd/mcpserver/network_reachability.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/rbac_escalation.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/service_exposure.go
  - kind: code
    role: implementation
    target: cmd/mcpserver/mutating_policy_impact.go
---

# An analysis reports what it cannot establish instead of a clean result

These analyses read the cluster's configuration without running anything. Where
the configuration cannot settle the answer — a network policy that cannot be
read, an escalation search that reaches its bound, a route into another
namespace, a policy condition that cannot be evaluated statically — the result
says so rather than reporting the subject safe.
