---
domain: vap
references:
  - kind: code
    role: implementation
    target: cmd/vap/vap.go
---

# Admission policy binding

A ValidatingAdmissionPolicyBinding that puts one policy from the Kubescape CEL
admission policy library into effect for chosen namespaces, labels and resource
types.

## Information kept

- **Name** — the binding's name
- **Policy** — the admission policy it binds, by policy name or control ID
- **Actions** — what the cluster does with a violating request: deny, warn or audit
- **Namespaces** — the namespaces it applies to
- **Labels** — the labels resources must carry for it to apply
- **Resource rules** — the resource types it narrows the policy to, among those the policy already matches
- **Parameter reference** — the parameter object the policy reads, for policies that take one
