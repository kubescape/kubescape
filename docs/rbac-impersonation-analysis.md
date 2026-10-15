# Impersonation targets and effective permissions

An unrestricted `impersonate` grant on `users` or `serviceaccounts` lets an
identity choose from an unbounded set of targets. It does not give every target
administrator permissions.

RBAC escalation analysis keeps these grants in `unbounded_findings`, including
an `impersonated_kind` identifying the target type. It follows collected
ServiceAccounts and identities mentioned in collected bindings to recover
their actual rules. ServiceAccount subjects and ServiceAccount-form User names
in bindings remain impersonation targets even if their objects were deleted:
Kubernetes authorizes impersonation without looking up those objects. A missing
namespace on a RoleBinding ServiceAccount subject defaults to the binding
namespace. Group-only bindings to `system:serviceaccounts` or
`system:serviceaccounts:<namespace>` also supply known permissions. Analysis
follows a valid representative username for each relevant group namespace,
using the exact names allowed by a restricted grant. These representatives do not
require a ServiceAccount object. These identities do not enter the live
ServiceAccount inventory used for pod creation or token minting. A target with only read access contributes
only read access; a namespaced permission remains namespaced.

`cluster_admin_equivalent` is confirmed when a real target or subsequent
escalation grants cluster-wide administrative power. A false value accompanied
by unbounded findings is not an all-clear: additional identities or bindings
outside the collected snapshot may still provide an escalation path.

ServiceAccount usernames require impersonation authorization on
`serviceaccounts`; a grant on `users` alone does not authorize them. Existing
handling of unrestricted group impersonation, including `system:masters`, and
`escalate` grants that can rewrite roles is preserved.

See [Kubernetes user impersonation](https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/).
