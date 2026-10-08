// Package rbacgraph models a cluster's RBAC objects (Roles, ClusterRoles,
// RoleBindings, ClusterRoleBindings, ServiceAccounts) as a graph of
// identities connected by privilege-escalation edges, and computes the
// transitive closure reachable from a starting identity -- "if this
// ServiceAccount/User/Group is compromised, what else becomes reachable."
//
// This is the RBAC counterpart to core/pkg/networkpolicy's pod-to-pod
// reachability model and core/pkg/exposure's external-reachability model:
// all three answer a "given X, what can actually be reached" question with
// a real graph traversal, rather than kubescape's existing RBAC coverage
// (control C-0015/C-0035, run via the generic Rego pipeline), which only
// flags a single object in isolation ("does this RoleBinding grant
// cluster-admin," "does this Role allow listing secrets") without ever
// checking whether a lower-privileged identity can reach that same power
// indirectly through one of the well-documented RBAC escalation techniques
// below.
//
// # Escalation primitives modeled
//
// Each is a specific, named Kubernetes RBAC escalation technique -- the
// same primitives security tooling such as PaloAltoNetworks/rbac-police and
// kubiscan check for in isolation; this package's contribution is chaining
// them into multi-hop paths, not inventing new ones:
//
//   - impersonate: the "impersonate" verb on users/groups/serviceaccounts
//     lets a subject act as the impersonated identity outright, inheriting
//     every permission it holds.
//   - escalate-verb: the "escalate" verb on roles/clusterroles, combined
//     with update/patch on the same resource, is Kubernetes' own built-in
//     escape hatch from its RBAC self-escalation prevention -- a subject
//     with both can grant themselves arbitrary rules directly.
//   - bind-verb: the "bind" verb on roles/clusterroles, combined with
//     create on rolebindings/clusterrolebindings, lets a subject attach any
//     Role/ClusterRole they can bind to a subject of their choosing
//     (typically themselves), adopting its rules without ever having held
//     them directly.
//   - assign-serviceaccount: create on pods lets a subject choose
//     spec.serviceAccountName freely (this package does not model
//     PodSecurity admission or third-party policy engines that might
//     restrict that choice -- see the package's trust-model note below),
//     so the subject can schedule a pod running as any ServiceAccount in
//     that namespace and read its mounted token from within.
//   - mint-serviceaccount-token: create on the serviceaccounts/token
//     subresource (the TokenRequest API) mints a live token for the named
//     ServiceAccount directly, no pod required.
//
// Two further things are modeled outside the five primitives above, both
// because a security-facing tool erring toward under-reporting reachable
// power is the more dangerous failure mode:
//
//   - Kubernetes' implicit groups: every ServiceAccount is automatically a
//     member of system:serviceaccounts, system:serviceaccounts:<its
//     namespace>, and system:authenticated; every User is a member of
//     system:authenticated. A RoleBinding/ClusterRoleBinding naming one of
//     these as its subject grants its rules to every matching identity,
//     not just to a literally-named Group object -- these are
//     authenticator-assigned, not RBAC objects, and binding a privileged
//     ClusterRole to one of them is a well-known real-world
//     misconfiguration.
//   - system:masters: hardcoded by the authorizer as an omnipotent
//     superuser group, bound to no RBAC object at all. Reaching it via
//     impersonation is an immediate, unconditional cluster-admin win --
//     the graph traversal would otherwise dead-end there and report a
//     false negative, since nothing binds it for DirectRules to find.
//
// # Trust model
//
// Like this repo's other reachability engines, this is a static model
// computed from RBAC object specs: holding a permission is treated as the
// ability to exercise it. It does not verify that PodSecurity admission,
// Gatekeeper/Kyverno, or any other admission-time control would actually
// block the pod-creation or token-minting step in practice -- those would
// only ever narrow an edge this package reports, never widen one, so a
// reported path is a genuine upper bound on what RBAC alone allows.
//
// This package also respects two real RBAC authorization mechanics that
// are easy to get backwards: a top-level "create" (the object doesn't
// exist yet) cannot be restricted by resourceNames -- a create rule
// carrying resourceNames authorizes nothing, not everything; and
// Users/Groups are non-namespaced identities, so a namespace-scoped
// Role/RoleBinding cannot meaningfully grant impersonate rights over them
// (only a cluster-scoped ClusterRole/ClusterRoleBinding can) -- unlike
// impersonating a ServiceAccount, which is itself a namespaced resource
// type a Role can constrain.
//
// # Non-goals (initial scope)
//
// Arbitrary User/Group impersonation (an unrestricted, wildcard-
// resourceNames grant) is reported as an Unbounded finding rather than
// enumerable edges, since there is no cluster object to enumerate target
// identities from. A "get/list secrets" edge toward legacy long-lived
// ServiceAccount token Secrets is not modeled at all.
package rbacgraph

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
)

// SubjectKind identifies what kind of RBAC identity a Subject is.
type SubjectKind string

const (
	KindServiceAccount SubjectKind = "ServiceAccount"
	KindUser           SubjectKind = "User"
	KindGroup          SubjectKind = "Group"
)

// Subject identifies one RBAC identity. Namespace is only meaningful (and
// only ever set) for a ServiceAccount -- Users and Groups are cluster-scoped
// identities in Kubernetes' RBAC model, even when everything they've been
// granted is namespace-confined.
//
// A User named system:serviceaccount:<namespace>:<name> carries a
// ServiceAccount's username and is granted whatever is bound to that username,
// by a User or a ServiceAccount subject. It is not credited with the
// ServiceAccount's groups: those come from the authenticator, not from the
// name. To analyze the ServiceAccount as its own token authenticates, groups
// included, use KindServiceAccount.
type Subject struct {
	Kind      SubjectKind
	Namespace string
	Name      string
}

func (s Subject) String() string {
	if s.Kind == KindServiceAccount {
		return fmt.Sprintf("ServiceAccount %s/%s", s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Name)
}

// ScopedRule is a PolicyRule together with the scope it was granted at.
// Namespace == "" means cluster-wide (granted via a ClusterRoleBinding);
// any other value confines the rule to that namespace (granted via a
// RoleBinding, whether the RoleBinding references a Role or a ClusterRole
// -- referencing a ClusterRole from a RoleBinding is a common way to reuse
// a ClusterRole's rules within a single namespace only).
type ScopedRule struct {
	Rule      rbacv1.PolicyRule
	Namespace string
}

// EscalationPrimitive names which well-known RBAC escalation technique an
// EscalationEdge represents. See the package doc comment for what each one
// means and why it's a real, not speculative, technique.
type EscalationPrimitive string

const (
	PrimitiveImpersonate             EscalationPrimitive = "impersonate"
	PrimitiveEscalateVerb            EscalationPrimitive = "escalate-verb"
	PrimitiveBindVerb                EscalationPrimitive = "bind-verb"
	PrimitiveAssignServiceAccount    EscalationPrimitive = "assign-serviceaccount"
	PrimitiveMintServiceAccountToken EscalationPrimitive = "mint-serviceaccount-token"
)

// EscalationEdge is one hop a Subject can take to gain privilege beyond
// what their own directly-bound rules grant. Exactly one of ToSubject or
// (GrantedRules / Unbounded) is meaningful for a given edge: impersonate,
// assign-serviceaccount, and mint-serviceaccount-token lead to assuming a
// concrete other identity (ToSubject set); escalate-verb and bind-verb
// grant additional rules directly, with no distinct identity to name
// (GrantedRules and/or Unbounded set instead).
type EscalationEdge struct {
	Primitive EscalationPrimitive
	// Detail is a human-readable explanation naming the object(s) involved
	// (e.g. the RoleBinding, the target Role/ClusterRole, the target SA).
	Detail string

	ToSubject *Subject

	GrantedRules []ScopedRule

	// Unbounded is true when this edge grants everything within Scope,
	// rather than a specific enumerable rule set -- an unrestricted bind or
	// escalate rule (no resourceNames) is not confined to the
	// Roles/ClusterRoles this package happened to collect; it covers any
	// Role/ClusterRole that could ever exist in that scope.
	Unbounded bool
	// Scope is "" for cluster-wide, else the namespace the edge is confined
	// to: the namespace an Unbounded edge grants everything in, or, for a
	// bind-verb edge, the namespace the new RoleBinding is created in ("" for
	// a ClusterRoleBinding). Unset on every other edge.
	Scope string

	// Target is the Role or ClusterRole an escalate-verb edge rewrites or a
	// bind-verb edge binds, so a caller can tell which object an edge is
	// about without parsing Detail. Nil on every other primitive.
	Target *RoleTarget
}

// RoleTarget identifies the Role(s) or ClusterRole(s) an escalate-verb or
// bind-verb EscalationEdge acts on.
type RoleTarget struct {
	// Kind is "Role" or "ClusterRole".
	Kind string
	// Namespace is the Role's namespace. It is "" for a ClusterRole, and ""
	// for a Role when the edge covers Roles in every namespace.
	Namespace string
	// Name is the object's name, or "" when the edge covers every object of
	// Kind in Namespace (an unrestricted grant). A grant restricted by
	// resourceNames always carries the name, whether or not an object of that
	// name was found in the collected snapshot.
	Name string
}

// Covers reports whether t includes the Role or ClusterRole identified by
// kind, namespace and name.
func (t RoleTarget) Covers(kind, namespace, name string) bool {
	return t.Kind == kind &&
		(t.Namespace == "" || t.Namespace == namespace) &&
		(t.Name == "" || t.Name == name)
}

// EscalationPath is one hop-by-hop chain from a starting Subject, letting a
// caller show its reasoning, not just the final reachable set.
type EscalationPath struct {
	From  Subject
	Edges []EscalationEdge
}
