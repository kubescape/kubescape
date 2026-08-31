package rbacgraph

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
)

// DirectEscalationEdges returns every one-hop escalation technique subject
// can exercise given rules (their currently-known ScopedRules -- either
// DirectRules(subject), or an enriched set after a bind-verb/escalate-verb
// edge has already granted additional rules to subject). Self-edges (an
// edge whose ToSubject is subject itself, e.g. a Pod-creation right letting
// a ServiceAccount "assign" its own identity) are filtered out -- they
// don't represent an escalation.
func (idx *Index) DirectEscalationEdges(subject Subject, rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	edges = append(edges, idx.impersonateEdges(rules)...)
	edges = append(edges, idx.escalateVerbEdges(rules)...)
	edges = append(edges, idx.bindVerbEdges(rules)...)
	edges = append(edges, idx.assignServiceAccountEdges(rules)...)
	edges = append(edges, idx.mintServiceAccountTokenEdges(rules)...)

	out := edges[:0]
	for _, e := range edges {
		if e.ToSubject != nil && *e.ToSubject == subject {
			continue
		}
		out = append(out, e)
	}
	return out
}

// impersonateEdges implements the impersonate primitive: the "impersonate"
// verb (core API group) on serviceaccounts/users/groups lets a subject act
// as the impersonated identity outright. serviceaccounts targets are
// enumerated against collected ServiceAccount objects (respecting the
// granting rule's own namespace scope, or every collected namespace for a
// cluster-wide grant); users/groups targets are enumerated only when the
// rule names them explicitly via resourceNames, since there is no cluster
// object to enumerate arbitrary user/group identities from -- an
// unrestricted rule against any of the three resource types is reported as
// an Unbounded finding instead of guessed-at concrete edges.
func (idx *Index) impersonateEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	for _, sr := range rules {
		rule := sr.Rule
		if !containsOrWildcard(rule.Verbs, "impersonate") || !containsOrWildcard(rule.APIGroups, "") {
			continue
		}
		names, restricted := namedResources(rule)

		if containsOrWildcard(rule.Resources, "serviceaccounts") || containsOrWildcard(rule.Resources, "*") {
			if !restricted {
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveImpersonate,
					Detail:    "can impersonate any ServiceAccount (unrestricted impersonate on serviceaccounts)",
					Unbounded: true,
					Scope:     sr.Namespace,
				})
			} else {
				for _, ns := range idx.targetNamespaces(sr.Namespace) {
					for _, saName := range idx.serviceAccountsByNS[ns] {
						if !containsOrWildcard(names, saName) {
							continue
						}
						edges = append(edges, EscalationEdge{
							Primitive: PrimitiveImpersonate,
							Detail:    fmt.Sprintf("can impersonate ServiceAccount %s/%s", ns, saName),
							ToSubject: &Subject{Kind: KindServiceAccount, Namespace: ns, Name: saName},
						})
					}
				}
			}
		}
		if containsOrWildcard(rule.Resources, "users") || containsOrWildcard(rule.Resources, "*") {
			if !restricted {
				edges = append(edges, EscalationEdge{Primitive: PrimitiveImpersonate, Detail: "can impersonate any User (unrestricted impersonate on users)", Unbounded: true})
			} else {
				for _, name := range names {
					edges = append(edges, EscalationEdge{Primitive: PrimitiveImpersonate, Detail: fmt.Sprintf("can impersonate User %q", name), ToSubject: &Subject{Kind: KindUser, Name: name}})
				}
			}
		}
		if containsOrWildcard(rule.Resources, "groups") || containsOrWildcard(rule.Resources, "*") {
			if !restricted {
				edges = append(edges, EscalationEdge{Primitive: PrimitiveImpersonate, Detail: "can impersonate any Group (unrestricted impersonate on groups)", Unbounded: true})
			} else {
				for _, name := range names {
					edges = append(edges, EscalationEdge{Primitive: PrimitiveImpersonate, Detail: fmt.Sprintf("can impersonate Group %q", name), ToSubject: &Subject{Kind: KindGroup, Name: name}})
				}
			}
		}
	}
	return edges
}

// escalateVerbEdges implements the escalate-verb primitive: Kubernetes'
// RBAC self-escalation prevention normally stops a subject from granting a
// Role/ClusterRole rules it doesn't already itself hold, unless the
// subject also holds the "escalate" verb on that resource type -- combined
// with update/patch (needed to actually modify the object), that's a
// documented built-in bypass. Only clusterroles at cluster scope and roles
// at either scope are modeled; a namespace-scoped rule naming the
// cluster-scoped "clusterroles" resource type is an unusual enough pattern
// that this package doesn't attempt to reason about its effect.
func (idx *Index) escalateVerbEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	for _, resource := range []string{"clusterroles", "roles"} {
		escalateScopes := map[string]bool{}
		mutateScopes := map[string]bool{}
		for _, sr := range rules {
			if ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "escalate") {
				escalateScopes[sr.Namespace] = true
			}
			if ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "update") || ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "patch") {
				mutateScopes[sr.Namespace] = true
			}
		}
		for ns := range escalateScopes {
			if !mutateScopes[ns] {
				continue
			}
			if resource == "clusterroles" && ns != "" {
				continue
			}
			edges = append(edges, EscalationEdge{
				Primitive: PrimitiveEscalateVerb,
				Detail:    fmt.Sprintf("holds escalate + update/patch on %s.rbac.authorization.k8s.io", resource),
				Unbounded: true,
				Scope:     ns,
			})
		}
	}
	return edges
}

// bindVerbEdges implements the bind-verb primitive: the "bind" verb on a
// Role/ClusterRole is RBAC's other documented self-escalation-prevention
// bypass -- combined with the ability to create a RoleBinding or
// ClusterRoleBinding, a subject can attach any Role/ClusterRole they can
// bind to a subject of their choosing (in practice, themselves), adopting
// its rules without ever having held them directly.
func (idx *Index) bindVerbEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge

	for _, sr := range rules {
		if !ruleGrants(sr.Rule, "rbac.authorization.k8s.io", "clusterroles", "bind") {
			continue
		}
		names, restricted := namedResources(sr.Rule)
		targets := idx.matchingClusterRoles(names, restricted)

		if idx.hasClusterWideCreate(rules, "clusterrolebindings") {
			for _, cr := range targets {
				edges = append(edges, EscalationEdge{
					Primitive:    PrimitiveBindVerb,
					Detail:       fmt.Sprintf("can bind ClusterRole %q cluster-wide via a new ClusterRoleBinding", cr.Name),
					GrantedRules: scopeRules(cr.Rules, ""),
				})
			}
		}
		for _, ns := range idx.namespacesWithCreate(rules, "rolebindings") {
			for _, cr := range targets {
				edges = append(edges, EscalationEdge{
					Primitive:    PrimitiveBindVerb,
					Detail:       fmt.Sprintf("can bind ClusterRole %q within namespace %q via a new RoleBinding", cr.Name, ns),
					GrantedRules: scopeRules(cr.Rules, ns),
				})
			}
		}
	}

	for _, sr := range rules {
		if sr.Namespace == "" || !ruleGrants(sr.Rule, "rbac.authorization.k8s.io", "roles", "bind") {
			continue
		}
		if !idx.hasCreateInNamespace(rules, "rolebindings", sr.Namespace) {
			continue
		}
		names, restricted := namedResources(sr.Rule)
		for _, r := range idx.matchingRoles(sr.Namespace, names, restricted) {
			edges = append(edges, EscalationEdge{
				Primitive:    PrimitiveBindVerb,
				Detail:       fmt.Sprintf("can bind Role %q within namespace %q via a new RoleBinding", r.Name, sr.Namespace),
				GrantedRules: scopeRules(r.Rules, sr.Namespace),
			})
		}
	}
	return edges
}

// assignServiceAccountEdges implements the assign-serviceaccount primitive:
// create on pods lets a subject choose spec.serviceAccountName freely (see
// the package doc comment's trust-model note on admission-time
// restrictions this package does not model), so the subject can schedule a
// pod running as any ServiceAccount in that namespace and read its mounted
// token from within.
func (idx *Index) assignServiceAccountEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	for _, sr := range rules {
		if !ruleGrants(sr.Rule, "", "pods", "create") {
			continue
		}
		for _, ns := range idx.targetNamespaces(sr.Namespace) {
			for _, saName := range idx.serviceAccountsByNS[ns] {
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveAssignServiceAccount,
					Detail:    fmt.Sprintf("can create Pods in namespace %q and assign spec.serviceAccountName=%q, inheriting its mounted token", ns, saName),
					ToSubject: &Subject{Kind: KindServiceAccount, Namespace: ns, Name: saName},
				})
			}
		}
	}
	return edges
}

// mintServiceAccountTokenEdges implements the mint-serviceaccount-token
// primitive: create on the serviceaccounts/token subresource (the
// TokenRequest API) mints a live token for the named ServiceAccount
// directly, no pod required.
func (idx *Index) mintServiceAccountTokenEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	for _, sr := range rules {
		if !ruleGrants(sr.Rule, "", "serviceaccounts/token", "create") {
			continue
		}
		names, restricted := namedResources(sr.Rule)
		for _, ns := range idx.targetNamespaces(sr.Namespace) {
			for _, saName := range idx.serviceAccountsByNS[ns] {
				if restricted && !containsOrWildcard(names, saName) {
					continue
				}
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveMintServiceAccountToken,
					Detail:    fmt.Sprintf("can mint a live token for ServiceAccount %s/%s via the TokenRequest API", ns, saName),
					ToSubject: &Subject{Kind: KindServiceAccount, Namespace: ns, Name: saName},
				})
			}
		}
	}
	return edges
}

// targetNamespaces expands a ScopedRule's own scope into the namespaces an
// edge should enumerate targets against: just that one namespace for a
// namespace-scoped rule, or every namespace this Index has ServiceAccount
// data for when the rule is cluster-wide.
func (idx *Index) targetNamespaces(scopeNamespace string) []string {
	if scopeNamespace != "" {
		return []string{scopeNamespace}
	}
	out := make([]string, 0, len(idx.serviceAccountsByNS))
	for ns := range idx.serviceAccountsByNS {
		out = append(out, ns)
	}
	return out
}

func (idx *Index) matchingClusterRoles(names []string, restricted bool) []*rbacv1.ClusterRole {
	var out []*rbacv1.ClusterRole
	for _, cr := range idx.clusterRoles {
		if restricted && !containsOrWildcard(names, cr.Name) {
			continue
		}
		out = append(out, cr)
	}
	return out
}

func (idx *Index) matchingRoles(namespace string, names []string, restricted bool) []*rbacv1.Role {
	var out []*rbacv1.Role
	for _, r := range idx.roles {
		if r.Namespace != namespace {
			continue
		}
		if restricted && !containsOrWildcard(names, r.Name) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (idx *Index) hasClusterWideCreate(rules []ScopedRule, resource string) bool {
	for _, sr := range rules {
		if sr.Namespace == "" && ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "create") {
			return true
		}
	}
	return false
}

func (idx *Index) hasCreateInNamespace(rules []ScopedRule, resource, namespace string) bool {
	for _, sr := range rules {
		if sr.Namespace == namespace && ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "create") {
			return true
		}
	}
	return false
}

func (idx *Index) namespacesWithCreate(rules []ScopedRule, resource string) []string {
	seen := map[string]bool{}
	var out []string
	for _, sr := range rules {
		if sr.Namespace == "" {
			continue
		}
		if !ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "create") {
			continue
		}
		if seen[sr.Namespace] {
			continue
		}
		seen[sr.Namespace] = true
		out = append(out, sr.Namespace)
	}
	return out
}

func scopeRules(rules []rbacv1.PolicyRule, namespace string) []ScopedRule {
	out := make([]ScopedRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ScopedRule{Rule: r, Namespace: namespace})
	}
	return out
}
