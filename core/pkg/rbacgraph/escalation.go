package rbacgraph

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
)

// superuserGroups are RBAC subject names the authorizer treats as
// omnipotent without any RBAC object ever binding them -- reaching one via
// impersonation is an immediate, unconditional cluster-admin win, and the
// BFS would otherwise dead-end there (nothing binds these names, so
// DirectRules finds nothing further).
var superuserGroups = map[string]bool{
	"system:masters": true,
}

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
// as the impersonated identity outright.
//
// serviceaccounts targets are enumerated against collected ServiceAccount
// objects regardless of whether the rule is resourceNames-restricted (an
// unrestricted grant is a superset of the restricted case, so it must
// enumerate the same targets too, in addition to being reported as
// Unbounded for whatever this Index didn't collect).
//
// users/groups targets are enumerated only when the rule names them
// explicitly via resourceNames, since there is no cluster object to
// enumerate arbitrary user/group identities from. These two branches also
// only fire from a cluster-wide rule (granted via ClusterRoleBinding):
// Users and Groups are not namespaced identities, and Kubernetes' RBAC
// authorizer does not honor a namespace-scoped Role/RoleBinding's grant
// against them -- only serviceaccounts is itself a namespaced resource
// type a Role can meaningfully constrain.
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
			}
			for _, ns := range idx.targetNamespaces(sr.Namespace) {
				for _, saName := range idx.serviceAccountsByNS[ns] {
					if restricted && !containsOrWildcard(names, saName) {
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
		if sr.Namespace != "" {
			continue // users/groups impersonation is not honored from a namespace-scoped grant
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

// roleCoverage tracks, for one verb across one scope, whether a subject's
// rules cover every object of a resource type (Unrestricted) or only
// specific named ones (Names) -- used by escalateVerbEdges to correlate
// two different verbs (escalate, and update/patch) against the same
// target role, not just the same scope.
type roleCoverage struct {
	unrestricted bool
	names        map[string]bool
}

func (c *roleCoverage) add(rule rbacv1.PolicyRule) {
	names, restricted := namedResources(rule)
	if !restricted {
		c.unrestricted = true
		return
	}
	for _, n := range names {
		c.names[n] = true
	}
}

// escalateVerbEdges implements the escalate-verb primitive: Kubernetes'
// RBAC self-escalation prevention normally stops a subject from granting a
// Role/ClusterRole rules it doesn't already itself hold, unless the
// subject also holds the "escalate" verb on that resource type -- combined
// with update/patch (needed to actually modify the object), that's a
// documented built-in bypass. The escalate grant and the update/patch grant
// must actually cover the *same* role -- two independent resourceNames-
// restricted grants for different roles (escalate on role-a, update on
// role-b) don't combine into anything exploitable, so this correlates them
// by target name (or scope-wide, when either or both sides are
// unrestricted) rather than just checking "does the subject hold both verbs
// somewhere in this scope." Only clusterroles at cluster scope and roles at
// either scope are modeled; a namespace-scoped rule naming the
// cluster-scoped "clusterroles" resource type is an unusual enough pattern
// that this package doesn't attempt to reason about its effect.
func (idx *Index) escalateVerbEdges(rules []ScopedRule) []EscalationEdge {
	var edges []EscalationEdge
	for _, resource := range []string{"clusterroles", "roles"} {
		escalateByScope := map[string]*roleCoverage{}
		mutateByScope := map[string]*roleCoverage{}
		for _, sr := range rules {
			if ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "escalate") {
				c, ok := escalateByScope[sr.Namespace]
				if !ok {
					c = &roleCoverage{names: map[string]bool{}}
					escalateByScope[sr.Namespace] = c
				}
				c.add(sr.Rule)
			}
			if ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "update") || ruleGrants(sr.Rule, "rbac.authorization.k8s.io", resource, "patch") {
				c, ok := mutateByScope[sr.Namespace]
				if !ok {
					c = &roleCoverage{names: map[string]bool{}}
					mutateByScope[sr.Namespace] = c
				}
				c.add(sr.Rule)
			}
		}

		for scope, esc := range escalateByScope {
			if resource == "clusterroles" && scope != "" {
				continue
			}
			mut, ok := mutateByScope[scope]
			if !ok {
				continue
			}

			if esc.unrestricted && mut.unrestricted {
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveEscalateVerb,
					Detail:    fmt.Sprintf("holds escalate + update/patch on %s.rbac.authorization.k8s.io", resource),
					Unbounded: true,
					Scope:     scope,
				})
				continue
			}

			// targetNames == empty here (both grants restricted, no
			// overlapping name) is a genuine rejection -- escalate on
			// role-a and update on role-b don't authorize rewriting
			// either, so no edge, no fallback.
			var targetNames []string
			switch {
			case esc.unrestricted:
				targetNames = setToSlice(mut.names)
			case mut.unrestricted:
				targetNames = setToSlice(esc.names)
			default:
				targetNames = intersectSets(esc.names, mut.names)
			}
			if len(targetNames) == 0 {
				continue
			}
			sort.Strings(targetNames)

			if resource == "clusterroles" {
				matched := idx.matchingClusterRoles(targetNames, true)
				if len(matched) == 0 {
					// targetNames is non-empty (the grants do overlap on a
					// name) but resolves to no object this Index actually
					// collected -- that could mean the name is stale, or it
					// could mean a partial/paginated collection missed it.
					// Fail toward reporting risk, not silence: the prior
					// (pre-name-correlation) version of this code reported a
					// scope-level Unbounded here, and dropping that
					// silently would be a regression in exactly the
					// direction this package exists to avoid.
					edges = append(edges, EscalationEdge{
						Primitive: PrimitiveEscalateVerb,
						Detail:    fmt.Sprintf("holds escalate + update/patch on ClusterRole(s) %v, not found in the collected snapshot -- may be a partial collection, not a confirmed absence", targetNames),
						Unbounded: true,
						Scope:     "",
					})
				}
				for _, cr := range matched {
					edges = append(edges, EscalationEdge{
						Primitive: PrimitiveEscalateVerb,
						Detail:    fmt.Sprintf("holds escalate + update/patch on ClusterRole %q: can rewrite it to grant itself anything", cr.Name),
						Unbounded: true,
						Scope:     "",
					})
				}
				continue
			}

			var roles []*rbacv1.Role
			if scope == "" {
				roles = idx.matchingRolesAnyNamespace(targetNames, true)
			} else {
				roles = idx.matchingRoles(scope, targetNames, true)
			}
			if len(roles) == 0 {
				// Same partial-collection fallback as the clusterroles case
				// above.
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveEscalateVerb,
					Detail:    fmt.Sprintf("holds escalate + update/patch on Role(s) %v in namespace scope %q, not found in the collected snapshot -- may be a partial collection, not a confirmed absence", targetNames, scope),
					Unbounded: true,
					Scope:     scope,
				})
			}
			for _, r := range roles {
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveEscalateVerb,
					Detail:    fmt.Sprintf("holds escalate + update/patch on Role %q in namespace %q: can rewrite it to grant itself anything", r.Name, r.Namespace),
					Unbounded: true,
					Scope:     r.Namespace,
				})
			}
		}
	}
	return edges
}

// bindVerbEdges implements the bind-verb primitive: the "bind" verb on a
// Role/ClusterRole is RBAC's other documented self-escalation-prevention
// bypass -- combined with the ability to create a RoleBinding or
// ClusterRoleBinding, a subject can attach any Role/ClusterRole they can
// bind to a subject of their choosing (in practice, themselves), adopting
// its rules without ever having held them directly. A cluster-wide grant of
// either half (bind, or create rolebindings/clusterrolebindings) is treated
// as covering every namespace this Index knows about, not skipped -- it is
// the more powerful case, not an edge case to exclude.
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
		for _, ns := range idx.knownNamespaces() {
			if !idx.canCreateRoleBindingsIn(rules, ns) {
				continue
			}
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
		if !ruleGrants(sr.Rule, "rbac.authorization.k8s.io", "roles", "bind") {
			continue
		}
		names, restricted := namedResources(sr.Rule)
		var candidates []*rbacv1.Role
		if sr.Namespace == "" {
			candidates = idx.matchingRolesAnyNamespace(names, restricted)
		} else {
			candidates = idx.matchingRoles(sr.Namespace, names, restricted)
		}
		for _, r := range candidates {
			if !idx.canCreateRoleBindingsIn(rules, r.Namespace) {
				continue
			}
			edges = append(edges, EscalationEdge{
				Primitive:    PrimitiveBindVerb,
				Detail:       fmt.Sprintf("can bind Role %q within namespace %q via a new RoleBinding", r.Name, r.Namespace),
				GrantedRules: scopeRules(r.Rules, r.Namespace),
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
		if !ruleGrantsUnnamedCreate(sr.Rule, "", "pods") {
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
// directly, no pod required. Unlike a top-level create, this is a create on
// an already-named parent object (POST .../serviceaccounts/{name}/token),
// so resourceNames legitimately restricts it -- this is intentionally not
// routed through ruleGrantsUnnamedCreate.
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

// knownNamespaces returns every namespace this Index has any evidence of,
// drawn from collected ServiceAccounts, Roles, and RoleBindings -- used to
// expand a cluster-wide grant (e.g. create rolebindings with no namespace
// restriction) into the concrete namespaces this package can reason about.
func (idx *Index) knownNamespaces() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ns string) {
		if ns == "" || seen[ns] {
			return
		}
		seen[ns] = true
		out = append(out, ns)
	}
	for ns := range idx.serviceAccountsByNS {
		add(ns)
	}
	for _, r := range idx.roles {
		add(r.Namespace)
	}
	for _, rb := range idx.roleBindings {
		add(rb.Namespace)
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

// matchingRolesAnyNamespace is matchingRoles without a namespace filter --
// for a cluster-wide grant (e.g. bind on roles via a ClusterRoleBinding),
// which applies to Role objects in every namespace, not just one.
func (idx *Index) matchingRolesAnyNamespace(names []string, restricted bool) []*rbacv1.Role {
	var out []*rbacv1.Role
	for _, r := range idx.roles {
		if restricted && !containsOrWildcard(names, r.Name) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (idx *Index) hasClusterWideCreate(rules []ScopedRule, resource string) bool {
	for _, sr := range rules {
		if sr.Namespace == "" && ruleGrantsUnnamedCreate(sr.Rule, "rbac.authorization.k8s.io", resource) {
			return true
		}
	}
	return false
}

func (idx *Index) hasCreateInNamespace(rules []ScopedRule, resource, namespace string) bool {
	for _, sr := range rules {
		if sr.Namespace == namespace && ruleGrantsUnnamedCreate(sr.Rule, "rbac.authorization.k8s.io", resource) {
			return true
		}
	}
	return false
}

// canCreateRoleBindingsIn reports whether rules lets the subject create a
// RoleBinding in namespace ns -- either via a grant scoped to exactly that
// namespace, or a cluster-wide grant (covers every namespace).
func (idx *Index) canCreateRoleBindingsIn(rules []ScopedRule, ns string) bool {
	return idx.hasCreateInNamespace(rules, "rolebindings", ns) || idx.hasClusterWideCreate(rules, "rolebindings")
}

func scopeRules(rules []rbacv1.PolicyRule, namespace string) []ScopedRule {
	out := make([]ScopedRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, ScopedRule{Rule: r, Namespace: namespace})
	}
	return out
}
