package rbacgraph

import (
	"fmt"
	"maps"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
)

// roleRewrite records a reachable identity's ability to rewrite a role. It is
// shared only within one analysis: changing the role can benefit another
// reachable identity, but must not mutate the Index used by later queries.
type roleRewrite struct {
	subject Subject
	edge    EscalationEdge
}

// rewriteEdges separates authority to edit a role from authority obtained
// through a binding. Rewriting an unbound role is a risk finding, not a grant.
func (idx *Index) rewriteEdges(subject Subject, rules []ScopedRule, rewrites []roleRewrite) []EscalationEdge {
	var edges []EscalationEdge
	for _, rewrite := range rewrites {
		e := rewrite.edge
		acquired := false
		add := func(target RoleTarget) {
			for _, scope := range idx.rewriteBindingScopes(subject, rules, target) {
				acquired = true
				edges = append(edges, EscalationEdge{
					Primitive: PrimitiveEscalateVerb,
					Detail:    fmt.Sprintf("%s can rewrite %s %s/%s; %s can acquire its rules through %s", rewrite.subject, target.Kind, target.Namespace, target.Name, subject, scope.via),
					Unbounded: true,
					Scope:     scope.namespace,
					Target:    &target,
				})
			}
		}
		if e.Target != nil {
			switch e.Target.Kind {
			case "ClusterRole":
				for _, name := range slices.Sorted(maps.Keys(idx.clusterRoles)) {
					if e.Target.Covers("ClusterRole", "", name) {
						add(RoleTarget{Kind: "ClusterRole", Name: name})
					}
				}
			case "Role":
				for _, key := range slices.Sorted(maps.Keys(idx.roles)) {
					role := idx.roles[key]
					if e.Target.Covers("Role", role.Namespace, role.Name) {
						add(RoleTarget{Kind: "Role", Namespace: role.Namespace, Name: role.Name})
					}
				}
			}
		}
		// An unrestricted rewrite still covers targets outside the collected
		// binding paths, even when some concrete roles granted permissions.
		if rewrite.subject == subject && (!acquired || (e.Target != nil && e.Target.Name == "")) {
			e.PermissionsUnconfirmed = true
			e.Detail += "; no usable binding to acquire the rewritten permissions was established"
			edges = append(edges, e)
		}
	}
	return edges
}

type bindingScope struct {
	namespace string
	via       string
}

// rewriteBindingScopes returns the scopes in which subject can acquire a
// collected, rewritable role. A new or edited binding does not require bind:
// the role can first be cleared, the empty role bound (no escalation), then
// its rules rewritten. An existing binding's roleRef is never changed.
func (idx *Index) rewriteBindingScopes(subject Subject, rules []ScopedRule, target RoleTarget) []bindingScope {
	scopes := map[string]string{}
	record := func(namespace, via string) {
		if previous, ok := scopes[namespace]; !ok || via < previous {
			scopes[namespace] = via
		}
	}
	if target.Kind == "ClusterRole" {
		for _, binding := range idx.clusterRoleBindingsByRole[target.Name] {
			if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != target.Name {
				continue
			}
			if bindingNamesSubject(binding.Subjects, "", subject) {
				record("", "existing ClusterRoleBinding "+binding.Name)
			} else if canEditBinding(rules, "clusterrolebindings", "", binding.Name) {
				record("", "an editable ClusterRoleBinding "+binding.Name)
			}
		}
		if idx.hasClusterWideCreate(rules, "clusterrolebindings") {
			record("", "a new ClusterRoleBinding after clearing the role")
		}
	}
	for _, binding := range idx.roleBindingsByRole[target] {
		if binding.RoleRef.Kind != target.Kind || binding.RoleRef.Name != target.Name ||
			(target.Kind == "Role" && binding.Namespace != target.Namespace) {
			continue
		}
		if bindingNamesSubject(binding.Subjects, binding.Namespace, subject) {
			record(binding.Namespace, "existing RoleBinding "+binding.Namespace+"/"+binding.Name)
		} else if canEditBinding(rules, "rolebindings", binding.Namespace, binding.Name) {
			record(binding.Namespace, "an editable RoleBinding "+binding.Namespace+"/"+binding.Name)
		}
	}
	namespaces := idx.knownNamespaces()
	if subject.Namespace != "" && !slices.Contains(namespaces, subject.Namespace) {
		namespaces = append(namespaces, subject.Namespace)
	}
	for _, sr := range rules {
		if sr.Namespace != "" && !slices.Contains(namespaces, sr.Namespace) {
			namespaces = append(namespaces, sr.Namespace)
		}
	}
	for _, namespace := range namespaces {
		if target.Kind == "Role" && namespace != target.Namespace {
			continue
		}
		if idx.canCreateRoleBindingsIn(rules, namespace) {
			record(namespace, "a new RoleBinding in "+namespace+" after clearing the role")
		}
	}
	// Cluster-wide acquisition subsumes the namespaced grants for this target.
	if via, ok := scopes[""]; ok {
		return []bindingScope{{via: via}}
	}
	var out []bindingScope
	for _, namespace := range slices.Sorted(maps.Keys(scopes)) {
		out = append(out, bindingScope{namespace: namespace, via: scopes[namespace]})
	}
	return out
}

func canEditBinding(rules []ScopedRule, resource, namespace, name string) bool {
	for _, sr := range rules {
		if sr.Namespace != "" && sr.Namespace != namespace {
			continue
		}
		if len(sr.Rule.ResourceNames) != 0 && !resourceNameMatches(sr.Rule.ResourceNames, name) {
			continue
		}
		if ruleGrants(sr.Rule, rbacv1.GroupName, resource, "update") || ruleGrants(sr.Rule, rbacv1.GroupName, resource, "patch") {
			return true
		}
	}
	return false
}
