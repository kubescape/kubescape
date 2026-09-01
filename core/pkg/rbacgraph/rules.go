package rbacgraph

import rbacv1 "k8s.io/api/rbac/v1"

// ruleGrants reports whether rule grants verb on the given apiGroup and
// resource (a "*" entry in any of rule's Verbs/APIGroups/Resources matches
// anything, per RBAC's own wildcard semantics).
func ruleGrants(rule rbacv1.PolicyRule, apiGroup, resource, verb string) bool {
	return containsOrWildcard(rule.APIGroups, apiGroup) &&
		containsOrWildcard(rule.Resources, resource) &&
		containsOrWildcard(rule.Verbs, verb)
}

func containsOrWildcard(list []string, want string) bool {
	for _, v := range list {
		if v == "*" || v == want {
			return true
		}
	}
	return false
}

// namedResources reports whether rule (already confirmed to grant the verb
// in question) restricts to specific object names, and if so, what they
// are. An empty rule.ResourceNames means no restriction -- the rule applies
// to every object of that resource type, not to none.
func namedResources(rule rbacv1.PolicyRule) (names []string, restricted bool) {
	if len(rule.ResourceNames) == 0 {
		return nil, false
	}
	return rule.ResourceNames, true
}

// ruleGrantsUnnamedCreate reports whether rule grants an unrestricted
// "create" on the given apiGroup/resource. A create request has no object
// name for the authorizer to match against -- the object doesn't exist
// yet -- so RBAC's own ResourceNameMatches always returns false for a
// create verb when a rule carries a non-empty resourceNames list: such a
// rule authorizes nothing for create, not "every object of that type."
// Only used for top-level collection creates (pods, rolebindings,
// clusterrolebindings); a subresource create on an already-named parent
// object (e.g. serviceaccounts/token) does have a real object name to
// match against and should use ruleGrants directly instead.
func ruleGrantsUnnamedCreate(rule rbacv1.PolicyRule, apiGroup, resource string) bool {
	return ruleGrants(rule, apiGroup, resource, "create") && len(rule.ResourceNames) == 0
}

func setToSlice(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func intersectSets(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if b[k] {
			out = append(out, k)
		}
	}
	return out
}
