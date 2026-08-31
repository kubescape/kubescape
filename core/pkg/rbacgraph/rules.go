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
