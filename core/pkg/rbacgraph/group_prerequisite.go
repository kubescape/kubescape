package rbacgraph

import "k8s.io/apiserver/pkg/authentication/serviceaccount"

// canImpersonateUsername checks the independent prerequisite for a group
// impersonation request. Kubernetes rejects group headers without a username,
// and authorizes that username against users or serviceaccounts before groups.
// A collected object or binding is not needed: impersonation checks the name.
func canImpersonateUsername(rules []ScopedRule) bool {
	for _, sr := range rules {
		if !containsOrWildcard(sr.Rule.Verbs, "impersonate") || !containsOrWildcard(sr.Rule.APIGroups, "") {
			continue
		}
		names, restricted := namedResources(sr.Rule)
		if sr.Namespace == "" && containsOrWildcard(sr.Rule.Resources, "users") {
			if !restricted {
				return true
			}
			for _, name := range names {
				// An SA-form username is checked against serviceaccounts, not users.
				if name != "" {
					if _, _, err := serviceaccount.SplitUsername(name); err != nil {
						return true
					}
				}
			}
		}
		if containsOrWildcard(sr.Rule.Resources, "serviceaccounts") {
			namespace := sr.Namespace
			if namespace == "" {
				namespace = "default"
			}
			if !restricted {
				names = []string{"impersonation-target"}
			}
			for _, name := range names {
				if _, _, err := serviceaccount.SplitUsername(serviceaccount.MakeUsername(namespace, name)); err == nil {
					return true
				}
			}
		}
	}
	return false
}
