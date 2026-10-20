package rbacgraph

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

// serviceAccountImpersonationTargets includes identities evidenced by bindings
// even when their ServiceAccount objects are absent. Impersonation authorizes
// the username without looking up the object; pod and token operations still
// use only the collected object inventory.
func (idx *Index) serviceAccountImpersonationTargets(scope string, names []string) []Subject {
	seen := map[Subject]bool{}
	// A group binding proves permissions for any valid SA username in its
	// namespace, whether or not an individual object or subject was collected.
	groupNamespaces := map[string]bool{}
	addGroupNamespace := func(namespace string) {
		if namespace == "" {
			namespace = scope
		}
		// A global group applies in any namespace. Impersonation does not
		// require that namespace (or the ServiceAccount) to exist.
		if namespace == "" {
			namespace = "default"
		}
		groupNamespaces[namespace] = true
	}
	add := func(namespace, name string) {
		if namespace != "" && name != "" && (scope == "" || namespace == scope) {
			seen[Subject{Kind: KindServiceAccount, Namespace: namespace, Name: name}] = true
		}
	}
	for namespace, names := range idx.serviceAccountsByNS {
		for _, name := range names {
			add(namespace, name)
		}
	}
	addBindings := func(subjects []rbacv1.Subject, bindingNamespace string) {
		for _, subject := range subjects {
			switch subject.Kind {
			case "Group":
				switch {
				case subject.Name == serviceaccount.AllServiceAccountsGroup || subject.Name == "system:authenticated":
					addGroupNamespace("")
				case strings.HasPrefix(subject.Name, serviceaccount.ServiceAccountGroupPrefix):
					namespace := strings.TrimPrefix(subject.Name, serviceaccount.ServiceAccountGroupPrefix)
					if namespace != "" {
						addGroupNamespace(namespace)
					}
				}
			case "ServiceAccount":
				namespace := subject.Namespace
				if namespace == "" {
					namespace = bindingNamespace
				}
				add(namespace, subject.Name)
			case "User":
				namespace, name, err := serviceaccount.SplitUsername(subject.Name)
				if err == nil {
					add(namespace, name)
				}
			}
		}
	}
	for _, binding := range idx.roleBindings {
		addBindings(binding.Subjects, binding.Namespace)
	}
	for _, binding := range idx.clusterRoleBindings {
		addBindings(binding.Subjects, "")
	}
	// One representative per group namespace is sufficient for unrestricted
	// names. Restricted grants must use their exact permitted names instead.
	representativeNames := names
	if len(representativeNames) == 0 {
		representativeNames = []string{"impersonation-target"}
	}
	for namespace := range groupNamespaces {
		for _, name := range representativeNames {
			if _, _, err := serviceaccount.SplitUsername(serviceaccount.MakeUsername(namespace, name)); err == nil {
				add(namespace, name)
			}
		}
	}
	targets := slices.Collect(maps.Keys(seen))
	slices.SortFunc(targets, func(a, b Subject) int {
		if order := cmp.Compare(a.Namespace, b.Namespace); order != 0 {
			return order
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return targets
}
