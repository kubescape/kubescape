package rbacgraph

import (
	"cmp"
	"maps"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

// serviceAccountImpersonationTargets includes identities evidenced by bindings
// even when their ServiceAccount objects are absent. Impersonation authorizes
// the username without looking up the object; pod and token operations still
// use only the collected object inventory.
func (idx *Index) serviceAccountImpersonationTargets(scope string) []Subject {
	seen := map[Subject]bool{}
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
	targets := slices.Collect(maps.Keys(seen))
	slices.SortFunc(targets, func(a, b Subject) int {
		if order := cmp.Compare(a.Namespace, b.Namespace); order != 0 {
			return order
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return targets
}
