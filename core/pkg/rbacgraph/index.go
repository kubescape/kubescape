package rbacgraph

import (
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

// Index indexes a cluster's Role, ClusterRole, RoleBinding,
// ClusterRoleBinding, and ServiceAccount objects for repeated escalation
// queries against the same snapshot.
type Index struct {
	roles               map[string]*rbacv1.Role // key: namespace/name
	clusterRoles        map[string]*rbacv1.ClusterRole
	roleBindings        []*rbacv1.RoleBinding
	clusterRoleBindings []*rbacv1.ClusterRoleBinding
	// serviceAccountsByNS lists every ServiceAccount name collected per
	// namespace, needed to enumerate targets for assign-serviceaccount and
	// mint-serviceaccount-token edges when the granting rule has no
	// resourceNames restriction.
	serviceAccountsByNS map[string][]string
}

// NewIndex builds an Index from a cluster's (or a query's) collected
// objects. A nil/empty slice for any parameter is treated as "none
// collected," not an error.
func NewIndex(roles []rbacv1.Role, clusterRoles []rbacv1.ClusterRole, roleBindings []rbacv1.RoleBinding, clusterRoleBindings []rbacv1.ClusterRoleBinding, serviceAccounts []corev1.ServiceAccount) *Index {
	idx := &Index{
		roles:               make(map[string]*rbacv1.Role, len(roles)),
		clusterRoles:        make(map[string]*rbacv1.ClusterRole, len(clusterRoles)),
		serviceAccountsByNS: make(map[string][]string),
	}
	for i := range roles {
		r := &roles[i]
		idx.roles[roleKey(r.Namespace, r.Name)] = r
	}
	for i := range clusterRoles {
		cr := &clusterRoles[i]
		idx.clusterRoles[cr.Name] = cr
	}
	for i := range roleBindings {
		idx.roleBindings = append(idx.roleBindings, &roleBindings[i])
	}
	for i := range clusterRoleBindings {
		idx.clusterRoleBindings = append(idx.clusterRoleBindings, &clusterRoleBindings[i])
	}
	for _, sa := range serviceAccounts {
		idx.serviceAccountsByNS[sa.Namespace] = append(idx.serviceAccountsByNS[sa.Namespace], sa.Name)
	}
	// Sorted so the Index is canonical whatever order its inputs arrived in:
	// these names are enumerated straight into escalation edges, and an
	// escalation report should not depend on collection order.
	for ns := range idx.serviceAccountsByNS {
		sort.Strings(idx.serviceAccountsByNS[ns])
	}
	return idx
}

func roleKey(namespace, name string) string {
	return namespace + "/" + name
}

// DirectRules returns every ScopedRule granted to subject by a
// RoleBinding or ClusterRoleBinding that names it as a subject -- the
// rules subject holds without needing any escalation technique.
func (idx *Index) DirectRules(subject Subject) []ScopedRule {
	var out []ScopedRule
	for _, crb := range idx.clusterRoleBindings {
		if !bindingNamesSubject(crb.Subjects, "", subject) {
			continue
		}
		if cr, ok := idx.clusterRoles[crb.RoleRef.Name]; ok {
			for _, rule := range cr.Rules {
				out = append(out, ScopedRule{Rule: rule, Namespace: ""})
			}
		}
	}
	for _, rb := range idx.roleBindings {
		if !bindingNamesSubject(rb.Subjects, rb.Namespace, subject) {
			continue
		}
		switch rb.RoleRef.Kind {
		case "Role":
			if r, ok := idx.roles[roleKey(rb.Namespace, rb.RoleRef.Name)]; ok {
				for _, rule := range r.Rules {
					out = append(out, ScopedRule{Rule: rule, Namespace: rb.Namespace})
				}
			}
		case "ClusterRole":
			if cr, ok := idx.clusterRoles[rb.RoleRef.Name]; ok {
				for _, rule := range cr.Rules {
					out = append(out, ScopedRule{Rule: rule, Namespace: rb.Namespace})
				}
			}
		}
	}
	return out
}

// bindingNamesSubject reports whether any of subjects actually authorizes
// subject -- either by naming it directly, or via one of Kubernetes'
// implicit groups every identity of that kind automatically belongs to:
// every ServiceAccount is a member of system:serviceaccounts,
// system:serviceaccounts:<its namespace>, and system:authenticated; every
// User is a member of system:authenticated. A RoleBinding/ClusterRoleBinding
// naming one of these groups as its subject grants its rules to every
// matching identity, not just to a literally-named Group object (there
// usually isn't one -- these are authenticator-assigned, not RBAC objects).
// Missing this is a real, well-known misconfiguration source: binding a
// privileged ClusterRole to system:serviceaccounts grants it to every
// ServiceAccount in the cluster.
//
// bindingNamespace is the namespace of the RoleBinding the subjects belong
// to, or "" for a ClusterRoleBinding. A ServiceAccount subject may leave its
// namespace out, and the API server then resolves it in the RoleBinding's
// namespace; a ClusterRoleBinding has none to resolve it in, so there such a
// subject matches nobody. The authorizer matches User and ServiceAccount
// subjects on the username alone, and a ServiceAccount's username is
// system:serviceaccount:<namespace>:<name>: a User subject carrying that name
// applies to the ServiceAccount, and a ServiceAccount subject applies to a
// User asked about under that name. All of this follows appliesToUser in
// Kubernetes' pkg/registry/rbac/validation.
func bindingNamesSubject(subjects []rbacv1.Subject, bindingNamespace string, subject Subject) bool {
	for _, s := range subjects {
		switch subject.Kind {
		case KindServiceAccount:
			if s.Kind == "ServiceAccount" && s.Name == subject.Name {
				saNamespace := s.Namespace
				if saNamespace == "" {
					saNamespace = bindingNamespace
				}
				if saNamespace != "" && saNamespace == subject.Namespace {
					return true
				}
			}
			// A ServiceAccount authenticates as the user
			// system:serviceaccount:<namespace>:<name>, and the authorizer
			// compares a User subject with the authenticated username, so a
			// User subject carrying that name is this ServiceAccount.
			if s.Kind == "User" && serviceaccount.MatchesUsername(subject.Namespace, subject.Name, s.Name) {
				return true
			}
			if s.Kind == "Group" && (s.Name == "system:serviceaccounts" ||
				s.Name == "system:serviceaccounts:"+subject.Namespace ||
				s.Name == "system:authenticated") {
				return true
			}
		case KindUser:
			if s.Kind == "User" && s.Name == subject.Name {
				return true
			}
			// The same rule read the other way: a ServiceAccount subject
			// applies to whoever carries that ServiceAccount's username, so it
			// applies to a User asked about under it. Only the username is
			// shared. The ServiceAccount groups are assigned by the
			// authenticator and are not implied by the name, so the Group
			// subjects that the ServiceAccount case above honors do not apply
			// to a User.
			if s.Kind == "ServiceAccount" {
				saNamespace := s.Namespace
				if saNamespace == "" {
					saNamespace = bindingNamespace
				}
				if saNamespace != "" && serviceaccount.MatchesUsername(saNamespace, s.Name, subject.Name) {
					return true
				}
			}
			if s.Kind == "Group" && s.Name == "system:authenticated" {
				return true
			}
		case KindGroup:
			if s.Kind == "Group" && s.Name == subject.Name {
				return true
			}
		}
	}
	return false
}

// IsClusterAdminEquivalent reports whether rules includes a cluster-wide
// (Namespace == "") rule granting every verb on every resource in every
// API group -- the literal definition of the built-in cluster-admin
// ClusterRole's power, however it was actually reached.
func IsClusterAdminEquivalent(rules []ScopedRule) bool {
	for _, sr := range rules {
		if sr.Namespace != "" {
			continue
		}
		if ruleGrants(sr.Rule, "*", "*", "*") {
			return true
		}
	}
	return false
}
