package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestUnrestrictedImpersonationDoesNotInventPermissions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resource  string
		namespace string
	}{
		{name: "cluster-wide service accounts", resource: "serviceaccounts"},
		{name: "namespaced service accounts", resource: "serviceaccounts", namespace: "prod"},
		{name: "cluster-wide users", resource: "users"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := rule([]string{""}, []string{tc.resource}, []string{"impersonate"}, nil)
			reader := rule([]string{""}, []string{"pods"}, []string{"get"}, nil)
			var roles []rbacv1.Role
			var clusterRoles []rbacv1.ClusterRole
			var bindings []rbacv1.RoleBinding
			var clusterBindings []rbacv1.ClusterRoleBinding
			if tc.namespace != "" {
				roles = []rbacv1.Role{role("prod", "impersonator", grant), role("prod", "reader", reader)}
				bindings = []rbacv1.RoleBinding{
					roleBinding("prod", "impersonate", "Role", "impersonator", saSubject("prod", "caller")),
					roleBinding("prod", "read", "Role", "reader", saSubject("prod", "target")),
				}
			} else {
				clusterRoles = []rbacv1.ClusterRole{clusterRole("impersonator", grant), clusterRole("reader", reader)}
				clusterBindings = []rbacv1.ClusterRoleBinding{
					clusterRoleBinding("impersonate", "impersonator", saSubject("prod", "caller")),
					clusterRoleBinding("read", "reader", saSubject("prod", "target")),
				}
			}
			idx := NewIndex(roles, clusterRoles, bindings, clusterBindings, []corev1.ServiceAccount{saObj("prod", "caller"), saObj("prod", "target")})
			result := idx.AnalyzeEscalation(sa("prod", "caller"))
			require.False(t, result.ClusterAdmin, "the ability to choose an identity does not create rules that identity does not hold")
			require.NotEmpty(t, result.Unbounded, "uncollected possible targets must remain visible as risk findings")
			require.False(t, result.Truncated)
			for _, effective := range result.EffectiveRules {
				require.False(t, ruleGrants(effective.Rule, "*", "*", "*"), "impersonation must never materialize a wildcard permission")
			}
		})
	}
}

func TestUnrestrictedServiceAccountImpersonationWithNoInventory(t *testing.T) {
	cr := clusterRole("impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("binding", "impersonator", saSubject("prod", "caller")),
	}, nil)
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.False(t, result.ClusterAdmin)
	require.Empty(t, result.Reached)
	require.Len(t, result.Unbounded, 1)
	require.Len(t, result.EffectiveRules, 1)
}

func TestUnrestrictedUsersTraverseCollectedBindings(t *testing.T) {
	for _, clusterWide := range []bool{false, true} {
		t.Run(map[bool]string{false: "namespaced rules", true: "cluster administrator"}[clusterWide], func(t *testing.T) {
			impersonate := clusterRole("impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
			power := clusterRole("target-power", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
			user := rbacv1.Subject{Kind: "User", Name: "alice"}
			clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller"))}
			var bindings []rbacv1.RoleBinding
			if clusterWide {
				clusterBindings = append(clusterBindings, clusterRoleBinding("admin", "target-power", user))
			} else {
				bindings = []rbacv1.RoleBinding{roleBinding("prod", "admin", "ClusterRole", "target-power", user)}
			}
			idx := NewIndex(nil, []rbacv1.ClusterRole{impersonate, power}, bindings, clusterBindings, nil)
			result := idx.AnalyzeEscalation(sa("prod", "caller"))
			require.Equal(t, clusterWide, result.ClusterAdmin)
			require.Len(t, result.Reached, 1)
			path := result.Reached[0].Edges
			require.Equal(t, &Subject{Kind: KindUser, Name: "alice"}, path[len(path)-1].ToSubject)
			require.NotEmpty(t, result.Unbounded)
			if !clusterWide {
				for _, r := range result.EffectiveRules {
					if ruleGrants(r.Rule, "*", "*", "*") {
						require.Equal(t, "prod", r.Namespace)
					}
				}
			}
		})
	}
}

func TestUnrestrictedUsersFollowMultiHopEscalation(t *testing.T) {
	impersonator := clusterRole("impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
	binder := clusterRole("binder",
		rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"admin"}),
		rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{impersonator, binder, admin}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")),
		clusterRoleBinding("alice-binder", "binder", rbacv1.Subject{Kind: "User", Name: "alice"}),
	}, nil)
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.True(t, result.ClusterAdmin)
	require.NotEmpty(t, result.Reached, "the result must follow the actual user before claiming its reachable permissions")
	foundAdminGrant := false
	for _, effective := range result.EffectiveRules {
		foundAdminGrant = foundAdminGrant || IsClusterAdminEquivalent([]ScopedRule{effective})
	}
	require.True(t, foundAdminGrant)
}

func TestUnrestrictedUsersCannotImpersonateServiceAccountUsernames(t *testing.T) {
	impersonator := clusterRole("impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{impersonator, admin}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")),
		clusterRoleBinding("sa-admin", "admin", rbacv1.Subject{Kind: "User", Name: "system:serviceaccount:prod:privileged"}),
	}, []corev1.ServiceAccount{saObj("prod", "privileged")})
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.False(t, result.ClusterAdmin)
	require.Empty(t, result.Reached, "Kubernetes authorizes these usernames against serviceaccounts, not users")
	require.NotEmpty(t, result.Unbounded)
}

func TestUnrestrictedServiceAccountsStillReachRealAdministrator(t *testing.T) {
	for _, namespace := range []string{"", "prod"} {
		grant := rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil)
		var roles []rbacv1.Role
		var bindings []rbacv1.RoleBinding
		admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
		clusterRoles := []rbacv1.ClusterRole{admin}
		clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("victim", "admin", saSubject("prod", "privileged"))}
		if namespace == "" {
			clusterRoles = append(clusterRoles, clusterRole("impersonator", grant))
			clusterBindings = append(clusterBindings, clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")))
		} else {
			roles = []rbacv1.Role{role("prod", "impersonator", grant)}
			bindings = []rbacv1.RoleBinding{roleBinding("prod", "grant", "Role", "impersonator", saSubject("prod", "caller"))}
		}
		idx := NewIndex(roles, clusterRoles, bindings, clusterBindings, []corev1.ServiceAccount{saObj("prod", "privileged")})
		result := idx.AnalyzeEscalation(sa("prod", "caller"))
		require.True(t, result.ClusterAdmin)
		require.NotEmpty(t, result.Reached, "administrator access must come from a concrete target")
	}
}

func TestUnrestrictedUsersAreEnumeratedOnceInStableOrder(t *testing.T) {
	impersonator := clusterRole("impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
	reader := clusterRole("reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	bindings := []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")),
		clusterRoleBinding("z-user", "reader", rbacv1.Subject{Kind: "User", Name: "zoe"}),
		clusterRoleBinding("a-user", "reader", rbacv1.Subject{Kind: "User", Name: "alice"}),
		clusterRoleBinding("duplicate-user", "reader", rbacv1.Subject{Kind: "User", Name: "alice"}),
		clusterRoleBinding("group-not-user", "reader", rbacv1.Subject{Kind: "Group", Name: "developers"}),
	}
	for _, reverse := range []bool{false, true} {
		ordered := append([]rbacv1.ClusterRoleBinding(nil), bindings...)
		if reverse {
			for i, j := 0, len(ordered)-1; i < j; i, j = i+1, j-1 {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
		idx := NewIndex(nil, []rbacv1.ClusterRole{impersonator, reader}, nil, ordered, nil)
		result := idx.AnalyzeEscalation(sa("prod", "caller"))
		require.False(t, result.ClusterAdmin)
		var reached []string
		for _, path := range result.Reached {
			reached = append(reached, path.Edges[len(path.Edges)-1].ToSubject.Name)
		}
		require.Equal(t, []string{"alice", "zoe"}, reached)
	}
}

func TestNamespacedImpersonationDoesNotReachOtherNamespace(t *testing.T) {
	impersonator := role("prod", "impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex([]rbacv1.Role{impersonator}, []rbacv1.ClusterRole{admin}, []rbacv1.RoleBinding{
		roleBinding("prod", "grant", "Role", "impersonator", saSubject("prod", "caller")),
	}, []rbacv1.ClusterRoleBinding{clusterRoleBinding("victim", "admin", saSubject("other", "privileged"))}, []corev1.ServiceAccount{
		saObj("prod", "reader"), saObj("other", "privileged"),
	})
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.False(t, result.ClusterAdmin)
	for _, path := range result.Reached {
		require.Equal(t, "prod", path.Edges[len(path.Edges)-1].ToSubject.Namespace)
	}
	for _, effective := range result.EffectiveRules {
		require.False(t, ruleGrants(effective.Rule, "*", "*", "*"))
	}
	require.Len(t, result.Unbounded, 1)
	require.Equal(t, "prod", result.Unbounded[0].Edge.Scope)
}

func TestUnboundedImpersonationCarriesTargetKind(t *testing.T) {
	for _, tc := range []struct {
		resource string
		kind     SubjectKind
	}{
		{resource: "users", kind: KindUser},
		{resource: "groups", kind: KindGroup},
		{resource: "serviceaccounts", kind: KindServiceAccount},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			idx := NewIndex(nil, nil, nil, nil, nil)
			edges := idx.DirectEscalationEdges(sa("prod", "caller"), []ScopedRule{{
				Rule: rule([]string{""}, []string{tc.resource}, []string{"impersonate"}, nil),
			}})
			require.Len(t, edges, 1)
			require.True(t, edges[0].Unbounded)
			require.Equal(t, tc.kind, edges[0].ImpersonatedKind)
			require.Empty(t, edges[0].GrantedRules)
		})
	}
}

func TestImpersonationWarningDoesNotSuppressActualEscalateGrant(t *testing.T) {
	grant := clusterRole("combined", rule(
		[]string{"", "rbac.authorization.k8s.io"},
		[]string{"serviceaccounts", "clusterroles"},
		[]string{"impersonate", "escalate", "update"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{grant}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("grant", "combined", saSubject("prod", "caller")),
	}, nil)
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.True(t, result.ClusterAdmin, "the real escalate+update capability still proves administrative power")
	foundEscalate := false
	for _, finding := range result.Unbounded {
		foundEscalate = foundEscalate || finding.Edge.Primitive == PrimitiveEscalateVerb
	}
	require.True(t, foundEscalate, "administrator access must be attributed to the permission grant, not the unrelated identity warning")
}
