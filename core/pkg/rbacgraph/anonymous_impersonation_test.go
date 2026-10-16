package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestUserImpersonationReachesAnonymousGroupPermissions(t *testing.T) {
	for _, tc := range []struct {
		name              string
		names             []string
		namespacedBinding bool
		want              bool
	}{
		{name: "unrestricted", want: true},
		{name: "explicit anonymous", names: []string{"system:anonymous"}, want: true},
		{name: "different user", names: []string{"bob"}},
		{name: "literal star", names: []string{"*"}},
		{name: "namespaced permissions", namespacedBinding: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := Subject{Kind: KindUser, Name: "alice"}
			grant := clusterRole("impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, tc.names))
			admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
			clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("grant", "impersonator", rbacv1.Subject{Kind: "User", Name: "alice"})}
			var bindings []rbacv1.RoleBinding
			group := rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}
			if tc.namespacedBinding {
				bindings = append(bindings, roleBinding("prod", "anonymous", "ClusterRole", "admin", group))
			} else {
				clusterBindings = append(clusterBindings, clusterRoleBinding("anonymous", "admin", group))
			}
			idx := NewIndex(nil, []rbacv1.ClusterRole{grant, admin}, bindings, clusterBindings, nil)
			result := idx.AnalyzeEscalation(caller)
			require.Equal(t, tc.want && !tc.namespacedBinding, result.ClusterAdmin)
			if tc.want {
				require.Len(t, result.Reached, 1)
				require.Equal(t, &Subject{Kind: KindUser, Name: "system:anonymous"}, result.Reached[0].Edges[0].ToSubject)
				if tc.namespacedBinding {
					found := false
					for _, r := range result.EffectiveRules {
						if ruleGrants(r.Rule, "*", "*", "*") {
							require.Equal(t, "prod", r.Namespace)
							found = true
						}
					}
					require.True(t, found)
				}
			} else {
				for _, path := range result.Reached {
					require.NotEqual(t, "system:anonymous", path.Edges[0].ToSubject.Name)
				}
				for _, r := range result.EffectiveRules {
					require.False(t, ruleGrants(r.Rule, "*", "*", "*"))
				}
			}
			if len(tc.names) == 0 {
				require.NotEmpty(t, result.Unbounded)
			}
		})
	}
}

func TestAnonymousUserDoesNotInheritAuthenticatedPermissions(t *testing.T) {
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	reader := clusterRole("reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{admin, reader}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("authenticated", "admin", rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}),
		clusterRoleBinding("unauthenticated", "reader", rbacv1.Subject{Kind: "Group", Name: "system:unauthenticated"}),
	}, nil)
	anonymous := Subject{Kind: KindUser, Name: "system:anonymous"}
	rules := idx.DirectRules(anonymous)
	require.Len(t, rules, 1)
	require.True(t, ruleGrants(rules[0].Rule, "", "pods", "get"))
	require.False(t, idx.AnalyzeEscalation(anonymous).ClusterAdmin)
	require.True(t, idx.AnalyzeEscalation(Subject{Kind: KindUser, Name: "alice"}).ClusterAdmin)
	require.False(t, bindingNamesSubject([]rbacv1.Subject{{Kind: "Group", Name: "system:unauthenticated"}}, "", Subject{Kind: KindUser, Name: "alice"}))
}
