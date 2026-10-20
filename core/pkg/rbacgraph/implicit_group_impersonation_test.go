package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestServiceAccountImpersonationReachesGroupOnlyPermissions(t *testing.T) {
	for _, tc := range []struct {
		name, group, scope string
		names              []string
		namespacedBinding  bool
		want               bool
	}{
		{name: "namespace group", group: "system:serviceaccounts:prod", want: true},
		{name: "global group", group: "system:serviceaccounts", want: true},
		{name: "authenticated group", group: "system:authenticated", want: true},
		{name: "scoped grant", group: "system:serviceaccounts:prod", scope: "prod", want: true},
		{name: "different namespace", group: "system:serviceaccounts:other", scope: "prod"},
		{name: "named target", group: "system:serviceaccounts:prod", names: []string{"missing-reader"}, want: true},
		{name: "named scoped target", group: "system:serviceaccounts", scope: "prod", names: []string{"missing-reader"}, want: true},
		{name: "literal star", group: "system:serviceaccounts", names: []string{"*"}},
		{name: "empty name", group: "system:serviceaccounts", names: []string{""}},
		{name: "malformed namespace", group: "system:serviceaccounts:bad:namespace"},
		{name: "unrelated group", group: "developers"},
		{name: "namespaced permissions", group: "system:serviceaccounts:prod", namespacedBinding: true, want: true},
		{name: "global group in RoleBinding", group: "system:serviceaccounts", namespacedBinding: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := Subject{Kind: KindUser, Name: "alice"}
			grant := rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, tc.names)
			power := clusterRole("power", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
			var roles []rbacv1.Role
			var bindings []rbacv1.RoleBinding
			clusterRoles := []rbacv1.ClusterRole{power}
			var clusterBindings []rbacv1.ClusterRoleBinding
			user := rbacv1.Subject{Kind: "User", Name: "alice"}
			if tc.scope == "" {
				clusterRoles = append(clusterRoles, clusterRole("impersonator", grant))
				clusterBindings = append(clusterBindings, clusterRoleBinding("grant", "impersonator", user))
			} else {
				roles = append(roles, role(tc.scope, "impersonator", grant))
				bindings = append(bindings, roleBinding(tc.scope, "grant", "Role", "impersonator", user))
			}
			group := rbacv1.Subject{Kind: "Group", Name: tc.group}
			if tc.namespacedBinding {
				bindings = append(bindings, roleBinding("prod", "power", "ClusterRole", "power", group))
			} else {
				clusterBindings = append(clusterBindings, clusterRoleBinding("power", "power", group))
			}
			idx := NewIndex(roles, clusterRoles, bindings, clusterBindings, nil)
			result := idx.AnalyzeEscalation(caller)
			require.Equal(t, tc.want && !tc.namespacedBinding, result.ClusterAdmin)
			if tc.want && tc.group != "system:authenticated" {
				require.NotEmpty(t, result.Reached)
				target := result.Reached[0].Edges[0].ToSubject
				require.Equal(t, KindServiceAccount, target.Kind)
				if tc.scope != "" {
					require.Equal(t, tc.scope, target.Namespace)
				}
				if len(tc.names) > 0 {
					require.Contains(t, tc.names, target.Name)
				}
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
			} else if !tc.want {
				require.Empty(t, result.Reached)
			}
			require.Empty(t, idx.serviceAccountsByNS)
			require.Empty(t, idx.assignServiceAccountEdges([]ScopedRule{{Namespace: "prod", Rule: rule([]string{""}, []string{"pods"}, []string{"create"}, nil)}}))
			require.Empty(t, idx.mintServiceAccountTokenEdges([]ScopedRule{{Namespace: "prod", Rule: rule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, nil)}}))
		})
	}
}
