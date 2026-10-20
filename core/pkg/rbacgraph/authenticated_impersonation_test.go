package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

func TestAnonymousImpersonationReachesAuthenticatedGroupPermissions(t *testing.T) {
	for _, tc := range []struct {
		name                                                          string
		names                                                         []string
		noImpersonation, namespacedGrant, namespacedPower, readerOnly bool
		wantReached, wantAdmin                                        bool
	}{
		{name: "unrestricted", wantReached: true, wantAdmin: true},
		{name: "without impersonation", noImpersonation: true},
		{name: "anonymous-only restriction", names: []string{"system:anonymous"}},
		{name: "named ordinary user", names: []string{"bob"}, wantReached: true, wantAdmin: true},
		{name: "literal star username", names: []string{"*"}, wantReached: true, wantAdmin: true},
		{name: "service account username excluded", names: []string{"system:serviceaccount:prod:reader"}},
		{name: "namespace grant cannot impersonate users", namespacedGrant: true},
		{name: "namespaced group permissions", namespacedPower: true, wantReached: true},
		{name: "read-only group permissions", readerOnly: true, wantReached: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := Subject{Kind: KindUser, Name: "system:anonymous"}
			grant := rule([]string{""}, []string{"users"}, []string{"impersonate"}, tc.names)
			powerRule := rule([]string{"*"}, []string{"*"}, []string{"*"}, nil)
			if tc.readerOnly {
				powerRule = rule([]string{""}, []string{"pods"}, []string{"get"}, nil)
			}
			clusterRoles := []rbacv1.ClusterRole{clusterRole("power", powerRule)}
			var roles []rbacv1.Role
			var bindings []rbacv1.RoleBinding
			var clusterBindings []rbacv1.ClusterRoleBinding
			if !tc.noImpersonation {
				subject := rbacv1.Subject{Kind: "User", Name: caller.Name}
				if tc.namespacedGrant {
					roles = append(roles, role("prod", "grant", grant))
					bindings = append(bindings, roleBinding("prod", "grant", "Role", "grant", subject))
				} else {
					clusterRoles = append(clusterRoles, clusterRole("grant", grant))
					clusterBindings = append(clusterBindings, clusterRoleBinding("grant", "grant", subject))
				}
			}
			group := rbacv1.Subject{Kind: "Group", Name: "system:authenticated"}
			if tc.namespacedPower {
				bindings = append(bindings, roleBinding("prod", "power", "ClusterRole", "power", group))
			} else {
				clusterBindings = append(clusterBindings, clusterRoleBinding("power", "power", group))
			}
			idx := NewIndex(roles, clusterRoles, bindings, clusterBindings, nil)
			require.False(t, IsClusterAdminEquivalent(idx.DirectRules(caller)), "anonymous must not directly inherit authenticated rules")
			result := idx.AnalyzeEscalation(caller)
			require.Equal(t, tc.wantAdmin, result.ClusterAdmin)
			require.Equal(t, tc.wantReached, len(result.Reached) > 0)
			if tc.wantReached {
				target := result.Reached[0].Edges[0].ToSubject
				require.Equal(t, KindUser, target.Kind)
				require.NotEqual(t, caller.Name, target.Name)
				_, _, err := serviceaccount.SplitUsername(target.Name)
				require.Error(t, err)
				if len(tc.names) > 0 {
					require.Contains(t, tc.names, target.Name)
				}
				found := false
				for _, r := range result.EffectiveRules {
					if ruleGrants(r.Rule, powerRule.APIGroups[0], powerRule.Resources[0], powerRule.Verbs[0]) {
						found = true
						if tc.namespacedPower {
							require.Equal(t, "prod", r.Namespace)
						}
					}
				}
				require.True(t, found)
			}
			if !tc.noImpersonation && !tc.namespacedGrant && len(tc.names) == 0 {
				require.NotEmpty(t, result.Unbounded)
			}
		})
	}
}
