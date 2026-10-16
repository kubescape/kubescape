package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestImpersonationReachesDeletedBoundServiceAccount(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		saSubject("prod", "deleted-admin"),
		{Kind: "User", Name: "system:serviceaccount:prod:deleted-admin"},
	} {
		for _, restricted := range []bool{false, true} {
			t.Run(subject.Kind+map[bool]string{false: "/unrestricted", true: "/named"}[restricted], func(t *testing.T) {
				var names []string
				if restricted {
					names = []string{"deleted-admin"}
				}
				impersonator := clusterRole("impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, names))
				admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
				idx := NewIndex(nil, []rbacv1.ClusterRole{impersonator, admin}, nil, []rbacv1.ClusterRoleBinding{
					clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")),
					clusterRoleBinding("dangling-admin", "admin", subject),
				}, nil)
				result := idx.AnalyzeEscalation(sa("prod", "caller"))
				require.True(t, result.ClusterAdmin)
				require.NotEmpty(t, result.Reached)
				require.Equal(t, &Subject{Kind: KindServiceAccount, Namespace: "prod", Name: "deleted-admin"}, result.Reached[0].Edges[0].ToSubject)
				if !restricted {
					require.NotEmpty(t, result.Unbounded)
				}
				require.Empty(t, idx.serviceAccountsByNS, "binding identities must not become live objects")
			})
		}
	}
}

func TestServiceAccountImpersonationTargetsResolveBindings(t *testing.T) {
	idx := NewIndex(nil, nil, []rbacv1.RoleBinding{
		roleBinding("prod", "local", "Role", "reader", saSubject("", "local")),
		roleBinding("prod", "cross", "Role", "reader", saSubject("other", "remote")),
		roleBinding("prod", "user", "Role", "reader", rbacv1.Subject{Kind: "User", Name: "system:serviceaccount:other:from-user"}),
	}, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("duplicate", "reader", saSubject("prod", "local")),
		clusterRoleBinding("missing-namespace", "reader", saSubject("", "invalid")),
		clusterRoleBinding("empty-name", "reader", saSubject("prod", "")),
		clusterRoleBinding("not-sa", "reader", rbacv1.Subject{Kind: "Group", Name: "system:serviceaccount:prod:group"}, rbacv1.Subject{Kind: "User", Name: "alice"}),
	}, []corev1.ServiceAccount{saObj("prod", "local"), saObj("prod", "collected")})
	want := []Subject{
		{Kind: KindServiceAccount, Namespace: "other", Name: "from-user"},
		{Kind: KindServiceAccount, Namespace: "other", Name: "remote"},
		{Kind: KindServiceAccount, Namespace: "prod", Name: "collected"},
		{Kind: KindServiceAccount, Namespace: "prod", Name: "local"},
	}
	for _, tc := range []struct {
		scope string
		names []string
		want  []Subject
	}{
		{want: want},
		{scope: "prod", want: want[2:]},
		{scope: "prod", names: []string{"local"}, want: want[3:]},
		{scope: "prod", names: []string{"*"}},
		{scope: "absent"},
	} {
		edges := idx.impersonateEdges([]ScopedRule{{Namespace: tc.scope, Rule: rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, tc.names)}})
		var targets []Subject
		for _, edge := range edges {
			if edge.ToSubject != nil {
				targets = append(targets, *edge.ToSubject)
			}
		}
		require.Equal(t, tc.want, targets)
	}
}

func TestDeletedServiceAccountDoesNotBecomePodOrTokenTarget(t *testing.T) {
	idx := NewIndex(nil, nil, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("dangling", "admin", saSubject("prod", "deleted"))}, nil)
	rules := []ScopedRule{
		{Namespace: "prod", Rule: rule([]string{""}, []string{"pods"}, []string{"create"}, nil)},
		{Namespace: "prod", Rule: rule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, nil)},
	}
	require.Empty(t, idx.assignServiceAccountEdges(rules))
	require.Empty(t, idx.mintServiceAccountTokenEdges(rules))
}

func TestImpersonationRecoversRulesFromNamespacedDanglingBinding(t *testing.T) {
	for _, subject := range []rbacv1.Subject{
		saSubject("", "deleted-reader"),
		{Kind: "User", Name: "system:serviceaccount:prod:deleted-reader"},
	} {
		t.Run(subject.Kind, func(t *testing.T) {
			impersonator := role("prod", "impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
			reader := role("prod", "reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
			idx := NewIndex([]rbacv1.Role{impersonator, reader}, nil, []rbacv1.RoleBinding{
				roleBinding("prod", "grant", "Role", "impersonator", saSubject("prod", "caller")),
				roleBinding("prod", "dangling-reader", "Role", "reader", subject),
			}, nil, nil)
			result := idx.AnalyzeEscalation(sa("prod", "caller"))
			require.False(t, result.ClusterAdmin)
			require.Len(t, result.Reached, 1)
			found := false
			for _, effective := range result.EffectiveRules {
				if ruleGrants(effective.Rule, "", "secrets", "get") {
					require.Equal(t, "prod", effective.Namespace)
					found = true
				}
			}
			require.True(t, found, "the bound identity still holds its namespaced rules")
		})
	}
}
