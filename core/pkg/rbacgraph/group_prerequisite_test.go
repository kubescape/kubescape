package rbacgraph

import (
	"testing"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestGroupImpersonationRequiresUsernameAuthorization(t *testing.T) {
	for _, names := range [][]string{nil, {"system:masters"}, {"privileged"}} {
		grant := clusterRole("impersonator", rule([]string{""}, []string{"groups"}, []string{"impersonate"}, names))
		admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
		idx := NewIndex(nil, []rbacv1.ClusterRole{grant, admin}, nil, []rbacv1.ClusterRoleBinding{
			clusterRoleBinding("grant", "impersonator", saSubject("prod", "caller")),
			clusterRoleBinding("power", "admin", rbacv1.Subject{Kind: "Group", Name: "privileged"}),
		}, nil)
		result := idx.AnalyzeEscalation(sa("prod", "caller"))
		require.False(t, result.ClusterAdmin, "a group header alone cannot authorize an impersonation request")
		require.Empty(t, result.Reached)
	}
}

func TestGroupUsernamePrerequisiteRespectsAuthorizationAttributes(t *testing.T) {
	cases := []struct {
		name      string
		resource  string
		names     []string
		namespace string
		apiGroup  string
		verb      string
		want      bool
	}{
		{
			name:     "any user",
			resource: "users",
			want:     true,
		},
		{
			name:     "named user",
			resource: "users",
			names:    []string{"alice"},
			want:     true,
		},
		{
			name:     "anonymous",
			resource: "users",
			names:    []string{"system:anonymous"},
			want:     true,
		},
		{
			name:     "literal asterisk user",
			resource: "users",
			names:    []string{"*"},
			want:     true,
		},
		{
			name:     "empty user",
			resource: "users",
			names:    []string{""},
		},
		{
			name:     "SA username under users",
			resource: "users",
			names:    []string{"system:serviceaccount:prod:worker"},
		},
		{
			name:     "mixed user names",
			resource: "users",
			names:    []string{"", "system:serviceaccount:prod:worker", "alice"},
			want:     true,
		},
		{
			name:      "namespaced users",
			resource:  "users",
			namespace: "prod",
		},
		{
			name:     "any SA",
			resource: "serviceaccounts",
			want:     true,
		},
		{
			name:      "namespaced SA",
			resource:  "serviceaccounts",
			namespace: "prod",
			names:     []string{"worker"},
			want:      true,
		},
		{
			name:     "SA without object",
			resource: "serviceaccounts",
			names:    []string{"deleted-worker"},
			want:     true,
		},
		{
			name:     "empty SA",
			resource: "serviceaccounts",
			names:    []string{""},
		},
		{
			name:     "literal asterisk SA",
			resource: "serviceaccounts",
			names:    []string{"*"},
		},
		{
			name:     "invalid SA",
			resource: "serviceaccounts",
			names:    []string{"not:a:name"},
		},
		{
			name:     "mixed SA names",
			resource: "serviceaccounts",
			names:    []string{"", "*", "worker"},
			want:     true,
		},
		{
			name:     "wrong API group",
			resource: "users",
			apiGroup: "authentication.k8s.io",
		},
		{
			name:     "wrong verb",
			resource: "users",
			verb:     "get",
		},
		{
			name:     "token permission",
			resource: "serviceaccounts/token",
		},
		{
			name:     "groups only",
			resource: "groups",
		},
		{
			name:     "wildcard resource",
			resource: "*",
			want:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verb := tc.verb
			if verb == "" {
				verb = "impersonate"
			}
			rules := []ScopedRule{{Namespace: tc.namespace, Rule: rule([]string{tc.apiGroup}, []string{tc.resource}, []string{verb}, tc.names)}}
			require.Equal(t, tc.want, canImpersonateUsername(rules))
			// Neither the target inventory nor the starting subject supplies a
			// missing impersonate grant. All three kinds use the same prerequisite.
			for _, start := range []Subject{sa("prod", "caller"), {Kind: KindUser, Name: "caller"}, {Kind: KindGroup, Name: "callers"}} {
				combined := append([]ScopedRule{}, rules...)
				combined = append(combined, ScopedRule{Rule: rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"})})
				edges := NewIndex(nil, nil, nil, nil, nil).DirectEscalationEdges(start, combined)
				found := false
				for _, edge := range edges {
					found = found || (edge.ToSubject != nil && edge.ToSubject.Kind == KindGroup && edge.ToSubject.Name == "system:masters")
				}
				require.Equal(t, tc.want, found)
			}
		})
	}
}

func TestGroupImpersonationCombinesSeparatelyGrantedRules(t *testing.T) {
	for _, namespace := range []string{"", "prod"} {
		t.Run("SA scope "+namespace, func(t *testing.T) {
			groups := clusterRole("groups", rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"}))
			identity := rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"uncollected"})
			clusterRoles := []rbacv1.ClusterRole{groups}
			clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("groups", "groups", saSubject("prod", "caller"))}
			var roles []rbacv1.Role
			var bindings []rbacv1.RoleBinding
			if namespace == "" {
				clusterRoles = append(clusterRoles, clusterRole("identity", identity))
				clusterBindings = append(clusterBindings, clusterRoleBinding("identity", "identity", saSubject("prod", "caller")))
			} else {
				roles = []rbacv1.Role{role(namespace, "identity", identity)}
				bindings = []rbacv1.RoleBinding{roleBinding(namespace, "identity", "Role", "identity", saSubject("prod", "caller"))}
			}
			result := NewIndex(roles, clusterRoles, bindings, clusterBindings, nil).AnalyzeEscalation(sa("prod", "caller"))
			require.True(t, result.ClusterAdmin, "an authorized SA username needs no collected SA object")
		})
	}
}

func TestGroupImpersonationReevaluatesAfterRealRuleGrant(t *testing.T) {
	// The missing prerequisite may become available through an independent
	// bind edge. Checking only the subject's initial rules would miss this.
	start := clusterRole("start",
		rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"}),
		rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"identity"}),
		rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	identity := clusterRole("identity", rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"alice"}))
	idx := NewIndex(nil, []rbacv1.ClusterRole{start, identity}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("start", "start", saSubject("prod", "caller")),
	}, nil)
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.True(t, result.ClusterAdmin)
	require.NotEmpty(t, result.Granted)
}

func TestGroupImpersonationCannotBorrowAnotherSubjectsPrerequisite(t *testing.T) {
	groups := clusterRole("groups", rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"}))
	identity := clusterRole("identity", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{groups, identity}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("caller", "groups", saSubject("prod", "caller")),
		clusterRoleBinding("other", "identity", saSubject("prod", "other")),
	}, nil)
	require.False(t, idx.AnalyzeEscalation(sa("prod", "caller")).ClusterAdmin)
}

func TestGroupPrerequisiteIsCheckedForEachReachedIdentity(t *testing.T) {
	for _, secondUsernameGrant := range []bool{false, true} {
		t.Run(map[bool]string{false: "intermediate group permission alone", true: "intermediate also authorizes a username"}[secondUsernameGrant], func(t *testing.T) {
			caller := clusterRole("caller", rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"alice"}))
			intermediate := clusterRole("alice", rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"}))
			if secondUsernameGrant {
				intermediate.Rules = append(intermediate.Rules, rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"bob"}))
			}
			idx := NewIndex(nil, []rbacv1.ClusterRole{caller, intermediate}, nil, []rbacv1.ClusterRoleBinding{
				clusterRoleBinding("caller", "caller", saSubject("prod", "caller")),
				clusterRoleBinding("alice", "alice", rbacv1.Subject{Kind: "User", Name: "alice"}),
			}, nil)
			result := idx.AnalyzeEscalation(sa("prod", "caller"))
			require.Equal(t, secondUsernameGrant, result.ClusterAdmin)
			require.NotEmpty(t, result.Reached, "Alice remains reachable under the caller's own username grant")
			if !secondUsernameGrant {
				require.Len(t, result.Reached, 1, "Alice cannot reuse the original caller's impersonation permission")
				last := result.Reached[0].Edges[len(result.Reached[0].Edges)-1]
				require.Equal(t, &Subject{Kind: KindUser, Name: "alice"}, last.ToSubject)
			}
		})
	}
}

func TestGroupPrerequisiteDoesNotBlockImplicitServiceAccountGroups(t *testing.T) {
	grant := clusterRole("identity", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"worker"}))
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{grant, admin}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("caller", "identity", saSubject("prod", "caller")),
		clusterRoleBinding("SA-group-admin", "admin", rbacv1.Subject{Kind: "Group", Name: "system:serviceaccounts:prod"}),
	}, nil)
	result := idx.AnalyzeEscalation(sa("outside", "caller"))
	require.False(t, result.ClusterAdmin, "a grant to prod/caller does not authorize outside/caller")
	// The caller itself must not already belong to the privileged namespace.
	idx = NewIndex(nil, []rbacv1.ClusterRole{grant, admin}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("caller", "identity", saSubject("outside", "caller")),
		clusterRoleBinding("SA-group-admin", "admin", rbacv1.Subject{Kind: "Group", Name: "system:serviceaccounts:prod"}),
	}, nil)
	result = idx.AnalyzeEscalation(sa("outside", "caller"))
	require.True(t, result.ClusterAdmin, "username-only SA impersonation still receives its automatic groups")
	require.NotEmpty(t, result.Reached)
}

func TestNamespaceScopedGroupGrantCannotUseClusterWideUsernamePermission(t *testing.T) {
	groupRule := rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"})
	userRule := rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"alice"})
	idx := NewIndex([]rbacv1.Role{role("prod", "groups", groupRule)}, []rbacv1.ClusterRole{clusterRole("identity", userRule)},
		[]rbacv1.RoleBinding{roleBinding("prod", "groups", "Role", "groups", saSubject("prod", "caller"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("identity", "identity", saSubject("prod", "caller"))}, nil)
	result := idx.AnalyzeEscalation(sa("prod", "caller"))
	require.False(t, result.ClusterAdmin)
	for _, path := range result.Reached {
		target := path.Edges[len(path.Edges)-1].ToSubject
		require.NotEqual(t, KindGroup, target.Kind, "group impersonation is a cluster-scoped authorization")
	}
}
