package rbacgraph

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestAnalyzeEscalation_UnmatchedRoleNameDoesNotBecomeClusterAdmin(t *testing.T) {
	for _, name := range []string{"*", "missing"} {
		t.Run(name, func(t *testing.T) {
			idx := NewIndex([]rbacv1.Role{
				role("prod", "reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil)),
			}, []rbacv1.ClusterRole{
				clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "update"}, []string{name})),
			}, nil, []rbacv1.ClusterRoleBinding{
				clusterRoleBinding("escalator", "escalator", saSubject("prod", "attacker")),
			}, nil)
			result := idx.AnalyzeEscalation(sa("prod", "attacker"))
			if result.ClusterAdmin {
				t.Fatalf("unresolved namespaced Role became confirmed cluster-admin: %+v", result)
			}
			if len(result.Unbounded) != 1 || !strings.Contains(result.Unbounded[0].Edge.Detail, "not found in the collected snapshot") {
				t.Fatalf("missing-target warning must remain visible: %+v", result.Unbounded)
			}
			if !result.Unbounded[0].Edge.ScopeUnknown {
				t.Fatal("missing namespaced Role must explicitly report an unresolved scope")
			}
			if len(result.EffectiveRules) != 1 || IsClusterAdminEquivalent(result.EffectiveRules) {
				t.Fatalf("unresolved warning fabricated permissions: %+v", result.EffectiveRules)
			}
			if result.Truncated || len(result.Reached) != 0 {
				t.Fatalf("warning should not invent identities or prevent completion: %+v", result)
			}
		})
	}
}

func TestAnalyzeEscalation_UnresolvedRoleScopeDoesNotStopOtherTraversal(t *testing.T) {
	idx := NewIndex(nil, []rbacv1.ClusterRole{
		clusterRole("escalator",
			rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "update"}, []string{"*"}),
			rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"observer"})),
		clusterRole("observer", rule([]string{""}, []string{"configmaps"}, []string{"get"}, nil)),
	}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("attacker", "escalator", saSubject("prod", "attacker")),
		clusterRoleBinding("observer", "observer", saSubject("prod", "observer")),
	}, []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "observer")})
	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	if result.ClusterAdmin || len(result.Unbounded) != 1 || len(result.Reached) != 1 {
		t.Fatalf("unresolved warning short-circuited traversal: %+v", result)
	}
	observerRulesFound := false
	for _, grant := range result.EffectiveRules {
		if ruleGrants(grant.Rule, "", "configmaps", "get") {
			observerRulesFound = true
		}
	}
	if !observerRulesFound {
		t.Fatalf("ordinary reachable identity was never explored: %+v", result)
	}
}

func TestAnalyzeEscalation_RoleFallbackPreservesKnownScope(t *testing.T) {
	for _, tt := range []struct {
		name       string
		resource   string
		scope      string
		targetName string
		wantScope  string
		admin      bool
	}{
		{"collected namespaced Role", "roles", "", "reader", "prod", false},
		{"missing Role in known namespace", "roles", "prod", "missing", "prod", false},
		{"missing ClusterRole", "clusterroles", "", "missing", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			grant := rule([]string{"rbac.authorization.k8s.io"}, []string{tt.resource}, []string{"escalate", "update"}, []string{tt.targetName})
			roles := []rbacv1.Role{role("prod", "reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))}
			var clusterRoles []rbacv1.ClusterRole
			var bindings []rbacv1.RoleBinding
			var clusterBindings []rbacv1.ClusterRoleBinding
			if tt.scope == "" {
				clusterRoles = []rbacv1.ClusterRole{clusterRole("escalator", grant)}
				clusterBindings = []rbacv1.ClusterRoleBinding{clusterRoleBinding("attacker", "escalator", saSubject("prod", "attacker"))}
			} else {
				roles = append(roles, role(tt.scope, "escalator", grant))
				bindings = []rbacv1.RoleBinding{roleBinding(tt.scope, "attacker", "Role", "escalator", saSubject("prod", "attacker"))}
			}
			idx := NewIndex(roles, clusterRoles, bindings, clusterBindings, nil)
			result := idx.AnalyzeEscalation(sa("prod", "attacker"))
			if result.ClusterAdmin != tt.admin || len(result.Unbounded) == 0 {
				t.Fatalf("scope verdict changed: %+v", result)
			}
			for _, finding := range result.Unbounded {
				if finding.Edge.Scope != tt.wantScope {
					t.Fatalf("warning scope = %q, want %q", finding.Edge.Scope, tt.wantScope)
				}
				if finding.Edge.ScopeUnknown {
					t.Fatal("a known namespace or ClusterRole scope must remain resolved")
				}
			}
		})
	}
}
