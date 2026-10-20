package rbacgraph

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzeEscalation_FiniteBindGrantLeavesReachabilityEmptyAndRecordsProvenance(t *testing.T) {
	idx := NewIndex(
		[]rbacv1.Role{
			role("prod", "secret-reader", rule([]string{""}, []string{"secrets"}, []string{"get", "list"}, nil)),
			role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, []string{"secret-reader"})),
			role("prod", "rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil)),
		},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("prod", "rb1", "Role", "binder", saSubject("prod", "api")),
			roleBinding("prod", "rb2", "Role", "rb-creator", saSubject("prod", "api")),
		},
		nil,
		nil,
	)

	result := idx.AnalyzeEscalation(sa("prod", "api"))

	if len(result.Reached) != 0 || len(result.Unbounded) != 0 || result.ClusterAdmin || result.Truncated {
		t.Fatalf("Reached/Unbounded/ClusterAdmin/Truncated = %d/%d/%v/%v, want 0/0/false/false", len(result.Reached), len(result.Unbounded), result.ClusterAdmin, result.Truncated)
	}
	if len(result.Granted) != 1 {
		t.Fatalf("Granted = %+v, want exactly one grant", result.Granted)
	}
	g := result.Granted[0]
	if g.Subject != sa("prod", "api") || g.Edge.Primitive != PrimitiveBindVerb || g.Edge.Scope != "prod" ||
		g.Edge.Target == nil || *g.Edge.Target != (RoleTarget{Kind: "Role", Namespace: "prod", Name: "secret-reader"}) {
		t.Errorf("Granted[0] = %+v, want bind-verb of Role prod/secret-reader by prod/api", g)
	}
	if len(g.Edge.GrantedRules) != 1 || g.Edge.GrantedRules[0].Namespace != "prod" {
		t.Errorf("GrantedRules = %+v, want the secret-reader rule confined to prod", g.Edge.GrantedRules)
	}
}

func TestAnalyzeEscalation_DirectRulesAreNotReportedAsGranted(t *testing.T) {
	idx := NewIndex(
		[]rbacv1.Role{role("prod", "r", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))},
		nil,
		[]rbacv1.RoleBinding{roleBinding("prod", "rb", "Role", "r", saSubject("prod", "api"))},
		nil,
		nil,
	)
	if got := idx.AnalyzeEscalation(sa("prod", "api")).Granted; len(got) != 0 {
		t.Errorf("Granted = %+v, want none: a direct rule is not a grant", got)
	}
}

func TestAnalyzeEscalation_GrantedIsSortedAndDeduplicated(t *testing.T) {
	idx := NewIndex(
		[]rbacv1.Role{
			role("prod", "zeta", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
			role("prod", "alpha", rule([]string{""}, []string{"configmaps"}, []string{"get"}, nil)),
			role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, []string{"zeta", "alpha"})),
			role("prod", "rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil)),
		},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("prod", "rb1", "Role", "binder", saSubject("prod", "api")),
			roleBinding("prod", "rb2", "Role", "rb-creator", saSubject("prod", "api")),
		},
		nil,
		nil,
	)

	var first []string
	for i := 0; i < 5; i++ {
		var names []string
		for _, g := range idx.AnalyzeEscalation(sa("prod", "api")).Granted {
			names = append(names, g.Edge.Target.Name)
		}
		if i == 0 {
			first = names
			continue
		}
		if len(names) != len(first) {
			t.Fatalf("run %d: %v, want %v", i, names, first)
		}
		for j := range names {
			if names[j] != first[j] {
				t.Fatalf("run %d: %v, want %v", i, names, first)
			}
		}
	}
	if len(first) != 2 || first[0] != "alpha" || first[1] != "zeta" {
		t.Errorf("Granted targets = %v, want [alpha zeta]", first)
	}
}

func TestHasServiceAccount(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "api"}},
	})
	cases := []struct {
		ns, name string
		want     bool
	}{
		{"a", "web", true},
		{"a", "api", true},
		{"b", "web", false},
		{"a", "missing", false},
		{"", "web", false},
	}
	for _, c := range cases {
		if got := idx.HasServiceAccount(c.ns, c.name); got != c.want {
			t.Errorf("HasServiceAccount(%q, %q) = %v, want %v", c.ns, c.name, got, c.want)
		}
	}
}
