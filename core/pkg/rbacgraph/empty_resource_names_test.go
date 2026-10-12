package rbacgraph

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// The authorizer compares resourceNames with the request's name as written,
// and that includes the empty string. A request that names an object never
// matches "", and a top-level create, whose name is empty, does.

func TestEmptyResourceName_CoversNoNamedRole(t *testing.T) {
	rbacGroup := []string{"rbac.authorization.k8s.io"}
	rewrite := []string{"escalate", "update"}
	editable := role("prod", "editable", rule([]string{""}, []string{"configmaps"}, []string{"get"}, nil))
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	accounts := []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged")}
	privileged := clusterRoleBinding("privileged", "admin", saSubject("prod", "privileged"))

	clusterWide := func(resource string, names ...string) *Index {
		grant := clusterRole("grant", rule(rbacGroup, []string{resource}, rewrite, names))
		return NewIndex([]rbacv1.Role{editable}, []rbacv1.ClusterRole{admin, grant}, nil,
			[]rbacv1.ClusterRoleBinding{privileged, clusterRoleBinding("grant", "grant", saSubject("prod", "attacker"))}, accounts)
	}
	namespaced := func(names ...string) *Index {
		grant := role("prod", "grant", rule(rbacGroup, []string{"roles"}, rewrite, names))
		return NewIndex([]rbacv1.Role{editable, grant}, []rbacv1.ClusterRole{admin},
			[]rbacv1.RoleBinding{roleBinding("prod", "grant", "Role", "grant", saSubject("prod", "attacker"))},
			[]rbacv1.ClusterRoleBinding{privileged}, accounts)
	}

	for _, tt := range []struct {
		name string
		idx  *Index
	}{
		{"clusterroles cluster-wide", clusterWide("clusterroles", "")},
		{"roles cluster-wide", clusterWide("roles", "")},
		{"roles in a namespace", namespaced("")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.idx.AnalyzeEscalation(sa("prod", "attacker"))
			if result.ClusterAdmin {
				t.Error("ClusterAdmin = true, want false: no Role or ClusterRole can be named \"\", so the grant reaches nothing")
			}
			if len(result.Unbounded) != 0 {
				t.Errorf("Unbounded = %+v, want none: an empty name is not an object the snapshot could have missed", result.Unbounded)
			}
		})
	}

	t.Run("a real name next to it still applies", func(t *testing.T) {
		result := namespaced("", "editable").AnalyzeEscalation(sa("prod", "attacker"))
		if len(result.Unbounded) == 0 {
			t.Fatal("Unbounded = empty, want the finding for Role \"editable\"")
		}
	})
	t.Run("a real name that was not collected keeps its warning", func(t *testing.T) {
		result := clusterWide("clusterroles", "", "missing").AnalyzeEscalation(sa("prod", "attacker"))
		if !result.ClusterAdmin || len(result.Unbounded) != 1 {
			t.Fatalf("ClusterAdmin = %v, Unbounded = %+v, want the partial-collection fallback for \"missing\" only", result.ClusterAdmin, result.Unbounded)
		}
	})
}

func TestEmptyResourceName_GrantsTopLevelCreate(t *testing.T) {
	rbacGroup := []string{"rbac.authorization.k8s.io"}
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	accounts := []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged")}
	privileged := clusterRoleBinding("privileged", "admin", saSubject("prod", "privileged"))
	index := func(rules ...rbacv1.PolicyRule) *Index {
		return NewIndex([]rbacv1.Role{role("prod", "grant", rules...)}, []rbacv1.ClusterRole{admin},
			[]rbacv1.RoleBinding{roleBinding("prod", "grant", "Role", "grant", saSubject("prod", "attacker"))},
			[]rbacv1.ClusterRoleBinding{privileged}, accounts)
	}
	createPods := func(names ...string) *Index {
		return index(rule([]string{""}, []string{"pods"}, []string{"create"}, names))
	}
	bindAdmin := func(names ...string) *Index {
		return index(
			rule(rbacGroup, []string{"clusterroles"}, []string{"bind"}, []string{"admin"}),
			rule(rbacGroup, []string{"rolebindings"}, []string{"create"}, names))
	}
	primitives := func(idx *Index) map[EscalationPrimitive]bool {
		subject := sa("prod", "attacker")
		found := map[EscalationPrimitive]bool{}
		for _, edge := range idx.DirectEscalationEdges(subject, idx.DirectRules(subject)) {
			found[edge.Primitive] = true
		}
		return found
	}

	for _, tt := range []struct {
		name      string
		idx       *Index
		primitive EscalationPrimitive
		want      bool
	}{
		{"pods, empty name", createPods(""), PrimitiveAssignServiceAccount, true},
		{"pods, empty name next to another", createPods("some-pod", ""), PrimitiveAssignServiceAccount, true},
		{"pods, real name only", createPods("some-pod"), PrimitiveAssignServiceAccount, false},
		{"rolebindings, empty name", bindAdmin(""), PrimitiveBindVerb, true},
		{"rolebindings, real name only", bindAdmin("some-binding"), PrimitiveBindVerb, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := primitives(tt.idx)[tt.primitive]; got != tt.want {
				t.Errorf("%s edge present = %v, want %v", tt.primitive, got, tt.want)
			}
		})
	}
}
