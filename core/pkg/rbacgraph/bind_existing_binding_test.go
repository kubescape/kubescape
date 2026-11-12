package rbacgraph

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// The API server applies the same check to an update of a binding as to a
// create: BindingAuthorized, in pkg/registry/rbac/{rolebinding,
// clusterrolebinding}/policybased/storage.go. The roleRef of a binding is
// immutable, but its subjects are not, so bind on the referenced role plus
// update or patch on the binding lets a subject add itself.
func TestAnalyzeEscalation_BindAppliesToUpdatesOfExistingBindings(t *testing.T) {
	bindClusterRole := rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"bind"}, []string{"power"})
	bindRole := rule([]string{rbacv1.GroupName}, []string{"roles"}, []string{"bind"}, []string{"power"})
	bindReader := rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"bind"}, []string{"reader"})
	power := clusterRole("power", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	reader := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	namespacedPower := role("prod", "power", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	other := rbacv1.Subject{Kind: "User", Name: "someone-else"}
	attacker := saSubject("dev", "attacker")

	for _, tc := range []struct {
		name            string
		roles           []rbacv1.Role
		roleBindings    []rbacv1.RoleBinding
		clusterBindings []rbacv1.ClusterRoleBinding
		clusterGrants   []rbacv1.PolicyRule
		wantAdmin       bool
		wantScope       string
		wantTarget      string
	}{
		{
			name:            "update a named ClusterRoleBinding of the role",
			clusterBindings: []rbacv1.ClusterRoleBinding{clusterRoleBinding("admins", "power", other)},
			clusterGrants: []rbacv1.PolicyRule{
				bindClusterRole,
				rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"update"}, []string{"admins"}),
			},
			wantAdmin: true,
		},
		{
			name:            "patch any ClusterRoleBinding",
			clusterBindings: []rbacv1.ClusterRoleBinding{clusterRoleBinding("admins", "power", other)},
			clusterGrants: []rbacv1.PolicyRule{
				bindClusterRole,
				rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"patch"}, nil),
			},
			wantAdmin: true,
		},
		{
			name:         "update a RoleBinding of the ClusterRole confines it to that namespace",
			roleBindings: []rbacv1.RoleBinding{roleBinding("prod", "admins", "ClusterRole", "reader", other)},
			clusterGrants: []rbacv1.PolicyRule{
				bindReader,
				rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{"update"}, []string{"admins"}),
			},
			wantTarget: "reader",
			wantScope:  "prod",
		},
		{
			name:         "patch a RoleBinding of a Role",
			roles:        []rbacv1.Role{namespacedPower},
			roleBindings: []rbacv1.RoleBinding{roleBinding("prod", "admins", "Role", "power", other)},
			clusterGrants: []rbacv1.PolicyRule{
				bindRole,
				rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{"patch"}, nil),
			},
			wantTarget: "power",
			wantScope:  "prod",
		},
		{
			name:            "the editable binding must be the one that names the role",
			clusterBindings: []rbacv1.ClusterRoleBinding{clusterRoleBinding("admins", "power", other)},
			clusterGrants: []rbacv1.PolicyRule{
				bindClusterRole,
				rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"update"}, []string{"different"}),
			},
		},
		{
			name:            "no binding of the role is writable",
			clusterBindings: []rbacv1.ClusterRoleBinding{clusterRoleBinding("admins", "power", other)},
			clusterGrants:   []rbacv1.PolicyRule{bindClusterRole},
		},
		{
			name:            "editing the binding without bind does not authorize it",
			clusterBindings: []rbacv1.ClusterRoleBinding{clusterRoleBinding("admins", "power", other)},
			clusterGrants: []rbacv1.PolicyRule{
				rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"update"}, []string{"admins"}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grants := clusterRole("grants", tc.clusterGrants...)
			idx := NewIndex(tc.roles, []rbacv1.ClusterRole{power, reader, grants}, tc.roleBindings,
				append([]rbacv1.ClusterRoleBinding{clusterRoleBinding("grants", "grants", attacker)}, tc.clusterBindings...), nil)

			result := idx.AnalyzeEscalation(sa("dev", "attacker"))

			if result.ClusterAdmin != tc.wantAdmin {
				t.Errorf("ClusterAdmin = %v, want %v\nGranted: %+v", result.ClusterAdmin, tc.wantAdmin, result.Granted)
			}
			if tc.wantTarget == "" {
				if !tc.wantAdmin && len(result.Granted) != 0 {
					t.Errorf("Granted = %+v, want none", result.Granted)
				}
				return
			}
			if len(result.Granted) != 1 {
				t.Fatalf("Granted = %+v, want exactly one bind-verb grant", result.Granted)
			}
			edge := result.Granted[0].Edge
			if edge.Primitive != PrimitiveBindVerb || edge.Scope != tc.wantScope || edge.Target == nil || edge.Target.Name != tc.wantTarget {
				t.Errorf("Granted[0].Edge = %+v, want bind-verb of %s scoped to %q", edge, tc.wantTarget, tc.wantScope)
			}
			for _, sr := range edge.GrantedRules {
				if sr.Namespace != tc.wantScope {
					t.Errorf("GrantedRules namespace = %q, want %q", sr.Namespace, tc.wantScope)
				}
			}
		})
	}
}

// Adopting a wildcard role by editing a binding also grants create on
// rolebindings there, so a second path to the same grant appears on the next
// pass. It is still one grant.
func TestAnalyzeEscalation_BindGrantReachedByTwoPathsIsReportedOnce(t *testing.T) {
	grants := clusterRole("grants",
		rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"bind"}, []string{"power"}),
		rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{"update"}, []string{"admins"}))
	power := clusterRole("power", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{power, grants},
		[]rbacv1.RoleBinding{roleBinding("prod", "admins", "ClusterRole", "power", rbacv1.Subject{Kind: "User", Name: "someone-else"})},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("grants", "grants", saSubject("dev", "attacker"))}, nil)

	var adopted int
	for _, g := range idx.AnalyzeEscalation(sa("dev", "attacker")).Granted {
		if g.Edge.Primitive == PrimitiveBindVerb && g.Edge.Scope == "prod" && g.Edge.Target != nil && g.Edge.Target.Name == "power" {
			adopted++
		}
	}
	if adopted != 1 {
		t.Errorf("bind-verb grants of power in prod = %d, want 1", adopted)
	}
}

// bind is authorized in the binding's own namespace, so a RoleBinding-held
// bind grant cannot be spent on a ClusterRoleBinding or on a RoleBinding in
// another namespace, even when the subject may edit that binding.
func TestAnalyzeEscalation_NamespacedBindDoesNotAuthorizeUpdatesElsewhere(t *testing.T) {
	bindClusterRole := rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"bind"}, []string{"power"})
	power := clusterRole("power", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	other := rbacv1.Subject{Kind: "User", Name: "someone-else"}
	attacker := saSubject("dev", "attacker")

	idx := NewIndex(
		[]rbacv1.Role{role("dev", "binder", bindClusterRole)},
		[]rbacv1.ClusterRole{power, clusterRole("editor", rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings", "rolebindings"}, []string{"update"}, nil))},
		[]rbacv1.RoleBinding{
			roleBinding("dev", "binder", "Role", "binder", attacker),
			roleBinding("prod", "admins", "ClusterRole", "power", other),
		},
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("editor", "editor", attacker),
			clusterRoleBinding("admins", "power", other),
		},
		nil,
	)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if result.ClusterAdmin || len(result.Granted) != 0 {
		t.Errorf("ClusterAdmin = %v, Granted = %+v; want false and none: bind is only held in dev, where no binding of power exists", result.ClusterAdmin, result.Granted)
	}
}
