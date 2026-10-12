package rbacgraph

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// resourceNames is an exact-match allowlist, not one of RBAC's wildcard
// fields. Exercise both the graph primitives and the final closure so a
// restricted grant cannot silently grow into a path to cluster-admin.
func TestResourceNames_ServiceAccountTargets(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{
		saObj("prod", "admin"),
		saObj("prod", "reader"),
		saObj("dev", "admin"),
	})
	tests := []struct {
		name  string
		names []string
		want  []Subject
	}{
		{"unrestricted", nil, []Subject{sa("prod", "admin"), sa("prod", "reader")}},
		{"empty allowlist", []string{}, []Subject{sa("prod", "admin"), sa("prod", "reader")}},
		{"literal star", []string{"*"}, nil},
		{"prefix is not a glob", []string{"admin*"}, nil},
		{"exact name", []string{"admin"}, []Subject{sa("prod", "admin")}},
		{"star does not widen exact grant", []string{"*", "reader"}, []Subject{sa("prod", "reader")}},
		{"case sensitive", []string{"Admin"}, nil},
		{"duplicates do not duplicate edges", []string{"admin", "admin"}, []Subject{sa("prod", "admin")}},
	}
	for _, primitive := range []struct {
		name     string
		resource string
		verb     string
		edges    func([]ScopedRule) []EscalationEdge
	}{
		{"impersonation", "serviceaccounts", "impersonate", idx.impersonateEdges},
		{"token request", "serviceaccounts/token", "create", idx.mintServiceAccountTokenEdges},
	} {
		t.Run(primitive.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					rules := []ScopedRule{{Namespace: "prod", Rule: rule(
						[]string{""}, []string{primitive.resource}, []string{primitive.verb}, tt.names,
					)}}
					var got []Subject
					for _, edge := range primitive.edges(rules) {
						if edge.ToSubject != nil {
							got = append(got, *edge.ToSubject)
						}
					}
					if !reflect.DeepEqual(got, tt.want) {
						t.Fatalf("targets = %v, want %v", got, tt.want)
					}
				})
			}
		})
	}
}

func TestResourceNames_ClusterWideAccountGrantStillUsesExactNames(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{
		saObj("dev", "admin"),
		saObj("prod", "admin"),
		saObj("prod", "reader"),
	})
	for _, names := range [][]string{{"*"}, {"admin"}, {"*", "admin"}} {
		grant := []ScopedRule{{Rule: rule(
			[]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, names,
		)}}
		edges := idx.mintServiceAccountTokenEdges(grant)
		var got []Subject
		for _, edge := range edges {
			got = append(got, *edge.ToSubject)
		}
		var want []Subject
		if len(names) > 1 || names[0] == "admin" {
			want = []Subject{sa("dev", "admin"), sa("prod", "admin")}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("names %v: got %v, want %v", names, got, want)
		}
	}
}

func TestResourceNames_RoleEnumeration(t *testing.T) {
	idx := NewIndex(
		[]rbacv1.Role{role("prod", "admin"), role("prod", "reader"), role("dev", "admin")},
		[]rbacv1.ClusterRole{clusterRole("admin"), clusterRole("reader")},
		nil, nil, nil,
	)
	tests := []struct {
		name       string
		names      []string
		restricted bool
		cluster    []string
		prod       []string
		all        []string
	}{
		{"unrestricted", nil, false, []string{"admin", "reader"}, []string{"admin", "reader"}, []string{"dev/admin", "prod/admin", "prod/reader"}},
		{"literal star", []string{"*"}, true, nil, nil, nil},
		{"prefix", []string{"admin*"}, true, nil, nil, nil},
		{"named", []string{"admin"}, true, []string{"admin"}, []string{"admin"}, []string{"dev/admin", "prod/admin"}},
		{"mixed", []string{"*", "reader"}, true, []string{"reader"}, []string{"reader"}, []string{"prod/reader"}},
		{"absent", []string{"missing"}, true, nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cluster, prod, all []string
			for _, target := range idx.matchingClusterRoles(tt.names, tt.restricted) {
				cluster = append(cluster, target.Name)
			}
			for _, target := range idx.matchingRoles("prod", tt.names, tt.restricted) {
				prod = append(prod, target.Name)
			}
			for _, target := range idx.matchingRolesAnyNamespace(tt.names, tt.restricted) {
				all = append(all, target.Namespace+"/"+target.Name)
			}
			if !reflect.DeepEqual(cluster, tt.cluster) {
				t.Errorf("ClusterRoles = %v, want %v", cluster, tt.cluster)
			}
			if !reflect.DeepEqual(prod, tt.prod) {
				t.Errorf("prod Roles = %v, want %v", prod, tt.prod)
			}
			if !reflect.DeepEqual(all, tt.all) {
				t.Errorf("all Roles = %v, want %v", all, tt.all)
			}
		})
	}
}

func TestResourceNames_LiteralStarCanOnlyMatchLiteralStar(t *testing.T) {
	// Kubernetes object names cannot contain a star. Keep this unit-level
	// check nevertheless: the matcher must implement equality, not special
	// handling that treats a star as either a wildcard or an empty grant.
	idx := NewIndex(
		[]rbacv1.Role{role("prod", "*"), role("prod", "admin")},
		[]rbacv1.ClusterRole{clusterRole("*"), clusterRole("admin")},
		nil, nil, []corev1.ServiceAccount{saObj("prod", "*"), saObj("prod", "admin")},
	)
	if got := idx.matchingClusterRoles([]string{"*"}, true); len(got) != 1 || got[0].Name != "*" {
		t.Fatalf("literal ClusterRole match = %v", got)
	}
	if got := idx.matchingRoles("prod", []string{"*"}, true); len(got) != 1 || got[0].Name != "*" {
		t.Fatalf("literal Role match = %v", got)
	}
	if got := idx.matchingRolesAnyNamespace([]string{"*"}, true); len(got) != 1 || got[0].Name != "*" {
		t.Fatalf("literal any-namespace Role match = %v", got)
	}
}

func TestResourceNames_CannotAcquireAdminServiceAccount(t *testing.T) {
	for _, grant := range []struct {
		name     string
		resource string
		verb     string
	}{
		{"impersonate", "serviceaccounts", "impersonate"},
		{"mint token", "serviceaccounts/token", "create"},
	} {
		t.Run(grant.name, func(t *testing.T) {
			for _, tt := range []struct {
				name  string
				names []string
				admin bool
			}{
				{"star", []string{"*"}, false},
				{"star with reader", []string{"*", "reader"}, false},
				{"admin", []string{"admin"}, true},
				{"unrestricted", nil, true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					idx := NewIndex(nil, []rbacv1.ClusterRole{
						clusterRole("attacker", rule([]string{""}, []string{grant.resource}, []string{grant.verb}, tt.names)),
						clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil)),
					}, nil, []rbacv1.ClusterRoleBinding{
						clusterRoleBinding("attacker", "attacker", saSubject("prod", "attacker")),
						clusterRoleBinding("admin", "admin", saSubject("prod", "admin")),
					}, []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "admin"), saObj("prod", "reader")})
					result := idx.AnalyzeEscalation(sa("prod", "attacker"))
					if result.ClusterAdmin != tt.admin {
						t.Fatalf("ClusterAdmin = %v, want %v; result = %+v", result.ClusterAdmin, tt.admin, result)
					}
				})
			}
		})
	}
}

func TestResourceNames_BindCannotAcquireUnlistedClusterRole(t *testing.T) {
	for _, tt := range []struct {
		name  string
		names []string
		admin bool
	}{
		{"star", []string{"*"}, false},
		{"star and reader", []string{"*", "reader"}, false},
		{"named admin", []string{"admin"}, true},
		{"unrestricted", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewIndex(nil, []rbacv1.ClusterRole{
				clusterRole("attacker",
					rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, tt.names),
					rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil)),
				clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil)),
				clusterRole("reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil)),
			}, nil, []rbacv1.ClusterRoleBinding{
				clusterRoleBinding("attacker", "attacker", saSubject("prod", "attacker")),
			}, nil)
			result := idx.AnalyzeEscalation(sa("prod", "attacker"))
			if result.ClusterAdmin != tt.admin {
				t.Fatalf("ClusterAdmin = %v, want %v; result = %+v", result.ClusterAdmin, tt.admin, result)
			}
		})
	}
}

func TestResourceNames_BindRoleRespectsRestrictionAndScope(t *testing.T) {
	idx := NewIndex([]rbacv1.Role{
		role("prod", "admin", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
		role("prod", "reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil)),
		role("dev", "reader", rule([]string{""}, []string{"pods"}, []string{"get"}, nil)),
	}, nil, nil, nil, nil)
	for _, tt := range []struct {
		name  string
		names []string
		count int
	}{
		{"star", []string{"*"}, 0},
		{"reader", []string{"reader"}, 1},
		{"mixed", []string{"*", "reader"}, 1},
		{"unrestricted", nil, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := []ScopedRule{
				{Namespace: "prod", Rule: rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, tt.names)},
				{Namespace: "prod", Rule: rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil)},
			}
			edges := idx.bindVerbEdges(rules)
			if len(edges) != tt.count {
				t.Fatalf("edges = %+v, want %d", edges, tt.count)
			}
			for _, edge := range edges {
				for _, grant := range edge.GrantedRules {
					if grant.Namespace != "prod" {
						t.Fatalf("grant escaped namespace: %+v", grant)
					}
				}
			}
		})
	}
}

func TestResourceNames_WildcardRuleIsNotUnrestrictedAdmin(t *testing.T) {
	for _, names := range [][]string{nil, {}, {"*"}, {"admin"}, {"*", "admin"}} {
		for _, namespace := range []string{"", "prod"} {
			rules := []ScopedRule{{Namespace: namespace, Rule: rule(
				[]string{"*"}, []string{"*"}, []string{"*"}, names,
			)}}
			want := namespace == "" && len(names) == 0
			if got := IsClusterAdminEquivalent(rules); got != want {
				t.Errorf("namespace %q names %v: admin = %v, want %v", namespace, names, got, want)
			}
		}
	}
}

func TestResourceNames_RestrictionSurvivesJSONRoundTripAndClosure(t *testing.T) {
	// Scan collection converts unstructured RBAC through JSON. Preserve the
	// distinction between a wildcard-shaped name and unrestricted access
	// across that representation boundary, not only hand-built edge rules.
	for _, names := range [][]string{{"*"}, {"*", "reader"}, {"admin"}, nil} {
		original := clusterRole("attacker",
			rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, names))
		raw, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		var restored rbacv1.ClusterRole
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		idx := NewIndex(nil, []rbacv1.ClusterRole{
			restored,
			clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil)),
		}, nil, []rbacv1.ClusterRoleBinding{
			clusterRoleBinding("attacker", "attacker", saSubject("prod", "attacker")),
			clusterRoleBinding("admin", "admin", saSubject("prod", "admin")),
		}, []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "admin"), saObj("prod", "reader")})
		want := len(names) == 0 || names[0] == "admin"
		if got := idx.AnalyzeEscalation(sa("prod", "attacker")); got.ClusterAdmin != want {
			t.Fatalf("restored names %v: admin = %v, want %v", restored.Rules[0].ResourceNames, got.ClusterAdmin, want)
		}
	}
}

func TestResourceNames_EscalateDoesNotAttributeUnlistedRole(t *testing.T) {
	// The partial-snapshot fallback remains intentionally conservative.
	// Even when that fallback reports an unbounded risk, the graph must
	// not attribute a collected admin Role to a star name.
	for _, resource := range []string{"roles", "clusterroles"} {
		t.Run(resource, func(t *testing.T) {
			idx := NewIndex([]rbacv1.Role{
				role("prod", "admin", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
			}, []rbacv1.ClusterRole{
				clusterRole("admin", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
			}, nil, nil, nil)
			scope := "prod"
			if resource == "clusterroles" {
				scope = ""
			}
			for _, names := range [][]string{{"*"}, {"admin"}, {"*", "admin"}} {
				rules := []ScopedRule{{Namespace: scope, Rule: rule(
					[]string{"rbac.authorization.k8s.io"}, []string{resource}, []string{"escalate", "update"}, names,
				)}}
				edges := idx.escalateVerbEdges(rules)
				attributed := false
				for _, edge := range edges {
					if strings.Contains(edge.Detail, `Role "admin"`) {
						attributed = true
					}
				}
				want := len(names) > 1 || names[0] == "admin"
				if attributed != want {
					t.Fatalf("%s names %v: attributed admin role = %v, want %v; edges = %+v", resource, names, attributed, want, edges)
				}
			}
		})
	}
}

func TestResourceNames_RestrictedDirectAdminIsNotEquivalent(t *testing.T) {
	idx := NewIndex(nil, []rbacv1.ClusterRole{
		clusterRole("restricted", rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"named-object"})),
	}, nil, []rbacv1.ClusterRoleBinding{
		clusterRoleBinding("restricted", "restricted", saSubject("prod", "attacker")),
	}, []corev1.ServiceAccount{saObj("prod", "attacker")})
	direct := idx.DirectRules(sa("prod", "attacker"))
	if len(direct) != 1 {
		t.Fatalf("expected the restricted binding to remain visible, got %+v", direct)
	}
	if IsClusterAdminEquivalent(direct) {
		t.Fatalf("name-restricted wildcard rule became directly equivalent to cluster-admin: %+v", direct)
	}
}

func TestResourceNames_WildcardsInOtherFieldsRemainSupported(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{
		saObj("prod", "admin"), saObj("prod", "reader"),
	})
	for _, tt := range []struct {
		name      string
		groups    []string
		resources []string
		verbs     []string
	}{
		{"wildcard group", []string{"*"}, []string{"serviceaccounts"}, []string{"impersonate"}},
		{"wildcard resource", []string{""}, []string{"*"}, []string{"impersonate"}},
		{"wildcard verb", []string{""}, []string{"serviceaccounts"}, []string{"*"}},
		{"all wildcard fields", []string{"*"}, []string{"*"}, []string{"*"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := []ScopedRule{{Namespace: "prod", Rule: rule(
				tt.groups, tt.resources, tt.verbs, []string{"admin"},
			)}}
			edges := idx.impersonateEdges(rules)
			if len(edges) != 1 || edges[0].ToSubject == nil || *edges[0].ToSubject != sa("prod", "admin") {
				t.Fatalf("wildcard grant lost its named target: %+v", edges)
			}
			if edges[0].Unbounded {
				t.Fatal("named target must not turn into unrestricted impersonation")
			}
		})
	}
}
