package rbacgraph

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// assignTargets returns the ServiceAccounts subject can be made to run as
// through an assign-serviceaccount edge, keyed by "namespace/name".
func assignTargets(idx *Index, subject Subject) map[string]EscalationEdge {
	out := map[string]EscalationEdge{}
	for _, e := range idx.DirectEscalationEdges(subject, idx.DirectRules(subject)) {
		if e.Primitive == PrimitiveAssignServiceAccount {
			out[e.ToSubject.Namespace+"/"+e.ToSubject.Name] = e
		}
	}
	return out
}

func workloadFixture(roleRules ...rbacv1.PolicyRule) *Index {
	return NewIndex(
		[]rbacv1.Role{role("prod", "writer", roleRules...)}, nil,
		[]rbacv1.RoleBinding{roleBinding("prod", "writer", "Role", "writer", saSubject("prod", "attacker"))},
		nil,
		[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged"), saObj("other", "privileged")},
	)
}

func TestAssignServiceAccount_WorkloadWrites(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule rbacv1.PolicyRule
		want bool
	}{
		{"create pods", rule([]string{""}, []string{"pods"}, []string{"create"}, nil), true},
		{"create replicationcontrollers", rule([]string{""}, []string{"replicationcontrollers"}, []string{"create"}, nil), true},
		{"create deployments", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}, nil), true},
		{"create statefulsets", rule([]string{"apps"}, []string{"statefulsets"}, []string{"create"}, nil), true},
		{"create daemonsets", rule([]string{"apps"}, []string{"daemonsets"}, []string{"create"}, nil), true},
		{"create replicasets", rule([]string{"apps"}, []string{"replicasets"}, []string{"create"}, nil), true},
		{"create jobs", rule([]string{"batch"}, []string{"jobs"}, []string{"create"}, nil), true},
		{"create cronjobs", rule([]string{"batch"}, []string{"cronjobs"}, []string{"create"}, nil), true},
		{"wildcard group, named resource", rule([]string{"*"}, []string{"deployments"}, []string{"create"}, nil), true},
		{"named group, wildcard resource", rule([]string{"apps"}, []string{"*"}, []string{"create"}, nil), true},
		{"wildcard verb", rule([]string{"apps"}, []string{"deployments"}, []string{"*"}, nil), true},
		{"empty resource name creates", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}, []string{""}), true},

		{"update deployments", rule([]string{"apps"}, []string{"deployments"}, []string{"update"}, nil), true},
		{"patch cronjobs", rule([]string{"batch"}, []string{"cronjobs"}, []string{"patch"}, nil), true},
		{"patch one named deployment", rule([]string{"apps"}, []string{"deployments"}, []string{"patch"}, []string{"web"}), true},

		{"get deployments", rule([]string{"apps"}, []string{"deployments"}, []string{"get"}, nil), false},
		{"list and watch cronjobs", rule([]string{"batch"}, []string{"cronjobs"}, []string{"list", "watch"}, nil), false},
		{"cronjobs in apps", rule([]string{"apps"}, []string{"cronjobs"}, []string{"create"}, nil), false},
		{"deployments in batch", rule([]string{"batch"}, []string{"deployments"}, []string{"create"}, nil), false},
		{"deployments in core group", rule([]string{""}, []string{"deployments"}, []string{"create"}, nil), false},
		{"pods in apps group", rule([]string{"apps"}, []string{"pods"}, []string{"create"}, nil), false},
		{"legacy extensions group", rule([]string{"extensions"}, []string{"deployments"}, []string{"create"}, nil), false},
		{"scale subresource", rule([]string{"apps"}, []string{"deployments/scale"}, []string{"create", "update"}, nil), false},
		{"podtemplates are not workloads", rule([]string{""}, []string{"podtemplates"}, []string{"create"}, nil), false},
		{"create with only a real resource name", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}, []string{"web"}), false},
		{"update naming only a literal star", rule([]string{"apps"}, []string{"deployments"}, []string{"update"}, []string{"*"}), false},
		{"patch naming only invalid names", rule([]string{"apps"}, []string{"deployments"}, []string{"patch"}, []string{"*", "", "Web_App", "web/app"}), false},
		{"patch naming a literal star and a valid name", rule([]string{"apps"}, []string{"deployments"}, []string{"patch"}, []string{"*", "web"}), true},
		{"update naming a dotted subdomain", rule([]string{"apps"}, []string{"statefulsets"}, []string{"update"}, []string{"db-0.shard"}), true},
		{"update naming only the empty name", rule([]string{"apps"}, []string{"deployments"}, []string{"update"}, []string{""}), false},
		// A Pod's serviceAccountName and a Job's template are immutable.
		{"update pods", rule([]string{""}, []string{"pods"}, []string{"update", "patch"}, nil), false},
		{"update jobs", rule([]string{"batch"}, []string{"jobs"}, []string{"update", "patch"}, nil), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets := assignTargets(workloadFixture(tt.rule), sa("prod", "attacker"))
			if _, got := targets["prod/privileged"]; got != tt.want {
				t.Errorf("edge to prod/privileged = %v, want %v (targets %v)", got, tt.want, targets)
			}
			if _, leaked := targets["other/privileged"]; leaked {
				t.Errorf("a Role in prod produced an edge into namespace other: %v", targets)
			}
			if _, self := targets["prod/attacker"]; self {
				t.Errorf("edge to the subject itself must be filtered: %v", targets)
			}
		})
	}
}

func TestAssignServiceAccount_ClusterRoleBindingSpansNamespaces(t *testing.T) {
	cr := clusterRole("deployer", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("deployer", "deployer", saSubject("prod", "attacker"))},
		[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged"), saObj("other", "privileged")})

	targets := assignTargets(idx, sa("prod", "attacker"))
	for _, want := range []string{"prod/privileged", "other/privileged"} {
		if _, ok := targets[want]; !ok {
			t.Errorf("targets = %v, missing %s", targets, want)
		}
	}
}

func TestAssignServiceAccount_RoleBindingToClusterRoleStaysInNamespace(t *testing.T) {
	cr := clusterRole("deployer", rule([]string{"batch"}, []string{"cronjobs"}, []string{"create"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr},
		[]rbacv1.RoleBinding{roleBinding("prod", "deployer", "ClusterRole", "deployer", saSubject("prod", "attacker"))}, nil,
		[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged"), saObj("other", "privileged")})

	targets := assignTargets(idx, sa("prod", "attacker"))
	if _, ok := targets["prod/privileged"]; !ok {
		t.Errorf("targets = %v, want prod/privileged", targets)
	}
	if _, ok := targets["other/privileged"]; ok {
		t.Errorf("targets = %v, a RoleBinding must not reach into another namespace", targets)
	}
}

func TestAssignServiceAccount_OneEdgePerServiceAccount(t *testing.T) {
	idx := workloadFixture(
		rule([]string{""}, []string{"pods"}, []string{"create"}, nil),
		rule([]string{"apps"}, []string{"deployments", "statefulsets"}, []string{"create", "update"}, nil),
		rule([]string{"batch"}, []string{"jobs"}, []string{"create"}, nil),
	)
	subject := sa("prod", "attacker")
	var edges []EscalationEdge
	for _, e := range idx.DirectEscalationEdges(subject, idx.DirectRules(subject)) {
		if e.Primitive == PrimitiveAssignServiceAccount {
			edges = append(edges, e)
		}
	}
	if len(edges) != 1 {
		t.Fatalf("assign-serviceaccount edges = %+v, want exactly one for prod/privileged", edges)
	}
	for _, want := range []string{"create pods", "create apps/deployments", "update apps/statefulsets", "create batch/jobs"} {
		if !strings.Contains(edges[0].Detail, want) {
			t.Errorf("Detail = %q, want it to name %q", edges[0].Detail, want)
		}
	}
}

func TestAnalyzeEscalation_DeploymentCreateReachesPrivilegedServiceAccount(t *testing.T) {
	// attacker cannot create pods, but can create Deployments; the
	// privileged ServiceAccount is cluster-admin. Running a Deployment under
	// it must make the attacker cluster-admin.
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{role("prod", "deployer", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}, nil))},
		[]rbacv1.ClusterRole{admin},
		[]rbacv1.RoleBinding{roleBinding("prod", "deployer", "Role", "deployer", saSubject("prod", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("admin", "admin", saSubject("prod", "privileged"))},
		[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged")},
	)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	if !result.ClusterAdmin {
		t.Fatalf("ClusterAdmin = false, want true; Reached = %+v", result.Reached)
	}
	if len(result.Reached) != 1 || result.Reached[0].Edges[0].Primitive != PrimitiveAssignServiceAccount ||
		*result.Reached[0].Edges[0].ToSubject != sa("prod", "privileged") {
		t.Errorf("Reached = %+v, want one assign-serviceaccount path to prod/privileged", result.Reached)
	}
}

func TestAssignServiceAccount_DetailQualifiesNamedObjectOnlyWrites(t *testing.T) {
	deployments := []string{"deployments"}
	apps := []string{"apps"}
	for _, tt := range []struct {
		name       string
		rules      []rbacv1.PolicyRule
		want       []string
		wantAbsent []string
	}{
		{
			name:  "named update is qualified",
			rules: []rbacv1.PolicyRule{rule(apps, deployments, []string{"update"}, []string{"web"})},
			want:  []string{"update apps/deployments (named objects only)"},
		},
		{
			name:       "unrestricted update is not qualified",
			rules:      []rbacv1.PolicyRule{rule(apps, deployments, []string{"update"}, nil)},
			want:       []string{"update apps/deployments)"},
			wantAbsent: []string{"named objects only"},
		},
		{
			name: "named and unrestricted rules for the same capability are not qualified",
			rules: []rbacv1.PolicyRule{
				rule(apps, deployments, []string{"patch"}, []string{"web"}),
				rule(apps, deployments, []string{"patch"}, nil),
			},
			want:       []string{"patch apps/deployments)"},
			wantAbsent: []string{"named objects only"},
		},
		{
			name: "qualification is per capability",
			rules: []rbacv1.PolicyRule{
				rule(apps, deployments, []string{"create"}, nil),
				rule(apps, deployments, []string{"update"}, []string{"web"}),
				rule(apps, []string{"statefulsets"}, []string{"update"}, nil),
			},
			want: []string{
				"create apps/deployments,",
				"update apps/deployments (named objects only)",
				"update apps/statefulsets)",
			},
		},
		{
			name:       "create is never qualified",
			rules:      []rbacv1.PolicyRule{rule(apps, deployments, []string{"create"}, []string{""})},
			want:       []string{"(create apps/deployments)"},
			wantAbsent: []string{"named objects only"},
		},
		{
			name:       "pod-only detail is unchanged",
			rules:      []rbacv1.PolicyRule{rule([]string{""}, []string{"pods"}, []string{"create"}, nil)},
			want:       []string{"(create pods), inheriting its mounted token"},
			wantAbsent: []string{"named objects only"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := assignTargets(workloadFixture(tt.rules...), sa("prod", "attacker"))["prod/privileged"]
			if !ok {
				t.Fatal("no edge to prod/privileged")
			}
			for _, w := range tt.want {
				if !strings.Contains(e.Detail, w) {
					t.Errorf("Detail = %q, want it to contain %q", e.Detail, w)
				}
			}
			for _, w := range tt.wantAbsent {
				if strings.Contains(e.Detail, w) {
					t.Errorf("Detail = %q, must not contain %q", e.Detail, w)
				}
			}
		})
	}
}

func TestAnalyzeEscalation_DeploymentPatchNamingLiteralStarIsNotClusterAdmin(t *testing.T) {
	// resourceNames is literal, so ["*"] names no Deployment that can exist.
	// It must not reach the cluster-admin ServiceAccount, unlike a patch rule
	// that names a real Deployment or has no resourceNames at all.
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	reaches := func(names []string) bool {
		idx := NewIndex(
			[]rbacv1.Role{role("prod", "patcher", rule([]string{"apps"}, []string{"deployments"}, []string{"patch"}, names))},
			[]rbacv1.ClusterRole{admin},
			[]rbacv1.RoleBinding{roleBinding("prod", "patcher", "Role", "patcher", saSubject("prod", "attacker"))},
			[]rbacv1.ClusterRoleBinding{clusterRoleBinding("admin", "admin", saSubject("prod", "privileged"))},
			[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged")},
		)
		result := idx.AnalyzeEscalation(sa("prod", "attacker"))
		if result.ClusterAdmin != (len(result.Reached) == 1) {
			t.Fatalf("ClusterAdmin = %v with Reached = %+v, want them to agree", result.ClusterAdmin, result.Reached)
		}
		return result.ClusterAdmin
	}

	for _, tt := range []struct {
		name  string
		names []string
		want  bool
	}{
		{"literal star only", []string{"*"}, false},
		{"literal star and a valid name", []string{"*", "web"}, true},
		{"valid name", []string{"web"}, true},
		{"no resourceNames", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := reaches(tt.names); got != tt.want {
				t.Errorf("cluster-admin reachable = %v, want %v", got, tt.want)
			}
		})
	}
}
