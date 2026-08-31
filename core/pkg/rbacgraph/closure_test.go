package rbacgraph

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func sa(namespace, name string) Subject {
	return Subject{Kind: KindServiceAccount, Namespace: namespace, Name: name}
}

func saObj(namespace, name string) corev1.ServiceAccount {
	return corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
}

func role(namespace, name string, rules ...rbacv1.PolicyRule) rbacv1.Role {
	return rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Rules: rules}
}

func clusterRole(name string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func saSubject(namespace, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: namespace, Name: name}
}

func roleBinding(namespace, name, roleKind, roleName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: roleKind, Name: roleName, APIGroup: "rbac.authorization.k8s.io"},
		Subjects:   subjects,
	}
}

func clusterRoleBinding(name, clusterRoleName string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: clusterRoleName, APIGroup: "rbac.authorization.k8s.io"},
		Subjects:   subjects,
	}
}

func rule(apiGroups, resources, verbs, resourceNames []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: apiGroups, Resources: resources, Verbs: verbs, ResourceNames: resourceNames}
}

// --- DirectRules scoping ---

func TestDirectRules_ClusterRoleBindingGrantsClusterWide(t *testing.T) {
	cr := clusterRole("view", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	crb := clusterRoleBinding("crb", "view", saSubject("ns", "app"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	rules := idx.DirectRules(sa("ns", "app"))
	if len(rules) != 1 || rules[0].Namespace != "" {
		t.Fatalf("rules = %+v, want one cluster-wide (Namespace==\"\") rule", rules)
	}
}

func TestDirectRules_RoleBindingReferencingClusterRoleIsConfinedToNamespace(t *testing.T) {
	cr := clusterRole("edit", rule([]string{""}, []string{"pods"}, []string{"*"}, nil))
	rb := roleBinding("prod", "rb", "ClusterRole", "edit", saSubject("prod", "app"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, []rbacv1.RoleBinding{rb}, nil, nil)

	rules := idx.DirectRules(sa("prod", "app"))
	if len(rules) != 1 || rules[0].Namespace != "prod" {
		t.Fatalf("rules = %+v, want one rule scoped to prod (ClusterRole via RoleBinding is namespace-confined)", rules)
	}
}

func TestDirectRules_UnrelatedSubjectGetsNothing(t *testing.T) {
	cr := clusterRole("view", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	crb := clusterRoleBinding("crb", "view", saSubject("ns", "app"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	if rules := idx.DirectRules(sa("ns", "other")); len(rules) != 0 {
		t.Errorf("rules = %+v, want empty", rules)
	}
}

// --- IsClusterAdminEquivalent ---

func TestIsClusterAdminEquivalent_WildcardClusterWideIsAdmin(t *testing.T) {
	rules := []ScopedRule{{Rule: rule([]string{"*"}, []string{"*"}, []string{"*"}, nil), Namespace: ""}}
	if !IsClusterAdminEquivalent(rules) {
		t.Error("want true for a cluster-wide */*/* rule")
	}
}

func TestIsClusterAdminEquivalent_WildcardConfinedToNamespaceIsNotAdmin(t *testing.T) {
	rules := []ScopedRule{{Rule: rule([]string{"*"}, []string{"*"}, []string{"*"}, nil), Namespace: "prod"}}
	if IsClusterAdminEquivalent(rules) {
		t.Error("want false: a namespace-confined wildcard rule is not cluster-admin")
	}
}

// --- impersonate primitive ---

func TestAnalyzeEscalation_ImpersonateNamedServiceAccountReachesIt(t *testing.T) {
	attacker := clusterRole("impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"target"}))
	target := clusterRole("admin-ish", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	idx := NewIndex(
		nil,
		[]rbacv1.ClusterRole{attacker, target},
		[]rbacv1.RoleBinding{roleBinding("ns", "rb-target", "ClusterRole", "admin-ish", saSubject("ns", "target"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb-attacker", "impersonator", saSubject("ns", "attacker"))},
		[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "target")},
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if len(result.Reached) != 1 || *result.Reached[0].Edges[len(result.Reached[0].Edges)-1].ToSubject != sa("ns", "target") {
		t.Fatalf("Reached = %+v, want exactly one path ending at ns/target", result.Reached)
	}
	if result.Reached[0].Edges[0].Primitive != PrimitiveImpersonate {
		t.Errorf("Primitive = %v, want impersonate", result.Reached[0].Edges[0].Primitive)
	}
}

func TestAnalyzeEscalation_UnrestrictedImpersonateOnUsersIsUnbounded(t *testing.T) {
	cr := clusterRole("god-mode", rule([]string{""}, []string{"users"}, []string{"impersonate"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "god-mode", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if len(result.Unbounded) != 1 || result.Unbounded[0].Edge.Primitive != PrimitiveImpersonate {
		t.Fatalf("Unbounded = %+v, want one impersonate finding", result.Unbounded)
	}
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: unrestricted user impersonation is treated as cluster-wide severity")
	}
}

// --- escalate-verb primitive ---

func TestAnalyzeEscalation_EscalateAndUpdateOnClusterRolesIsClusterAdmin(t *testing.T) {
	cr := clusterRole("self-escalate", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate", "update"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "self-escalate", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: escalate+update on clusterroles cluster-wide is a full self-escalation primitive")
	}
}

func TestAnalyzeEscalation_EscalateWithoutUpdateDoesNothing(t *testing.T) {
	cr := clusterRole("half-escalate", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "half-escalate", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if result.ClusterAdmin || len(result.Unbounded) != 0 {
		t.Errorf("want no escalation without the paired update/patch verb, got ClusterAdmin=%v Unbounded=%+v", result.ClusterAdmin, result.Unbounded)
	}
}

// --- bind-verb primitive ---

func TestAnalyzeEscalation_BindClusterRoleClusterWideGrantsItsRules(t *testing.T) {
	target := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := clusterRole("binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"cluster-admin-ish"}))
	creator := clusterRole("crb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	idx := NewIndex(
		nil,
		[]rbacv1.ClusterRole{target, binder, creator},
		nil,
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("crb1", "binder", saSubject("ns", "attacker")),
			clusterRoleBinding("crb2", "crb-creator", saSubject("ns", "attacker")),
		},
		nil,
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: bind+create-clusterrolebindings lets attacker adopt a */*/* ClusterRole cluster-wide")
	}
}

func TestAnalyzeEscalation_BindRoleWithinNamespaceGrantsItsRulesConfined(t *testing.T) {
	target := role("prod", "secret-reader", rule([]string{""}, []string{"secrets"}, []string{"get", "list"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{
			target,
			role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, []string{"secret-reader"})),
			role("prod", "rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil)),
		},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("prod", "rb1", "Role", "binder", saSubject("prod", "attacker")),
			roleBinding("prod", "rb2", "Role", "rb-creator", saSubject("prod", "attacker")),
		},
		nil,
		nil,
	)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	foundSecretRead := false
	for _, sr := range result.EffectiveRules {
		if sr.Namespace == "prod" && ruleGrants(sr.Rule, "", "secrets", "get") {
			foundSecretRead = true
		}
	}
	if !foundSecretRead {
		t.Errorf("EffectiveRules = %+v, want secret-reader's rules to have been adopted", result.EffectiveRules)
	}
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, want false: this bind was confined to namespace prod, not cluster-wide")
	}
}

func TestAnalyzeEscalation_BindWithoutCreateRoleBindingDoesNothing(t *testing.T) {
	idx := NewIndex(
		[]rbacv1.Role{
			role("prod", "secret-reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
			role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, []string{"secret-reader"})),
		},
		nil,
		[]rbacv1.RoleBinding{roleBinding("prod", "rb1", "Role", "binder", saSubject("prod", "attacker"))},
		nil,
		nil,
	)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	for _, sr := range result.EffectiveRules {
		if ruleGrants(sr.Rule, "", "secrets", "get") {
			t.Errorf("EffectiveRules = %+v, want secret-reader's rules NOT adopted without create-rolebindings", result.EffectiveRules)
		}
	}
}

// --- assign-serviceaccount primitive ---

func TestAnalyzeEscalation_CreatePodsReachesEveryServiceAccountInNamespace(t *testing.T) {
	cr := clusterRole("pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil))
	crb := clusterRoleBinding("crb", "pod-creator", saSubject("prod", "attacker"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, []corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "privileged")})

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	found := false
	for _, path := range result.Reached {
		last := path.Edges[len(path.Edges)-1]
		if last.ToSubject != nil && *last.ToSubject == sa("prod", "privileged") && last.Primitive == PrimitiveAssignServiceAccount {
			found = true
		}
	}
	if !found {
		t.Errorf("Reached = %+v, want a path to prod/privileged via assign-serviceaccount", result.Reached)
	}
}

// --- mint-serviceaccount-token primitive ---

func TestAnalyzeEscalation_MintTokenForNamedServiceAccountReachesIt(t *testing.T) {
	cr := clusterRole("token-minter", rule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}, []string{"target"}))
	idx := NewIndex(
		nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "token-minter", saSubject("ns", "attacker"))},
		[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "target"), saObj("other-ns", "target")},
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	// The rule is cluster-wide (via ClusterRoleBinding) with resourceNames
	// restricting to SAs literally named "target" -- both ns/target and
	// other-ns/target match, since the rule itself carries no namespace
	// restriction beyond the object name.
	if len(result.Reached) != 2 {
		t.Fatalf("Reached = %+v, want two paths: ns/target and other-ns/target both match resourceNames=[target]", result.Reached)
	}
}

// --- multi-hop chaining ---

func TestAnalyzeEscalation_ChainedImpersonateThenBindReachesClusterAdmin(t *testing.T) {
	// attacker can impersonate "middle", who can bind+create-clusterrolebindings
	// to adopt a full cluster-admin ClusterRole. Confirms BFS actually chases
	// a second hop, not just direct escalation edges from the start subject.
	admin := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := clusterRole("binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"cluster-admin-ish"}))
	crbCreator := clusterRole("crb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	impersonator := clusterRole("impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"middle"}))

	idx := NewIndex(
		nil,
		[]rbacv1.ClusterRole{admin, binder, crbCreator, impersonator},
		nil,
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("crb-impersonator", "impersonator", saSubject("ns", "attacker")),
			clusterRoleBinding("crb-binder", "binder", saSubject("ns", "middle")),
			clusterRoleBinding("crb-creator", "crb-creator", saSubject("ns", "middle")),
		},
		[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "middle")},
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: attacker -> impersonate middle -> middle binds cluster-admin-ish -> cluster-admin")
	}
	found := false
	for _, path := range result.Reached {
		if len(path.Edges) == 1 && *path.Edges[0].ToSubject == sa("ns", "middle") {
			found = true
		}
	}
	if !found {
		t.Errorf("Reached = %+v, want a one-hop path to ns/middle", result.Reached)
	}
}

func TestAnalyzeEscalation_NoRulesReachesNothing(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, nil)
	result := idx.AnalyzeEscalation(sa("ns", "nobody"))
	if len(result.Reached) != 0 || result.ClusterAdmin || len(result.Unbounded) != 0 {
		t.Errorf("result = %+v, want a completely empty result for an unknown subject with no bindings", result)
	}
}

func TestAnalyzeEscalation_SelfReferentialCreatePodsDoesNotSelfLoop(t *testing.T) {
	// A ServiceAccount that can create pods in its own namespace (a very
	// common, benign grant) must not "reach itself" via assign-serviceaccount
	// -- that's not an escalation.
	cr := clusterRole("pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil))
	idx := NewIndex(
		nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "pod-creator", saSubject("ns", "solo"))},
		[]corev1.ServiceAccount{saObj("ns", "solo")},
	)

	result := idx.AnalyzeEscalation(sa("ns", "solo"))
	if len(result.Reached) != 0 {
		t.Errorf("Reached = %+v, want empty: the only ServiceAccount in scope is the subject itself", result.Reached)
	}
}
