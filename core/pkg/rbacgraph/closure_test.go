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

func groupSubject(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "Group", Name: name}
}

// --- matthyx's review findings on PR #3681 ---

func TestDirectRules_ImplicitServiceAccountsGroupGrantsEveryServiceAccount(t *testing.T) {
	cr := clusterRole("privileged", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	crb := clusterRoleBinding("crb", "privileged", groupSubject("system:serviceaccounts"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	rules := idx.DirectRules(sa("any-ns", "any-name"))
	if len(rules) != 1 {
		t.Fatalf("rules = %+v, want the privileged ClusterRole's rule: every ServiceAccount is implicitly a member of system:serviceaccounts", rules)
	}
}

func TestDirectRules_ImplicitNamespacedServiceAccountsGroupIsNamespaceScoped(t *testing.T) {
	cr := clusterRole("privileged", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	crb := clusterRoleBinding("crb", "privileged", groupSubject("system:serviceaccounts:prod"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	if rules := idx.DirectRules(sa("prod", "app")); len(rules) != 1 {
		t.Errorf("rules = %+v, want one rule: prod/app is a member of system:serviceaccounts:prod", rules)
	}
	if rules := idx.DirectRules(sa("other", "app")); len(rules) != 0 {
		t.Errorf("rules = %+v, want empty: other/app is not a member of system:serviceaccounts:prod", rules)
	}
}

func TestDirectRules_ImplicitAuthenticatedGroupGrantsServiceAccountsAndUsers(t *testing.T) {
	cr := clusterRole("privileged", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	crb := clusterRoleBinding("crb", "privileged", groupSubject("system:authenticated"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	if rules := idx.DirectRules(sa("ns", "app")); len(rules) != 1 {
		t.Errorf("rules = %+v, want one rule: every ServiceAccount is a member of system:authenticated", rules)
	}
	if rules := idx.DirectRules(Subject{Kind: KindUser, Name: "alice"}); len(rules) != 1 {
		t.Errorf("rules = %+v, want one rule: every authenticated User is a member of system:authenticated", rules)
	}
}

func TestAnalyzeEscalation_UnrestrictedNamespacedImpersonateEnumeratesTargets(t *testing.T) {
	// A namespace-scoped (RoleBinding-granted) unrestricted impersonate on
	// serviceaccounts must still enumerate the concrete SAs it can reach --
	// not just report Unbounded and stop, which would silently miss a
	// known SA bound to cluster-admin in the same namespace.
	admin := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	impersonator := role("prod", "impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{impersonator},
		[]rbacv1.ClusterRole{admin},
		[]rbacv1.RoleBinding{roleBinding("prod", "rb", "Role", "impersonator", saSubject("prod", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "cluster-admin-ish", saSubject("prod", "victim"))},
		[]corev1.ServiceAccount{saObj("prod", "attacker"), saObj("prod", "victim")},
	)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: unrestricted namespaced impersonate must still enumerate and reach prod/victim, who is cluster-admin")
	}
}

func TestAnalyzeEscalation_ClusterWideBindOnRolesReachesAnyNamespace(t *testing.T) {
	// bind on "roles" granted cluster-wide (via ClusterRoleBinding) is the
	// MORE powerful case (any Role in any namespace), not an edge case to
	// skip.
	target := role("prod", "secret-reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	binder := clusterRole("binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, nil))
	creator := clusterRole("rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{target},
		[]rbacv1.ClusterRole{binder, creator},
		nil,
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("crb1", "binder", saSubject("ns", "attacker")),
			clusterRoleBinding("crb2", "rb-creator", saSubject("ns", "attacker")),
		},
		nil,
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	found := false
	for _, sr := range result.EffectiveRules {
		if sr.Namespace == "prod" && ruleGrants(sr.Rule, "", "secrets", "get") {
			found = true
		}
	}
	if !found {
		t.Errorf("EffectiveRules = %+v, want secret-reader's rules adopted: cluster-wide bind+create-rolebindings reaches Roles in any namespace", result.EffectiveRules)
	}
}

func TestAnalyzeEscalation_ClusterWideCreateRoleBindingsCoversEveryNamespace(t *testing.T) {
	// The other half of the same gap: bind is namespace-scoped, but create
	// rolebindings is granted cluster-wide -- must still combine.
	target := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, []string{"cluster-admin-ish"}))
	creator := clusterRole("rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{binder},
		[]rbacv1.ClusterRole{target, creator},
		[]rbacv1.RoleBinding{roleBinding("prod", "rb", "Role", "binder", saSubject("prod", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "rb-creator", saSubject("prod", "attacker"))},
		nil,
	)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	found := false
	for _, sr := range result.EffectiveRules {
		if sr.Namespace == "prod" && ruleGrants(sr.Rule, "*", "*", "*") {
			found = true
		}
	}
	if !found {
		t.Error("want cluster-admin-ish's rules adopted within prod: the namespace-scoped bind grant must combine with the cluster-wide create-rolebindings grant, not require both to share the same scope")
	}
}

func TestAnalyzeEscalation_ImpersonateSystemMastersIsImmediateClusterAdmin(t *testing.T) {
	// system:masters is hardcoded as an omnipotent superuser by the
	// authorizer itself -- no RBAC object ever binds it, so the BFS would
	// otherwise dead-end there and report ClusterAdmin: false.
	cr := clusterRole("impersonator", rule([]string{""}, []string{"groups"}, []string{"impersonate"}, []string{"system:masters"}))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "impersonator", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: impersonating system:masters is an unconditional cluster-admin win")
	}
}

func TestAnalyzeEscalation_NamespaceScopedUserImpersonateIsNotHonored(t *testing.T) {
	// Kubernetes does not honor a namespace-scoped (RoleBinding-granted)
	// grant of impersonate on the non-namespaced "users" resource type --
	// only a cluster-wide (ClusterRoleBinding) grant is meaningful.
	r := role("ns", "impersonator", rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"alice"}))
	idx := NewIndex([]rbacv1.Role{r}, nil, []rbacv1.RoleBinding{roleBinding("ns", "rb", "Role", "impersonator", saSubject("ns", "attacker"))}, nil, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if len(result.Reached) != 0 {
		t.Errorf("Reached = %+v, want empty: a namespace-scoped grant cannot authorize impersonating a User", result.Reached)
	}
}

func TestAnalyzeEscalation_CreateRestrictedByResourceNameGrantsNothing(t *testing.T) {
	// Kubernetes cannot restrict a top-level "create" by resourceNames (the
	// object doesn't exist yet, so there's no name to match against) -- a
	// rule with resourceNames on create authorizes nothing for create, not
	// "every object of that type."
	cr := clusterRole("scoped-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, []string{"some-specific-name"}))
	idx := NewIndex(
		nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "scoped-creator", saSubject("ns", "attacker"))},
		[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "victim")},
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if len(result.Reached) != 0 {
		t.Errorf("Reached = %+v, want empty: resourceNames-restricted create authorizes nothing", result.Reached)
	}
}

func TestAnalyzeEscalation_EscalateAndUpdateOnDifferentRolesDoNotCombine(t *testing.T) {
	// escalate restricted to role-a and update restricted to role-b are two
	// unrelated grants -- neither authorizes rewriting the other's target,
	// so they must not combine into an Unbounded finding.
	roleA := role("ns", "role-a", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	roleB := role("ns", "role-b", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	escalator := role("ns", "escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, []string{"role-a"}))
	mutator := role("ns", "mutator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, []string{"role-b"}))
	idx := NewIndex(
		[]rbacv1.Role{roleA, roleB, escalator, mutator},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("ns", "rb1", "Role", "escalator", saSubject("ns", "attacker")),
			roleBinding("ns", "rb2", "Role", "mutator", saSubject("ns", "attacker")),
		},
		nil, nil,
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if result.ClusterAdmin || len(result.Unbounded) != 0 {
		t.Errorf("want no escalation: escalate on role-a and update on role-b don't authorize rewriting either role, got ClusterAdmin=%v Unbounded=%+v", result.ClusterAdmin, result.Unbounded)
	}
}

func TestAnalyzeEscalation_EscalateAndUpdateOnSameNamedRoleDoesEscalate(t *testing.T) {
	// The positive counterpart: when both grants target the SAME role by
	// name, it is exploitable.
	roleA := role("ns", "role-a", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	escalator := role("ns", "escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, []string{"role-a"}))
	mutator := role("ns", "mutator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, []string{"role-a"}))
	idx := NewIndex(
		[]rbacv1.Role{roleA, escalator, mutator},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("ns", "rb1", "Role", "escalator", saSubject("ns", "attacker")),
			roleBinding("ns", "rb2", "Role", "mutator", saSubject("ns", "attacker")),
		},
		nil, nil,
	)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if len(result.Unbounded) == 0 {
		t.Error("Unbounded = empty, want a finding: escalate and update both target role-a")
	}
}

func TestAnalyzeEscalation_TruncatedFlagSetWhenBudgetExhausted(t *testing.T) {
	orig := maxEscalationHops
	maxEscalationHops = 1
	defer func() { maxEscalationHops = orig }()

	// Two hops needed (attacker -> middle -> cluster-admin via bind), but the
	// budget only allows processing the start subject itself.
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
	if !result.Truncated {
		t.Error("Truncated = false, want true: the search ran out of budget before confirming ClusterAdmin one way or the other")
	}
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, but Truncated should mean this specific run didn't confirm it -- test setup contradiction")
	}
}

func TestAnalyzeEscalation_NotTruncatedWhenClusterAdminConfirmedBeforeBudgetExhausted(t *testing.T) {
	orig := maxEscalationHops
	maxEscalationHops = 1
	defer func() { maxEscalationHops = orig }()

	cr := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "cluster-admin-ish", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if result.Truncated {
		t.Error("Truncated = true, want false: ClusterAdmin was confirmed directly from the start subject's own rules, before the budget mattered")
	}
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true")
	}
}

// --- matthyx's second review pass on PR #3681 ---

func TestAnalyzeEscalation_ScopedUnboundedEdgeIsReQueuedForMultiHopEscalation(t *testing.T) {
	// Concrete scenario from review: dev/attacker holds escalate+update on
	// Role dev/editable (a namespace-scoped Unbounded finding) and is also
	// bound to dev/editable itself. In reality, attacker rewrites editable
	// to add create-pods, then schedules a pod as dev/privileged (bound
	// cluster-wide to a full ClusterRole) to inherit its token. A scoped
	// Unbounded finding that isn't fed back into the traversal misses this
	// entirely.
	editable := role("dev", "editable", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
	escalator := role("dev", "escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "update"}, []string{"editable"}))
	privileged := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{editable, escalator},
		[]rbacv1.ClusterRole{privileged},
		[]rbacv1.RoleBinding{
			roleBinding("dev", "rb1", "Role", "editable", saSubject("dev", "attacker")),
			roleBinding("dev", "rb2", "Role", "escalator", saSubject("dev", "attacker")),
		},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "cluster-admin-ish", saSubject("dev", "privileged"))},
		[]corev1.ServiceAccount{saObj("dev", "attacker"), saObj("dev", "privileged")},
	)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: the scoped Unbounded finding (escalate+update on dev/editable) must be chased -- it unlocks create-pods in dev, which reaches dev/privileged")
	}
}

func TestAnalyzeEscalation_EscalateTargetNotInIndexFallsBackToScopeUnbounded(t *testing.T) {
	// Concrete scenario from review: escalate+update on clusterroles,
	// cluster-wide, restricted to a resourceName that resolves to no
	// object this Index actually collected (stale name, or a partial/
	// paginated collection gap). Silently emitting nothing here would be a
	// regression from the pre-name-correlation behavior, which reported a
	// scope-level Unbounded (cluster-wide -> ClusterAdmin) in this case --
	// failing toward risk, not silence, matches this package's own
	// documented trust model.
	cr := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"escalate", "update"}, []string{"does-not-exist"}))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "escalator", saSubject("ns", "attacker"))}, nil)

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: an unresolvable escalate+update target must fall back to a scope-level Unbounded finding, not silence")
	}
	if len(result.Unbounded) == 0 {
		t.Error("Unbounded = empty, want the fallback finding recorded")
	}
}
