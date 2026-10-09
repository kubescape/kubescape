package rbacgraph

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
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

// --- deterministic ordering ---

// escalationFingerprint renders everything a caller can observe about a
// result's ordering: the reached identities in order, the edges of each path,
// and the unbounded findings.
func escalationFingerprint(r EscalationResult) string {
	var b strings.Builder
	for _, p := range r.Reached {
		for _, e := range p.Edges {
			b.WriteString(string(e.Primitive) + "|" + e.Detail + "\n")
		}
		b.WriteString("--\n")
	}
	for _, f := range r.Unbounded {
		b.WriteString(f.Subject.String() + "|" + f.Edge.Detail + "\n")
	}
	return b.String()
}

func TestAnalyzeEscalation_ClusterWideGrantEnumeratesNamespacesInStableOrder(t *testing.T) {
	// A cluster-wide "create pods" grant enumerates every namespace the
	// Index has ServiceAccounts for. That list came straight out of a map,
	// so the reported escalation paths arrived in a different order on
	// every run and two scans of one unchanged cluster never matched.
	cr := clusterRole("pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil))
	crb := clusterRoleBinding("crb", "pod-creator", saSubject("home", "attacker"))
	accounts := []corev1.ServiceAccount{
		saObj("home", "attacker"),
		saObj("delta", "d1"),
		saObj("alpha", "a1"),
		saObj("charlie", "c1"),
		saObj("bravo", "b1"),
		saObj("echo", "e1"),
	}
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, accounts)

	want := escalationFingerprint(idx.AnalyzeEscalation(sa("home", "attacker")))
	for i := 1; i < 25; i++ {
		if got := escalationFingerprint(idx.AnalyzeEscalation(sa("home", "attacker"))); got != want {
			t.Fatalf("run %d differs from run 0:\nfirst:\n%s\ngot:\n%s", i, want, got)
		}
	}

	namespaces := idx.targetNamespaces("")
	if !sort.StringsAreSorted(namespaces) {
		t.Errorf("targetNamespaces(\"\") = %v, want sorted", namespaces)
	}
}

func TestAnalyzeEscalation_BindableRolesAndClusterRolesAreEnumeratedInStableOrder(t *testing.T) {
	// bind-verb walks the collected Roles and ClusterRoles, both stored in
	// maps, so the edges it emits carried map order into the report too.
	binder := clusterRole("binder",
		rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles", "roles"}, []string{"bind"}, nil),
		rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings", "clusterrolebindings"}, []string{"create"}, nil),
	)
	get := rule([]string{""}, []string{"pods"}, []string{"get"}, nil)
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "zeta", get), role("dev", "alpha", get), role("prod", "mu", get), role("prod", "beta", get)},
		[]rbacv1.ClusterRole{binder, clusterRole("zulu", get), clusterRole("kilo", get), clusterRole("alfa", get)},
		nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "binder", saSubject("dev", "attacker"))},
		[]corev1.ServiceAccount{saObj("dev", "attacker")},
	)

	want := escalationFingerprint(idx.AnalyzeEscalation(sa("dev", "attacker")))
	for i := 1; i < 25; i++ {
		if got := escalationFingerprint(idx.AnalyzeEscalation(sa("dev", "attacker"))); got != want {
			t.Fatalf("run %d differs from run 0:\nfirst:\n%s\ngot:\n%s", i, want, got)
		}
	}

	var clusterRoleNames []string
	for _, cr := range idx.matchingClusterRoles(nil, false) {
		clusterRoleNames = append(clusterRoleNames, cr.Name)
	}
	if !sort.StringsAreSorted(clusterRoleNames) {
		t.Errorf("matchingClusterRoles = %v, want sorted by name", clusterRoleNames)
	}

	var roleKeys []string
	for _, r := range idx.matchingRolesAnyNamespace(nil, false) {
		roleKeys = append(roleKeys, roleKey(r.Namespace, r.Name))
	}
	if !sort.StringsAreSorted(roleKeys) {
		t.Errorf("matchingRolesAnyNamespace = %v, want sorted by namespace/name", roleKeys)
	}
}

func TestFromResources_ConvertsInResourceIDOrder(t *testing.T) {
	// FromResources reads a map, and everything it returns becomes Index
	// state that the report's ordering depends on.
	resources := map[string]workloadinterface.IMetadata{}
	for _, name := range []string{"zeta", "alpha", "mu", "beta", "kilo"} {
		obj := workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1",
			"kind":       "ServiceAccount",
			"metadata":   map[string]any{"name": name, "namespace": "dev"},
		})
		resources[obj.GetID()] = obj
	}

	var want []string
	for i := 0; i < 25; i++ {
		_, _, _, _, serviceAccounts, errs := FromResources(resources)
		if len(errs) != 0 {
			t.Fatalf("errs = %v, want none", errs)
		}
		got := make([]string, 0, len(serviceAccounts))
		for _, sa := range serviceAccounts {
			got = append(got, sa.Name)
		}
		if i == 0 {
			want = got
			continue
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d = %v, want %v (same order every run)", i, got, want)
		}
	}
}

// --- ServiceAccount subjects without a namespace ---

// A RoleBinding may name a ServiceAccount without a namespace; the API server
// admits it and resolves the subject in the RoleBinding's own namespace
// (appliesToUser in pkg/registry/rbac/validation). It is a common way to
// write a binding for a ServiceAccount that lives next to it.
func TestDirectRules_UnqualifiedServiceAccountSubjectIsInTheRoleBindingNamespace(t *testing.T) {
	cr := clusterRole("secrets-admin", rule([]string{""}, []string{"secrets"}, []string{"*"}, nil))
	rb := roleBinding("payments", "rb", "ClusterRole", "secrets-admin", saSubject("", "worker"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, []rbacv1.RoleBinding{rb}, nil, nil)

	rules := idx.DirectRules(sa("payments", "worker"))
	if len(rules) != 1 || rules[0].Namespace != "payments" {
		t.Fatalf("rules = %+v, want the secrets rule scoped to payments", rules)
	}
	if rules := idx.DirectRules(sa("billing", "worker")); len(rules) != 0 {
		t.Errorf("rules = %+v, want none for a same-named ServiceAccount in another namespace", rules)
	}
}

func TestDirectRules_QualifiedServiceAccountSubjectIsNotMovedToTheRoleBindingNamespace(t *testing.T) {
	r := role("payments", "secrets-admin", rule([]string{""}, []string{"secrets"}, []string{"*"}, nil))
	rb := roleBinding("payments", "rb", "Role", "secrets-admin", saSubject("billing", "worker"))
	idx := NewIndex([]rbacv1.Role{r}, nil, []rbacv1.RoleBinding{rb}, nil, nil)

	if rules := idx.DirectRules(sa("billing", "worker")); len(rules) != 1 {
		t.Errorf("rules = %+v, want the rule for the ServiceAccount the subject names", rules)
	}
	if rules := idx.DirectRules(sa("payments", "worker")); len(rules) != 0 {
		t.Errorf("rules = %+v, want none: the subject names billing/worker", rules)
	}
}

// A ClusterRoleBinding has no namespace to resolve the subject in. The API
// server rejects such a subject on write and never matches one, so a manifest
// carrying it grants nothing.
func TestDirectRules_UnqualifiedServiceAccountSubjectInClusterRoleBindingGrantsNothing(t *testing.T) {
	cr := clusterRole("secrets-admin", rule([]string{""}, []string{"secrets"}, []string{"*"}, nil))
	crb := clusterRoleBinding("crb", "secrets-admin", saSubject("", "worker"))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil, []rbacv1.ClusterRoleBinding{crb}, nil)

	for _, subject := range []Subject{sa("payments", "worker"), sa("", "worker")} {
		if rules := idx.DirectRules(subject); len(rules) != 0 {
			t.Errorf("DirectRules(%s) = %+v, want none", subject, rules)
		}
	}
}

func TestAnalyzeEscalation_UnqualifiedServiceAccountSubjectStartsAPath(t *testing.T) {
	r := role("payments", "pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil))
	rb := roleBinding("payments", "rb", "Role", "pod-creator", saSubject("", "worker"))
	idx := NewIndex([]rbacv1.Role{r}, nil, []rbacv1.RoleBinding{rb}, nil,
		[]corev1.ServiceAccount{saObj("payments", "worker"), saObj("payments", "privileged")})

	result := idx.AnalyzeEscalation(sa("payments", "worker"))
	found := false
	for _, path := range result.Reached {
		last := path.Edges[len(path.Edges)-1]
		if last.ToSubject != nil && *last.ToSubject == sa("payments", "privileged") && last.Primitive == PrimitiveAssignServiceAccount {
			found = true
		}
	}
	if !found {
		t.Errorf("Reached = %+v, want a path to payments/privileged via assign-serviceaccount", result.Reached)
	}
}

// --- Kubernetes parity (see core/pkg/rbacgraph/parity) ---
//
// The cases below are also fixtures in the parity package, where the expected
// answer is checked against a real kube-apiserver. They are repeated here as
// plain unit tests of the functions that decide them.

func mintsTokenFor(result EscalationResult, target Subject) bool {
	for _, path := range result.Reached {
		last := path.Edges[len(path.Edges)-1]
		if last.Primitive == PrimitiveMintServiceAccountToken && last.ToSubject != nil && *last.ToSubject == target {
			return true
		}
	}
	return false
}

func TestAnalyzeEscalation_WildcardSubresourceRuleMintsToken(t *testing.T) {
	// "*/token" names the token subresource of every resource, which includes
	// serviceaccounts/token (ResourceMatches in Kubernetes).
	r := role("ns", "minter", rule([]string{""}, []string{"*/token"}, []string{"create"}, nil))
	idx := NewIndex([]rbacv1.Role{r}, nil,
		[]rbacv1.RoleBinding{roleBinding("ns", "rb", "Role", "minter", saSubject("ns", "attacker"))}, nil,
		[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "target")})

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if !mintsTokenFor(result, sa("ns", "target")) {
		t.Errorf("Reached = %+v, want a mint-serviceaccount-token path to ns/target: */token covers serviceaccounts/token", result.Reached)
	}
}

func TestAnalyzeEscalation_WildcardRuleForAnotherSubresourceDoesNotMintToken(t *testing.T) {
	for _, resource := range []string{"*/status", "serviceaccounts/status", "serviceaccounts", "*/tokens"} {
		t.Run(resource, func(t *testing.T) {
			r := role("ns", "other", rule([]string{""}, []string{resource}, []string{"create"}, nil))
			idx := NewIndex([]rbacv1.Role{r}, nil,
				[]rbacv1.RoleBinding{roleBinding("ns", "rb", "Role", "other", saSubject("ns", "attacker"))}, nil,
				[]corev1.ServiceAccount{saObj("ns", "attacker"), saObj("ns", "target")})

			if result := idx.AnalyzeEscalation(sa("ns", "attacker")); len(result.Reached) != 0 {
				t.Errorf("Reached = %+v, want empty: %q does not grant serviceaccounts/token", result.Reached, resource)
			}
		})
	}
}

func userSubject(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "User", Name: name, APIGroup: "rbac.authorization.k8s.io"}
}

func TestDirectRules_UserSubjectWithServiceAccountUsernameIsThatServiceAccount(t *testing.T) {
	// A ServiceAccount authenticates as system:serviceaccount:<ns>:<name>, and
	// a User subject is matched against the authenticated username.
	cr := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr},
		[]rbacv1.RoleBinding{roleBinding("payments", "rb", "ClusterRole", "reader", userSubject("system:serviceaccount:payments:worker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "reader", userSubject("system:serviceaccount:payments:auditor"))},
		nil)

	if rules := idx.DirectRules(sa("payments", "worker")); len(rules) != 1 || rules[0].Namespace != "payments" {
		t.Errorf("DirectRules(payments/worker) = %+v, want the RoleBinding's rule, confined to payments", rules)
	}
	if rules := idx.DirectRules(sa("payments", "auditor")); len(rules) != 1 || rules[0].Namespace != "" {
		t.Errorf("DirectRules(payments/auditor) = %+v, want the ClusterRoleBinding's rule, cluster-wide", rules)
	}
}

func TestDirectRules_UserSubjectWithAnotherServiceAccountUsernameGrantsNothing(t *testing.T) {
	cr := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "reader",
			userSubject("system:serviceaccount:payments:worker"),
			// Not a ServiceAccount username at all: no namespace separator.
			userSubject("system:serviceaccount:billing"),
			userSubject("billing"),
		)},
		nil)

	for _, other := range []Subject{sa("billing", "worker"), sa("payments", "billing"), sa("payments", "worker2"), sa("system:serviceaccount", "billing")} {
		if rules := idx.DirectRules(other); len(rules) != 0 {
			t.Errorf("DirectRules(%s) = %+v, want none: the User subjects name a different identity", other, rules)
		}
	}
}

// roleEscalationFindings returns the Scope of every escalate-verb finding on
// Roles, sorted.
func roleEscalationFindings(result EscalationResult) []string {
	var scopes []string
	for _, f := range result.Unbounded {
		if f.Edge.Primitive == PrimitiveEscalateVerb && f.Edge.Target != nil && f.Edge.Target.Kind == "Role" {
			scopes = append(scopes, f.Edge.Scope)
		}
	}
	sort.Strings(scopes)
	return scopes
}

func TestAnalyzeEscalation_ClusterWideEscalateCombinesWithNamespacedUpdate(t *testing.T) {
	// The API server authorizes escalate and update as two separate requests
	// in the Role's namespace; a cluster-wide grant answers either of them.
	escalate := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, nil))
	update := clusterRole("updater", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "editable")},
		[]rbacv1.ClusterRole{escalate, update},
		[]rbacv1.RoleBinding{roleBinding("dev", "rb", "ClusterRole", "updater", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "escalator", saSubject("dev", "attacker"))},
		nil)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if got := roleEscalationFindings(result); !slices.Equal(got, []string{"dev"}) {
		t.Errorf("escalate-verb findings on Roles have scopes %v, want [dev]: cluster-wide escalate + update in dev lets attacker rewrite Roles in dev", got)
	}
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, want false: the update half is confined to dev")
	}
}

func TestAnalyzeEscalation_NamespacedEscalateCombinesWithClusterWideUpdate(t *testing.T) {
	escalate := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, nil))
	patch := clusterRole("patcher", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"patch"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "editable")},
		[]rbacv1.ClusterRole{escalate, patch},
		[]rbacv1.RoleBinding{roleBinding("dev", "rb", "ClusterRole", "escalator", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "patcher", saSubject("dev", "attacker"))},
		nil)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if got := roleEscalationFindings(result); !slices.Equal(got, []string{"dev"}) {
		t.Errorf("escalate-verb findings on Roles have scopes %v, want [dev]: escalate in dev + cluster-wide patch lets attacker rewrite Roles in dev", got)
	}
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, want false: the escalate half is confined to dev")
	}
}

func TestAnalyzeEscalation_EscalateAndUpdateInDifferentNamespacesDoNotCombine(t *testing.T) {
	escalate := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, nil))
	update := clusterRole("updater", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, nil))
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "editable"), role("staging", "editable")},
		[]rbacv1.ClusterRole{escalate, update},
		[]rbacv1.RoleBinding{
			roleBinding("dev", "rb", "ClusterRole", "escalator", saSubject("dev", "attacker")),
			roleBinding("staging", "rb", "ClusterRole", "updater", saSubject("dev", "attacker")),
		},
		nil, nil)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if got := roleEscalationFindings(result); len(got) != 0 {
		t.Errorf("escalate-verb findings on Roles have scopes %v, want none: escalate in dev and update in staging never meet on one Role", got)
	}
}

func TestAnalyzeEscalation_SplitScopeEscalateAndUpdateStillCorrelateByRoleName(t *testing.T) {
	// The name correlation holds across scopes too: cluster-wide escalate on
	// role-a and update in dev on role-b authorize rewriting neither.
	escalate := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, []string{"role-a"}))
	update := clusterRole("updater", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, []string{"role-b"}))
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "role-a"), role("dev", "role-b")},
		[]rbacv1.ClusterRole{escalate, update},
		[]rbacv1.RoleBinding{roleBinding("dev", "rb", "ClusterRole", "updater", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "escalator", saSubject("dev", "attacker"))},
		nil)

	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if len(result.Unbounded) != 0 {
		t.Errorf("Unbounded = %+v, want empty: the two grants name different Roles", result.Unbounded)
	}
}

func TestAnalyzeEscalation_SplitScopeEscalateIsChasedInEveryNamespace(t *testing.T) {
	// Cluster-wide escalate + update in both a and z is one escalate-verb edge
	// per namespace, and the two differ in nothing but Scope: their Detail is
	// the same text. The closure has to keep them apart. The only privileged
	// identity here is z/admin, so a closure that takes the z edge for a
	// repeat of the a edge never materializes the grant in z and reports a
	// clean negative.
	escalate := clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate"}, nil))
	update := clusterRole("updater", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"update"}, nil))
	admin := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	owned := rule([]string{""}, []string{"configmaps"}, []string{"get"}, nil)
	idx := NewIndex(
		[]rbacv1.Role{role("a", "owned", owned), role("z", "owned", owned)},
		[]rbacv1.ClusterRole{escalate, update, admin},
		[]rbacv1.RoleBinding{
			roleBinding("a", "update", "ClusterRole", "updater", saSubject("a", "attacker")),
			roleBinding("z", "update", "ClusterRole", "updater", saSubject("a", "attacker")),
			roleBinding("a", "owned", "Role", "owned", saSubject("a", "attacker")),
			roleBinding("z", "owned", "Role", "owned", saSubject("a", "attacker")),
		},
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("escalate", "escalator", saSubject("a", "attacker")),
			clusterRoleBinding("admin", "cluster-admin-ish", saSubject("z", "admin")),
		},
		[]corev1.ServiceAccount{saObj("a", "attacker"), saObj("z", "admin")},
	)

	result := idx.AnalyzeEscalation(sa("a", "attacker"))
	if got := roleEscalationFindings(result); !slices.Equal(got, []string{"a", "z"}) {
		t.Errorf("escalate-verb findings on Roles have scopes %v, want [a z]: one finding per namespace the grant reaches", got)
	}
	reachedAdmin := false
	for _, p := range result.Reached {
		if last := p.Edges[len(p.Edges)-1]; last.ToSubject != nil && *last.ToSubject == sa("z", "admin") {
			reachedAdmin = true
		}
	}
	if !reachedAdmin {
		t.Errorf("Reached = %+v, want a path to ServiceAccount z/admin: rewriting a Role in z unlocks create-pods there", result.Reached)
	}
	if !result.ClusterAdmin {
		t.Error("ClusterAdmin = false, want true: z/admin is bound to a cluster-wide */*/* rule")
	}
}

func TestDirectEscalationEdges_UnfoundEscalateTargetKeepsItsResourceNames(t *testing.T) {
	// escalate + update restricted to a name that resolves to nothing in the
	// snapshot is still reported, as an Unbounded finding: the object may only
	// be missing from a partial collection. But the grant is no wider for
	// that. Its Target has to go on naming the object, or a caller asking
	// about an unrelated one that does exist is told it is covered.
	names := []string{"missing"}
	rbacRule := func(resource string) rbacv1.PolicyRule {
		return rule([]string{"rbac.authorization.k8s.io"}, []string{resource}, []string{"escalate", "update"}, names)
	}
	idx := NewIndex(
		[]rbacv1.Role{role("dev", "editable"), role("dev", "namespaced", rbacRule("roles"))},
		[]rbacv1.ClusterRole{clusterRole("existing"), clusterRole("cluster-wide", rbacRule("roles"), rbacRule("clusterroles"))},
		[]rbacv1.RoleBinding{roleBinding("dev", "rb", "Role", "namespaced", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "cluster-wide", saSubject("dev", "attacker"))},
		nil)

	type key struct {
		target RoleTarget
		scope  string
	}
	got := map[key]bool{}
	for _, e := range idx.DirectEscalationEdges(sa("dev", "attacker"), idx.DirectRules(sa("dev", "attacker"))) {
		if e.Primitive != PrimitiveEscalateVerb {
			continue
		}
		if !e.Unbounded {
			t.Errorf("edge %q is not Unbounded: the fallback has to stay a risk finding", e.Detail)
		}
		if e.Target == nil {
			t.Fatalf("edge %q has no Target", e.Detail)
		}
		got[key{*e.Target, e.Scope}] = true
		if e.Target.Covers("Role", "dev", "editable") || e.Target.Covers("ClusterRole", "", "existing") {
			t.Errorf("edge %q has Target %+v, which covers an object the grant does not name", e.Detail, *e.Target)
		}
	}
	for _, want := range []key{
		// The Role grant held in dev, and the one held cluster-wide.
		{RoleTarget{Kind: "Role", Namespace: "dev", Name: "missing"}, "dev"},
		{RoleTarget{Kind: "Role", Name: "missing"}, ""},
		{RoleTarget{Kind: "ClusterRole", Name: "missing"}, ""},
	} {
		if !got[want] {
			t.Errorf("no escalate-verb edge with Target %+v and Scope %q; got %+v", want.target, want.scope, got)
		}
	}
}

func TestAnalyzeEscalation_NamespacedBindDoesNotAllowAClusterRoleBinding(t *testing.T) {
	// bind is checked in the namespace of the binding being created, and a
	// ClusterRoleBinding has none: a bind grant from a RoleBinding cannot
	// authorize it, however the right to create ClusterRoleBindings was held.
	target := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := clusterRole("binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, nil))
	creator := clusterRole("crb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}, nil))
	idx := NewIndex(nil,
		[]rbacv1.ClusterRole{target, binder, creator},
		[]rbacv1.RoleBinding{roleBinding("prod", "rb", "ClusterRole", "binder", saSubject("prod", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "crb-creator", saSubject("prod", "attacker"))},
		nil)

	result := idx.AnalyzeEscalation(sa("prod", "attacker"))
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, want false: bind is held only in prod, so the API server refuses the ClusterRoleBinding")
	}
	for _, sr := range result.EffectiveRules {
		if ruleGrants(sr.Rule, "*", "*", "*") {
			t.Errorf("EffectiveRules contains %+v, want no adopted wildcard rule: attacker cannot create RoleBindings anywhere either", sr)
		}
	}
}

func TestAnalyzeEscalation_NamespacedBindDoesNotAllowARoleBindingInAnotherNamespace(t *testing.T) {
	target := clusterRole("cluster-admin-ish", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	binder := clusterRole("binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind"}, nil))
	creator := clusterRole("rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil))
	idx := NewIndex(nil,
		[]rbacv1.ClusterRole{target, binder, creator},
		[]rbacv1.RoleBinding{
			roleBinding("prod", "bind", "ClusterRole", "binder", saSubject("prod", "attacker"), saSubject("prod", "everywhere")),
			roleBinding("staging", "create", "ClusterRole", "rb-creator", saSubject("prod", "attacker")),
		},
		// Cluster-wide create on rolebindings does not widen the bind grant
		// either: it combines with it in prod and nowhere else.
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "rb-creator", saSubject("prod", "everywhere"))},
		nil)

	if result := idx.AnalyzeEscalation(sa("prod", "attacker")); len(result.EffectiveRules) != 2 {
		t.Errorf("EffectiveRules = %+v, want only attacker's own two rules: bind in prod and create rolebindings in staging do not combine", result.EffectiveRules)
	}

	adopted := map[string]bool{}
	for _, sr := range idx.AnalyzeEscalation(sa("prod", "everywhere")).EffectiveRules {
		if ruleGrants(sr.Rule, "*", "*", "*") {
			adopted[sr.Namespace] = true
		}
	}
	if !adopted["prod"] || len(adopted) != 1 {
		t.Errorf("wildcard rule adopted in namespaces %v, want prod only: the bind grant is confined to prod", adopted)
	}
}

func TestDirectEscalationEdges_BindAndEscalateEdgesNameTheirTarget(t *testing.T) {
	rbacRule := func(resource string, verbs ...string) rbacv1.PolicyRule {
		return rule([]string{"rbac.authorization.k8s.io"}, []string{resource}, verbs, nil)
	}
	power := clusterRole("power",
		rbacRule("clusterroles", "bind", "escalate", "update"),
		rbacRule("roles", "bind"),
		rbacRule("clusterrolebindings", "create"),
		rbacRule("rolebindings", "create"),
	)
	editor := role("dev", "editor", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "patch"}, []string{"editable"}))
	idx := NewIndex(
		[]rbacv1.Role{editor, role("dev", "editable")},
		[]rbacv1.ClusterRole{power},
		[]rbacv1.RoleBinding{roleBinding("dev", "rb", "Role", "editor", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "power", saSubject("dev", "attacker"))},
		nil)

	type key struct {
		primitive EscalationPrimitive
		target    RoleTarget
		scope     string
	}
	got := map[key]bool{}
	for _, e := range idx.DirectEscalationEdges(sa("dev", "attacker"), idx.DirectRules(sa("dev", "attacker"))) {
		if e.Primitive != PrimitiveBindVerb && e.Primitive != PrimitiveEscalateVerb {
			continue
		}
		if e.Target == nil {
			t.Fatalf("edge %q has no Target", e.Detail)
		}
		got[key{e.Primitive, *e.Target, e.Scope}] = true
	}

	for _, want := range []key{
		// Unrestricted escalate + update on clusterroles: every ClusterRole.
		{PrimitiveEscalateVerb, RoleTarget{Kind: "ClusterRole"}, ""},
		// escalate + patch on the Role named editable, in dev.
		{PrimitiveEscalateVerb, RoleTarget{Kind: "Role", Namespace: "dev", Name: "editable"}, "dev"},
		// A ClusterRole bound by a ClusterRoleBinding, and by a RoleBinding in dev.
		{PrimitiveBindVerb, RoleTarget{Kind: "ClusterRole", Name: "power"}, ""},
		{PrimitiveBindVerb, RoleTarget{Kind: "ClusterRole", Name: "power"}, "dev"},
		// A Role bound by a RoleBinding in its own namespace.
		{PrimitiveBindVerb, RoleTarget{Kind: "Role", Namespace: "dev", Name: "editable"}, "dev"},
	} {
		if !got[want] {
			t.Errorf("no %s edge with Target %+v and Scope %q; got %+v", want.primitive, want.target, want.scope, got)
		}
	}
}

func TestRoleTargetCovers(t *testing.T) {
	cases := []struct {
		target                RoleTarget
		kind, namespace, name string
		want                  bool
	}{
		{RoleTarget{Kind: "Role", Namespace: "dev", Name: "a"}, "Role", "dev", "a", true},
		{RoleTarget{Kind: "Role", Namespace: "dev", Name: "a"}, "Role", "dev", "b", false},
		{RoleTarget{Kind: "Role", Namespace: "dev", Name: "a"}, "Role", "prod", "a", false},
		{RoleTarget{Kind: "Role", Namespace: "dev"}, "Role", "dev", "anything", true},
		{RoleTarget{Kind: "Role", Namespace: "dev"}, "Role", "prod", "anything", false},
		{RoleTarget{Kind: "Role"}, "Role", "prod", "anything", true},
		{RoleTarget{Kind: "ClusterRole", Name: "a"}, "ClusterRole", "", "a", true},
		{RoleTarget{Kind: "ClusterRole"}, "Role", "dev", "a", false},
		{RoleTarget{Kind: "Role"}, "ClusterRole", "", "a", false},
	}
	for _, tc := range cases {
		if got := tc.target.Covers(tc.kind, tc.namespace, tc.name); got != tc.want {
			t.Errorf("%+v.Covers(%q, %q, %q) = %v, want %v", tc.target, tc.kind, tc.namespace, tc.name, got, tc.want)
		}
	}
}

func TestDirectRules_ServiceAccountSubjectAppliesToAUserWithItsUsername(t *testing.T) {
	// The reverse of the case above. The authorizer matches a ServiceAccount
	// subject against the requester's username, so it applies to a User asked
	// about under that username, which is how an audit log writes the
	// identity.
	cr := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr},
		[]rbacv1.RoleBinding{
			roleBinding("payments", "by-kind", "ClusterRole", "reader", saSubject("payments", "worker")),
			roleBinding("payments", "by-kind-unqualified", "ClusterRole", "reader", saSubject("", "worker")),
			roleBinding("payments", "by-username", "ClusterRole", "reader", userSubject("system:serviceaccount:payments:worker")),
		},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("by-kind-cluster-wide", "reader", saSubject("payments", "worker"))},
		nil)

	asUser := Subject{Kind: KindUser, Name: "system:serviceaccount:payments:worker"}
	got, want := idx.DirectRules(asUser), idx.DirectRules(sa("payments", "worker"))
	if len(want) != 4 {
		t.Fatalf("DirectRules(payments/worker) = %+v, want the rule of all four bindings", want)
	}
	if !slices.EqualFunc(got, want, func(a, b ScopedRule) bool { return a.Namespace == b.Namespace }) {
		t.Errorf("DirectRules(%s) = %+v, want the same rules the ServiceAccount holds through User and ServiceAccount subjects: %+v", asUser, got, want)
	}
}

func TestDirectRules_UserWithServiceAccountUsernameIsNotGivenServiceAccountGroups(t *testing.T) {
	// The username is all the two share. system:serviceaccounts and
	// system:serviceaccounts:<namespace> are assigned by the ServiceAccount
	// token authenticator; the API server does not infer them from a username,
	// so a requester that carries the name without them is not granted what is
	// bound to those groups.
	cr := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	group := func(name string) rbacv1.Subject { return rbacv1.Subject{Kind: "Group", Name: name} }
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr}, nil,
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("all-serviceaccounts", "reader", group("system:serviceaccounts")),
			clusterRoleBinding("namespace-serviceaccounts", "reader", group("system:serviceaccounts:payments")),
		},
		nil)

	if rules := idx.DirectRules(sa("payments", "worker")); len(rules) != 2 {
		t.Fatalf("DirectRules(payments/worker) = %+v, want both group bindings: the ServiceAccount is in those groups", rules)
	}
	asUser := Subject{Kind: KindUser, Name: "system:serviceaccount:payments:worker"}
	if rules := idx.DirectRules(asUser); len(rules) != 0 {
		t.Errorf("DirectRules(%s) = %+v, want none: a User is not a member of the ServiceAccount groups", asUser, rules)
	}
}

func TestDirectRules_ServiceAccountSubjectDoesNotApplyToOtherUsernames(t *testing.T) {
	cr := clusterRole("reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{cr},
		[]rbacv1.RoleBinding{
			roleBinding("payments", "by-kind", "ClusterRole", "reader", saSubject("payments", "worker")),
			roleBinding("payments", "by-kind-unqualified", "ClusterRole", "reader", saSubject("", "worker")),
		},
		// An unqualified ServiceAccount subject in a ClusterRoleBinding names
		// nobody, under any spelling.
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("unqualified", "reader", saSubject("", "worker"))},
		nil)

	for _, name := range []string{
		"worker",
		"payments:worker",
		"system:serviceaccount:payments",
		"system:serviceaccount:payments:worker:extra",
		"system:serviceaccount:payments:worker2",
		"system:serviceaccount:billing:worker", // same name, another namespace
		"system:serviceaccount:Payments:worker",
		"system:serviceaccounts:payments:worker",
		"system:serviceaccount::worker",
	} {
		if rules := idx.DirectRules(Subject{Kind: KindUser, Name: name}); len(rules) != 0 {
			t.Errorf("DirectRules(User %q) = %+v, want none: it is not the username of payments/worker", name, rules)
		}
	}
	// And the kind matters: a Group of that name is not the ServiceAccount.
	if rules := idx.DirectRules(Subject{Kind: KindGroup, Name: "system:serviceaccount:payments:worker"}); len(rules) != 0 {
		t.Errorf("DirectRules(Group) = %+v, want none", rules)
	}
}

func TestAnalyzeEscalation_UserWithServiceAccountUsernameFollowsServiceAccountSubjects(t *testing.T) {
	r := role("payments", "impersonator", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"privileged"}))
	idx := NewIndex([]rbacv1.Role{r}, nil,
		[]rbacv1.RoleBinding{roleBinding("payments", "rb", "Role", "impersonator", saSubject("payments", "worker"))}, nil,
		[]corev1.ServiceAccount{saObj("payments", "worker"), saObj("payments", "privileged")})

	start := Subject{Kind: KindUser, Name: "system:serviceaccount:payments:worker"}
	result := idx.AnalyzeEscalation(start)
	if result.Start != start {
		t.Errorf("Start = %s, want %s: the identity asked about is reported as it was asked", result.Start, start)
	}
	if len(result.Reached) != 1 || *result.Reached[0].Edges[0].ToSubject != sa("payments", "privileged") {
		t.Errorf("Reached = %+v, want exactly one path, to payments/privileged", result.Reached)
	}
}

func TestAnalyzeEscalation_ImpersonateOnUsersDoesNotReachAServiceAccountUsername(t *testing.T) {
	// The API server authorizes impersonating system:serviceaccount:<ns>:<name>
	// against the serviceaccounts resource. A grant on users naming that
	// username authorizes nothing, so it must not lead to the ServiceAccount.
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	onUsers := clusterRole("impersonate-users", rule([]string{""}, []string{"users"}, []string{"impersonate"}, []string{"system:serviceaccount:prod:privileged", "alice"}))
	onServiceAccounts := clusterRole("impersonate-serviceaccounts", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"privileged"}))
	idx := NewIndex(nil,
		[]rbacv1.ClusterRole{admin, onUsers, onServiceAccounts},
		nil,
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("admin", "admin", saSubject("prod", "privileged")),
			clusterRoleBinding("users", "impersonate-users", saSubject("ns", "attacker")),
			clusterRoleBinding("serviceaccounts", "impersonate-serviceaccounts", saSubject("ns", "control")),
		},
		[]corev1.ServiceAccount{saObj("prod", "privileged")})

	result := idx.AnalyzeEscalation(sa("ns", "attacker"))
	if result.ClusterAdmin {
		t.Error("ClusterAdmin = true, want false: impersonate on users does not authorize impersonating a ServiceAccount username")
	}
	if len(result.Reached) != 1 || *result.Reached[0].Edges[0].ToSubject != (Subject{Kind: KindUser, Name: "alice"}) {
		t.Errorf("Reached = %+v, want only User alice", result.Reached)
	}

	if control := idx.AnalyzeEscalation(sa("ns", "control")); !control.ClusterAdmin {
		t.Error("ClusterAdmin = false for the control, want true: impersonate on serviceaccounts does reach prod/privileged")
	}
}
