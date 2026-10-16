package attackpath

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/rbacgraph"
	"github.com/kubescape/kubescape/v4/core/pkg/vulnexposure"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rule(apiGroups, resources, verbs, resourceNames []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: apiGroups, Resources: resources, Verbs: verbs, ResourceNames: resourceNames}
}

func role(ns, name string, rules ...rbacv1.PolicyRule) rbacv1.Role {
	return rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Rules: rules}
}

func clusterRole(name string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func saObj(ns, name string) corev1.ServiceAccount {
	return corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
}

func saSubject(ns, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: ns, Name: name}
}

func roleBinding(ns, name, kind, roleName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: kind, Name: roleName},
		Subjects:   subjects,
	}
}

func clusterRoleBinding(name, roleName string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
		Subjects:   subjects,
	}
}

func wl(ns, kind, name string) vulnexposure.Workload {
	return vulnexposure.Workload{Namespace: ns, Kind: kind, Name: name}
}

func critical(id string) VulnerabilityRef {
	return VulnerabilityRef{ID: id, Severity: "Critical", FixAvailable: true}
}

func completeRBAC(idx *rbacgraph.Index) RBACInput {
	return RBACInput{Index: idx, State: RBACComplete}
}

func explicit(ns, name string) WorkloadIdentity {
	return WorkloadIdentity{Namespace: ns, ServiceAccountName: name, Origin: OriginExplicit, Token: TokenMounted}
}

func correlateOne(t *testing.T, in IdentityInput) IdentityContext {
	t.Helper()
	got := CorrelateIdentity(in)
	if len(got) != 1 {
		t.Fatalf("got %d contexts, want 1: %+v", len(got), got)
	}
	return got[0]
}

func TestCorrelateIdentity_ExplicitServiceAccountReachesClusterAdmin(t *testing.T) {
	// shop/report-gen can create pods in shop, and shop/admin is cluster-admin.
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{role("shop", "pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil))},
		[]rbacv1.ClusterRole{clusterRole("cluster-admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))},
		[]rbacv1.RoleBinding{roleBinding("shop", "rb", "Role", "pod-creator", saSubject("shop", "report-gen"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("admin", "cluster-admin", saSubject("shop", "admin"))},
		[]corev1.ServiceAccount{saObj("shop", "report-gen"), saObj("shop", "admin")},
	)
	w := wl("shop", "Deployment", "report-gen")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-2024-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("shop", "report-gen")},
		RBAC:       completeRBAC(idx),
	})

	if got.Status != IdentityAnalyzed {
		t.Fatalf("Status = %q, want analyzed (reason %q)", got.Status, got.Reason)
	}
	want := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: "shop", Name: "report-gen"}
	if got.ServiceAccount == nil || *got.ServiceAccount != want {
		t.Fatalf("ServiceAccount = %v, want %v", got.ServiceAccount, want)
	}
	if got.ServiceAccountOrigin != OriginExplicit || got.ServiceAccountObject != ObjectPresent || got.Token != TokenMounted {
		t.Errorf("origin/object/token = %q/%q/%q", got.ServiceAccountOrigin, got.ServiceAccountObject, got.Token)
	}
	if !got.Permissions.ClusterAdmin || got.Permissions.NoAdditionalReachabilityFound {
		t.Errorf("ClusterAdmin = %v, NoAdditionalReachabilityFound = %v, want true/false", got.Permissions.ClusterAdmin, got.Permissions.NoAdditionalReachabilityFound)
	}
	if len(got.Vulnerabilities) != 1 || got.Vulnerabilities[0] != critical("CVE-2024-1") {
		t.Errorf("Vulnerabilities = %+v", got.Vulnerabilities)
	}
}

func TestCorrelateIdentity_DefaultedServiceAccountInheritsImplicitGroupRules(t *testing.T) {
	idx := rbacgraph.NewIndex(
		nil,
		[]rbacv1.ClusterRole{clusterRole("view-cm", rule([]string{""}, []string{"configmaps"}, []string{"get"}, nil))},
		nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("all-sas", "view-cm", rbacv1.Subject{Kind: "Group", Name: "system:serviceaccounts"})},
		[]corev1.ServiceAccount{saObj("shop", "default")},
	)
	w := wl("shop", "Deployment", "web")

	got := correlateOne(t, IdentityInput{
		Workloads: []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{
			w: {ServiceAccountName: "default", Origin: OriginDefaulted, Token: TokenMounted},
		},
		RBAC: completeRBAC(idx),
	})

	if got.ServiceAccountOrigin != OriginDefaulted {
		t.Errorf("ServiceAccountOrigin = %q, want defaulted", got.ServiceAccountOrigin)
	}
	if len(got.Permissions.DirectRules) != 1 || got.Permissions.DirectRules[0].Rule.Resources[0] != "configmaps" {
		t.Errorf("DirectRules = %+v, want the system:serviceaccounts grant", got.Permissions.DirectRules)
	}
	if got.Permissions.PermissionGain {
		t.Errorf("PermissionGain = true, want false: a direct rule is not a gain (GainedRules %+v)", got.Permissions.GainedRules)
	}
	if !got.Permissions.NoAdditionalReachabilityFound {
		t.Error("NoAdditionalReachabilityFound = false, want true for a complete, untruncated, empty result")
	}
}

func TestCorrelateIdentity_FinitePermissionGainLeavesReachabilityEmpty(t *testing.T) {
	idx := rbacgraph.NewIndex(
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
		[]corev1.ServiceAccount{saObj("prod", "api")},
	)
	w := wl("prod", "Deployment", "api")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("prod", "api")},
		RBAC:       completeRBAC(idx),
	})

	p := got.Permissions
	// The regression: every identity/cluster-admin signal is empty...
	if p.IdentitiesReached != 0 || p.Unbounded || p.ClusterAdmin || p.Truncated {
		t.Fatalf("reachability = reached %d unbounded %v admin %v truncated %v, want all empty", p.IdentitiesReached, p.Unbounded, p.ClusterAdmin, p.Truncated)
	}
	if len(got.Escalation.Reached) != 0 || len(got.Escalation.Unbounded) != 0 {
		t.Fatalf("Escalation Reached/Unbounded = %d/%d, want 0/0", len(got.Escalation.Reached), len(got.Escalation.Unbounded))
	}
	// ...yet the ServiceAccount gained the finite secret-reading rule.
	if !p.PermissionGain || len(p.GainedRules) != 1 {
		t.Fatalf("PermissionGain = %v, GainedRules = %+v, want exactly the secret-reader rule", p.PermissionGain, p.GainedRules)
	}
	gained := p.GainedRules[0]
	if gained.Namespace != "prod" || gained.Rule.Resources[0] != "secrets" {
		t.Errorf("GainedRules[0] = %+v, want secrets in prod", gained)
	}
	// Reachability being empty is a separate claim from permission gain.
	if !p.NoAdditionalReachabilityFound {
		t.Error("NoAdditionalReachabilityFound = false, want true: nothing further was reachable")
	}
	// Provenance names the subject and the Role that was bound.
	if len(got.Escalation.Granted) != 1 {
		t.Fatalf("Granted = %+v, want one grant", got.Escalation.Granted)
	}
	g := got.Escalation.Granted[0]
	if g.Subject != *got.ServiceAccount || g.Edge.Primitive != rbacgraph.PrimitiveBindVerb ||
		g.Edge.Target == nil || g.Edge.Target.Kind != "Role" || g.Edge.Target.Name != "secret-reader" || g.Edge.Target.Namespace != "prod" {
		t.Errorf("Granted[0] = %+v, want bind-verb of Role prod/secret-reader by the ServiceAccount", g)
	}
}

func TestCorrelateIdentity_AssignServiceAccountIsIdentityReachability(t *testing.T) {
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{
			role("shop", "pod-creator", rule([]string{""}, []string{"pods"}, []string{"create"}, nil)),
			role("shop", "reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
		},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("shop", "rb1", "Role", "pod-creator", saSubject("shop", "web")),
			roleBinding("shop", "rb2", "Role", "reader", saSubject("shop", "worker")),
		},
		nil,
		[]corev1.ServiceAccount{saObj("shop", "web"), saObj("shop", "worker")},
	)
	w := wl("shop", "Deployment", "web")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("shop", "web")},
		RBAC:       completeRBAC(idx),
	})

	if got.Permissions.IdentitiesReached != 1 || got.Permissions.NoAdditionalReachabilityFound {
		t.Fatalf("IdentitiesReached = %d, NoAdditionalReachabilityFound = %v, want 1/false", got.Permissions.IdentitiesReached, got.Permissions.NoAdditionalReachabilityFound)
	}
	last := got.Escalation.Reached[0].Edges[0]
	if last.Primitive != rbacgraph.PrimitiveAssignServiceAccount || last.ToSubject == nil || last.ToSubject.Name != "worker" {
		t.Errorf("first reached edge = %+v, want assign-serviceaccount to shop/worker", last)
	}
}

func TestCorrelateIdentity_ManyFindingsOneWorkload_ManyWorkloadsOneServiceAccount(t *testing.T) {
	idx := rbacgraph.NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{saObj("shop", "shared")})
	a, b := wl("shop", "Deployment", "a"), wl("shop", "StatefulSet", "b")

	got := CorrelateIdentity(IdentityInput{
		Workloads: []WorkloadVulns{
			{Workload: b, Vulnerabilities: []VulnerabilityRef{critical("CVE-3")}},
			{Workload: a, Vulnerabilities: []VulnerabilityRef{critical("CVE-2"), critical("CVE-1")}},
			// A second manifest for the same workload, repeating CVE-1 and
			// adding a distinct one: the context is merged, not multiplied.
			{Workload: a, Vulnerabilities: []VulnerabilityRef{{ID: "CVE-1", Severity: "Critical"}, {ID: "CVE-9", Severity: "High"}}},
		},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{a: explicit("shop", "shared"), b: explicit("shop", "shared")},
		RBAC:       completeRBAC(idx),
	})

	if len(got) != 2 || got[0].Workload != a || got[1].Workload != b {
		t.Fatalf("contexts = %+v, want [a b] in workload order", got)
	}
	ids := []string{}
	for _, v := range got[0].Vulnerabilities {
		ids = append(ids, v.ID)
	}
	if len(ids) != 3 || ids[0] != "CVE-1" || ids[1] != "CVE-2" || ids[2] != "CVE-9" {
		t.Errorf("a's vulnerabilities = %v, want [CVE-1 CVE-2 CVE-9]", ids)
	}
	if !got[0].Vulnerabilities[0].FixAvailable {
		t.Error("CVE-1 FixAvailable = false, want true: one of the merged copies has a fix")
	}
	// One analysis for the shared ServiceAccount: both contexts hold the
	// same cached result.
	if got[0].Escalation != got[1].Escalation {
		t.Error("workloads sharing a ServiceAccount did not share one escalation analysis")
	}
}

func TestCorrelateIdentity_SameNameInDifferentNamespacesDoesNotCrossMatch(t *testing.T) {
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{role("a", "r", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))},
		nil,
		[]rbacv1.RoleBinding{roleBinding("a", "rb", "Role", "r", saSubject("a", "web"))},
		nil,
		[]corev1.ServiceAccount{saObj("a", "web"), saObj("b", "web")},
	)
	wa, wb := wl("a", "Deployment", "web"), wl("b", "Deployment", "web")

	got := CorrelateIdentity(IdentityInput{
		Workloads: []WorkloadVulns{
			{Workload: wa, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}},
			{Workload: wb, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}},
		},
		// Only a/web is resolved; b/web must not borrow its identity by name.
		Identities: map[vulnexposure.Workload]WorkloadIdentity{wa: explicit("a", "web")},
		RBAC:       completeRBAC(idx),
	})

	if got[0].Status != IdentityAnalyzed || len(got[0].Permissions.DirectRules) != 1 {
		t.Errorf("a/web = %q with %d direct rules, want analyzed with 1", got[0].Status, len(got[0].Permissions.DirectRules))
	}
	if got[1].Status != IdentityWorkloadUnresolved || got[1].ServiceAccount != nil || got[1].Escalation != nil {
		t.Errorf("b/web = %+v, want unresolved with no identity and no analysis", got[1])
	}
}

func TestCorrelateIdentity_UnresolvedIsNotAnEmptyAnalysis(t *testing.T) {
	idx := rbacgraph.NewIndex(nil, nil, nil, nil, nil)
	w := wl("shop", "CronJob", "nightly")

	got := correlateOne(t, IdentityInput{
		Workloads:         []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		UnresolvedReasons: map[vulnexposure.Workload]string{w: "CronJob shop/nightly not found in collected resources"},
		RBAC:              completeRBAC(idx),
	})

	if got.Status != IdentityWorkloadUnresolved || got.Reason != "CronJob shop/nightly not found in collected resources" {
		t.Errorf("Status/Reason = %q/%q", got.Status, got.Reason)
	}
	if got.Permissions != nil || got.Escalation != nil {
		t.Error("an unresolved workload carries an analysis; want none, not an empty one")
	}
}

func TestCorrelateIdentity_MismatchedServiceAccountNamespaceIsUnresolved(t *testing.T) {
	idx := rbacgraph.NewIndex(nil, nil, nil, nil, nil)
	w := wl("shop", "Deployment", "web")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("other", "web")},
		RBAC:       completeRBAC(idx),
	})
	if got.Status != IdentityWorkloadUnresolved {
		t.Errorf("Status = %q, want workload-unresolved", got.Status)
	}
}

func TestCorrelateIdentity_MissingServiceAccountObjectIsFlaggedNotHidden(t *testing.T) {
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{role("shop", "r", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))},
		nil,
		[]rbacv1.RoleBinding{roleBinding("shop", "rb", "Role", "r", saSubject("shop", "ghost"))},
		nil,
		nil,
	)
	w := wl("shop", "Deployment", "ghost")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("shop", "ghost")},
		RBAC:       completeRBAC(idx),
	})

	if got.Status != IdentityAnalyzed || got.ServiceAccountObject != ObjectAbsent {
		t.Errorf("Status/object = %q/%q, want analyzed/absent", got.Status, got.ServiceAccountObject)
	}
	if len(got.Permissions.DirectRules) != 1 {
		t.Errorf("DirectRules = %d, want the binding that names the ServiceAccount to still apply", len(got.Permissions.DirectRules))
	}
}

func TestCorrelateIdentity_RBACAvailability(t *testing.T) {
	w := wl("shop", "Deployment", "web")
	idx := rbacgraph.NewIndex(nil, nil, nil, nil, []corev1.ServiceAccount{saObj("shop", "web")})
	in := func(r RBACInput) IdentityInput {
		return IdentityInput{
			Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
			Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("shop", "web")},
			RBAC:       r,
		}
	}

	t.Run("unavailable", func(t *testing.T) {
		got := correlateOne(t, in(RBACInput{State: RBACUnavailable, Reason: "list clusterrolebindings: forbidden"}))
		if got.Status != IdentityRBACUnavailable || got.Reason != "list clusterrolebindings: forbidden" {
			t.Errorf("Status/Reason = %q/%q", got.Status, got.Reason)
		}
		if got.Permissions != nil || got.ServiceAccount == nil {
			t.Error("want the resolved ServiceAccount kept and no analysis attached")
		}
	})

	t.Run("complete state without an index is not trusted", func(t *testing.T) {
		got := correlateOne(t, in(RBACInput{State: RBACComplete}))
		if got.Status != IdentityRBACUnavailable || got.RBAC != RBACUnavailable {
			t.Errorf("Status/RBAC = %q/%q, want rbac-unavailable", got.Status, got.RBAC)
		}
	})

	t.Run("partial", func(t *testing.T) {
		got := correlateOne(t, in(RBACInput{Index: idx, State: RBACPartial, Reason: "rolebindings: partial"}))
		if got.Status != IdentityRBACIncomplete || got.Permissions == nil {
			t.Fatalf("Status = %q, permissions nil = %v, want rbac-incomplete with the analysis attached", got.Status, got.Permissions == nil)
		}
		if got.Permissions.NoAdditionalReachabilityFound {
			t.Error("NoAdditionalReachabilityFound = true over partial RBAC data")
		}
	})
}

func TestCorrelateIdentity_TokenStateDoesNotChangeTheRBACResult(t *testing.T) {
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{role("shop", "r", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil))},
		nil,
		[]rbacv1.RoleBinding{roleBinding("shop", "rb", "Role", "r", saSubject("shop", "web"))},
		nil,
		[]corev1.ServiceAccount{saObj("shop", "web")},
	)
	w := wl("shop", "Deployment", "web")
	run := func(tok TokenState) IdentityContext {
		id := explicit("shop", "web")
		id.Token = tok
		return correlateOne(t, IdentityInput{
			Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{{ID: "CVE-1", Severity: "Critical"}}}},
			Identities: map[vulnexposure.Workload]WorkloadIdentity{w: id},
			RBAC:       completeRBAC(idx),
		})
	}

	mounted, notMounted, unknown := run(TokenMounted), run(TokenNotMounted), run(TokenUnknown)

	if mounted.Status != IdentityAnalyzed || notMounted.Status != IdentityTokenNotMounted || unknown.Status != IdentityAnalyzed {
		t.Errorf("statuses = %q/%q/%q", mounted.Status, notMounted.Status, unknown.Status)
	}
	if unknown.Token != TokenUnknown || notMounted.Token != TokenNotMounted {
		t.Errorf("token states = %q/%q: unknown must stay unknown, not become not-mounted", unknown.Token, notMounted.Token)
	}
	for name, c := range map[string]IdentityContext{"not-mounted": notMounted, "unknown": unknown} {
		if c.Permissions == nil || len(c.Permissions.DirectRules) != len(mounted.Permissions.DirectRules) {
			t.Errorf("%s: RBAC analysis differs from the mounted case; token state must not change it", name)
		}
		if c.Vulnerabilities[0].Severity != "Critical" {
			t.Errorf("%s: severity = %q, want it untouched", name, c.Vulnerabilities[0].Severity)
		}
	}
}

func TestCorrelateIdentity_OutputIsDeterministic(t *testing.T) {
	idx := rbacgraph.NewIndex(nil, nil, nil, nil, nil)
	ws := []vulnexposure.Workload{wl("b", "Job", "x"), wl("a", "Deployment", "z"), wl("a", "Deployment", "y")}
	build := func(order []int) []IdentityContext {
		in := IdentityInput{RBAC: completeRBAC(idx), Identities: map[vulnexposure.Workload]WorkloadIdentity{}}
		for _, i := range order {
			in.Workloads = append(in.Workloads, WorkloadVulns{Workload: ws[i], Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}})
			in.Identities[ws[i]] = explicit(ws[i].Namespace, "sa")
		}
		return CorrelateIdentity(in)
	}
	first, second := build([]int{0, 1, 2}), build([]int{2, 0, 1})
	for i := range first {
		if first[i].Workload != second[i].Workload {
			t.Fatalf("order differs at %d: %v vs %v", i, first[i].Workload, second[i].Workload)
		}
	}
	if first[0].Workload != ws[2] || first[2].Workload != ws[0] {
		t.Errorf("order = %v, want sorted by namespace/kind/name", []vulnexposure.Workload{first[0].Workload, first[1].Workload, first[2].Workload})
	}
}

func TestSummarize_TruncatedAndScopeUnknownAreNeverACleanNegative(t *testing.T) {
	sa := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: "ns", Name: "sa"}

	truncated := summarize(rbacgraph.EscalationResult{Start: sa, Truncated: true}, nil, RBACComplete)
	if !truncated.Truncated || truncated.NoAdditionalReachabilityFound {
		t.Errorf("truncated: Truncated = %v, NoAdditionalReachabilityFound = %v, want true/false", truncated.Truncated, truncated.NoAdditionalReachabilityFound)
	}

	unknownScope := summarize(rbacgraph.EscalationResult{
		Start: sa,
		Unbounded: []rbacgraph.UnboundedFinding{{
			Subject: sa,
			Edge:    rbacgraph.EscalationEdge{Primitive: rbacgraph.PrimitiveBindVerb, Unbounded: true, ScopeUnknown: true},
		}},
	}, nil, RBACComplete)
	if !unknownScope.ScopeUnknown || !unknownScope.Unbounded || unknownScope.NoAdditionalReachabilityFound || unknownScope.ClusterAdmin {
		t.Errorf("scope unknown: %+v, want visible uncertainty, no authority, no clean negative", unknownScope)
	}
	if unknownScope.PermissionGain {
		t.Error("PermissionGain = true from a scope-unknown warning, want false: it grants nothing")
	}
}

func TestRuleKey_DistinguishesRulesAThinStringJoinWouldMerge(t *testing.T) {
	r := func(resources, verbs []string) rbacgraph.ScopedRule {
		return rbacgraph.ScopedRule{Namespace: "ns", Rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: resources, Verbs: verbs}}
	}
	if ruleKey(r([]string{"a", "b"}, []string{"get"})) == ruleKey(r([]string{"a"}, []string{"b", "get"})) {
		t.Error("rules with different resource/verb boundaries share a key")
	}
	if ruleKey(r([]string{"a", "b"}, []string{"get", "list"})) != ruleKey(r([]string{"b", "a"}, []string{"list", "get"})) {
		t.Error("the same rule with its sets in another order has a different key")
	}
	other := r([]string{"a"}, []string{"get"})
	other.Namespace = ""
	if ruleKey(r([]string{"a"}, []string{"get"})) == ruleKey(other) {
		t.Error("a namespaced and a cluster-wide rule share a key")
	}
}

func TestCorrelateIdentity_ScopeUnknownStaysVisibleAndGrantsNothing(t *testing.T) {
	// escalate+update on roles restricted to a name no collected Role has: the
	// analyzer reports a missing-target warning with an unresolved scope.
	idx := rbacgraph.NewIndex(
		nil,
		[]rbacv1.ClusterRole{clusterRole("escalator", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"escalate", "update"}, []string{"missing"}))},
		nil,
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("crb", "escalator", saSubject("prod", "api"))},
		[]corev1.ServiceAccount{saObj("prod", "api")},
	)
	w := wl("prod", "Deployment", "api")

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: explicit("prod", "api")},
		RBAC:       completeRBAC(idx),
	})

	p := got.Permissions
	if !p.ScopeUnknown || !p.Unbounded {
		t.Fatalf("ScopeUnknown/Unbounded = %v/%v, want the warning kept visible", p.ScopeUnknown, p.Unbounded)
	}
	if p.ClusterAdmin || p.PermissionGain || p.NoAdditionalReachabilityFound {
		t.Errorf("ClusterAdmin/PermissionGain/NoAdditionalReachabilityFound = %v/%v/%v, want false/false/false", p.ClusterAdmin, p.PermissionGain, p.NoAdditionalReachabilityFound)
	}
	if len(p.GainedRules) != 0 {
		t.Errorf("GainedRules = %+v, want none: an unresolved scope grants nothing", p.GainedRules)
	}
}

func TestCorrelateIdentity_TokenNotMountedKeepsTheSameAnalysis(t *testing.T) {
	idx := rbacgraph.NewIndex(
		[]rbacv1.Role{
			role("prod", "secret-reader", rule([]string{""}, []string{"secrets"}, []string{"get"}, nil)),
			role("prod", "binder", rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind"}, []string{"secret-reader"})),
			role("prod", "rb-creator", rule([]string{"rbac.authorization.k8s.io"}, []string{"rolebindings"}, []string{"create"}, nil)),
		},
		nil,
		[]rbacv1.RoleBinding{
			roleBinding("prod", "rb1", "Role", "binder", saSubject("prod", "api")),
			roleBinding("prod", "rb2", "Role", "rb-creator", saSubject("prod", "api")),
		},
		nil,
		[]corev1.ServiceAccount{saObj("prod", "api")},
	)
	w := wl("prod", "Deployment", "api")
	id := explicit("prod", "api")
	id.Token = TokenNotMounted

	got := correlateOne(t, IdentityInput{
		Workloads:  []WorkloadVulns{{Workload: w, Vulnerabilities: []VulnerabilityRef{critical("CVE-1")}}},
		Identities: map[vulnexposure.Workload]WorkloadIdentity{w: id},
		RBAC:       completeRBAC(idx),
	})

	if got.Status != IdentityTokenNotMounted || got.Token != TokenNotMounted {
		t.Fatalf("Status/Token = %q/%q", got.Status, got.Token)
	}
	if got.Escalation == nil || len(got.Escalation.Granted) != 1 || got.Permissions == nil || !got.Permissions.PermissionGain {
		t.Errorf("token-not-mounted dropped the RBAC analysis: escalation %+v, permissions %+v", got.Escalation, got.Permissions)
	}
}

func TestSummarize_GainedRulesAreDeduplicatedAndOrdered(t *testing.T) {
	sa := rbacgraph.Subject{Kind: rbacgraph.KindServiceAccount, Namespace: "ns", Name: "sa"}
	mk := func(res string, verbs ...string) rbacgraph.ScopedRule {
		return rbacgraph.ScopedRule{Namespace: "ns", Rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{res}, Verbs: verbs}}
	}
	direct := []rbacgraph.ScopedRule{mk("pods", "get", "list")}
	esc := rbacgraph.EscalationResult{Start: sa, EffectiveRules: []rbacgraph.ScopedRule{
		mk("secrets", "get"),
		mk("pods", "list", "get"), // the direct rule with its set reordered: not a gain
		mk("configmaps", "get"),
		mk("secrets", "get"), // duplicate
	}}

	s := summarize(esc, direct, RBACComplete)

	if len(s.GainedRules) != 2 || s.GainedRules[0].Rule.Resources[0] != "configmaps" || s.GainedRules[1].Rule.Resources[0] != "secrets" {
		t.Errorf("GainedRules = %+v, want [configmaps secrets]", s.GainedRules)
	}
	if !s.PermissionGain {
		t.Error("PermissionGain = false, want true")
	}
}
