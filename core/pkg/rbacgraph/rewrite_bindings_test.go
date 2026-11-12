package rbacgraph

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func hasRewritePermission(result EscalationResult, namespace string) bool {
	for _, sr := range result.EffectiveRules {
		if sr.Namespace == namespace && len(sr.Rule.ResourceNames) == 0 && ruleGrants(sr.Rule, "*", "*", "*") {
			return true
		}
	}
	return false
}

func TestAnalyzeEscalation_ClusterRoleRewriteRequiresBinding(t *testing.T) {
	for _, tt := range []struct {
		name       string
		binding    string
		capability string
		names      []string
		wantScope  string
		wantGrant  bool
	}{
		{name: "unbound"},
		{name: "cluster binding", binding: "cluster", wantGrant: true},
		{name: "namespace binding", binding: "namespace", wantScope: "dev", wantGrant: true},
		{name: "bound to someone else", binding: "other"},
		{name: "implicit group", binding: "group", wantGrant: true},
		{name: "service account username", binding: "username", wantGrant: true},
		{name: "create cluster binding without bind", capability: "create-cluster", wantGrant: true},
		{name: "cluster-wide namespace binding create", capability: "create-all-namespaces", wantScope: "dev", wantGrant: true},
		{name: "named create is not authorized", capability: "create-cluster", names: []string{"editable"}},
		{name: "create namespace binding without bind", capability: "create-namespace", wantGrant: true, wantScope: "dev"},
		{name: "patch existing cluster binding", binding: "other", capability: "patch-cluster", names: []string{"editable-binding"}, wantGrant: true},
		{name: "patch another binding name", binding: "other", capability: "patch-cluster", names: []string{"different-binding"}},
		{name: "patch missing binding", capability: "patch-cluster", names: []string{"editable-binding"}},
		{name: "update namespace binding", binding: "other-namespace", capability: "update-namespace", wantScope: "dev", wantGrant: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			editor := clusterRole("editor", rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"escalate", "patch"}, []string{"editable"}))
			editable := clusterRole("editable", rule([]string{""}, []string{"pods"}, []string{"get"}, nil))
			clusterBindings := []rbacv1.ClusterRoleBinding{clusterRoleBinding("editor-binding", "editor", saSubject("dev", "attacker"))}
			var bindings []rbacv1.RoleBinding
			switch tt.binding {
			case "cluster":
				clusterBindings = append(clusterBindings, clusterRoleBinding("editable-binding", "editable", saSubject("dev", "attacker")))
			case "group":
				clusterBindings = append(clusterBindings, clusterRoleBinding("editable-binding", "editable", rbacv1.Subject{Kind: "Group", Name: "system:serviceaccounts:dev"}))
			case "username":
				clusterBindings = append(clusterBindings, clusterRoleBinding("editable-binding", "editable", rbacv1.Subject{Kind: "User", Name: "system:serviceaccount:dev:attacker"}))
			case "namespace":
				bindings = append(bindings, roleBinding("dev", "editable-binding", "ClusterRole", "editable", saSubject("dev", "attacker")))
			case "other":
				clusterBindings = append(clusterBindings, clusterRoleBinding("editable-binding", "editable", saSubject("dev", "other")))
			case "other-namespace":
				bindings = append(bindings, roleBinding("dev", "editable-binding", "ClusterRole", "editable", saSubject("dev", "other")))
			}
			switch tt.capability {
			case "create-cluster":
				editor.Rules = append(editor.Rules, rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"create"}, tt.names))
			case "create-all-namespaces":
				editor.Rules = append(editor.Rules, rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{"create"}, nil))
			case "patch-cluster":
				editor.Rules = append(editor.Rules, rule([]string{rbacv1.GroupName}, []string{"clusterrolebindings"}, []string{"patch"}, tt.names))
			case "create-namespace", "update-namespace":
				verb := "create"
				if tt.capability == "update-namespace" {
					verb = "update"
				}
				creator := role("dev", "binding-writer", rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{verb}, tt.names))
				bindings = append(bindings, roleBinding("dev", "writer-binding", "Role", "binding-writer", saSubject("dev", "attacker")))
				idx := NewIndex([]rbacv1.Role{creator}, []rbacv1.ClusterRole{editor, editable}, bindings, clusterBindings, nil)
				checkRewriteResult(t, idx.AnalyzeEscalation(sa("dev", "attacker")), tt.wantGrant, tt.wantScope)
				return
			}
			idx := NewIndex(nil, []rbacv1.ClusterRole{editor, editable}, bindings, clusterBindings, nil)
			checkRewriteResult(t, idx.AnalyzeEscalation(sa("dev", "attacker")), tt.wantGrant, tt.wantScope)
		})
	}
}

func checkRewriteResult(t *testing.T, result EscalationResult, wantGrant bool, scope string) {
	t.Helper()
	wantAdmin := wantGrant && scope == ""
	if result.ClusterAdmin != wantAdmin {
		t.Fatalf("ClusterAdmin=%v, want %v: %+v", result.ClusterAdmin, wantAdmin, result)
	}
	if !wantAdmin && hasRewritePermission(result, scope) != wantGrant {
		t.Fatalf("wildcard grant in %q=%v, want %v", scope, hasRewritePermission(result, scope), wantGrant)
	}
	if !wantGrant {
		if len(result.Unbounded) != 1 || !result.Unbounded[0].Edge.PermissionsUnconfirmed {
			t.Fatalf("rewrite risk must remain visible without permissions: %+v", result)
		}
		for _, sr := range result.EffectiveRules {
			if len(sr.Rule.ResourceNames) == 0 && ruleGrants(sr.Rule, "*", "*", "*") {
				t.Fatalf("unbound rewrite invented permissions: %+v", result)
			}
		}
	}
	if result.Truncated {
		t.Fatal("small analysis unexpectedly truncated")
	}
}

func TestAnalyzeEscalation_RoleRewriteHonorsBindingNamespace(t *testing.T) {
	for _, tt := range []struct {
		name, namespace, verb string
		bound, want           bool
	}{
		{name: "unbound"},
		{name: "already bound", bound: true, want: true},
		{name: "create in role namespace", namespace: "prod", verb: "create", want: true},
		{name: "create elsewhere", namespace: "staging", verb: "create"},
		{name: "update an existing binding", namespace: "prod", verb: "update", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			editor := clusterRole("editor", rule([]string{rbacv1.GroupName}, []string{"roles"}, []string{"escalate", "update"}, []string{"editable"}))
			roles := []rbacv1.Role{role("prod", "editable")}
			var bindings []rbacv1.RoleBinding
			if tt.bound {
				bindings = append(bindings, roleBinding("prod", "editable-binding", "Role", "editable", saSubject("dev", "attacker")))
			}
			if tt.verb != "" {
				roles = append(roles, role(tt.namespace, "creator", rule([]string{rbacv1.GroupName}, []string{"rolebindings"}, []string{tt.verb}, nil)))
				bindings = append(bindings, roleBinding(tt.namespace, "creator-binding", "Role", "creator", saSubject("dev", "attacker")))
				if tt.verb == "update" {
					bindings = append(bindings, roleBinding("prod", "editable-binding", "Role", "editable", saSubject("prod", "other")))
				}
			}
			idx := NewIndex(roles, []rbacv1.ClusterRole{editor}, bindings, []rbacv1.ClusterRoleBinding{clusterRoleBinding("editor", "editor", saSubject("dev", "attacker"))}, nil)
			checkRewriteResult(t, idx.AnalyzeEscalation(sa("dev", "attacker")), tt.want, "prod")
		})
	}
}

func TestAnalyzeEscalation_RewriteBenefitsPreviouslyReachedIdentity(t *testing.T) {
	// reader is visited first. writer can rewrite only editable; neither it nor
	// the starting identity is bound to editable. Reprocessing reader after the
	// rewrite grants pod creation in prod and reaches prod/admin.
	start := clusterRole("start", rule([]string{""}, []string{"serviceaccounts"}, []string{"impersonate"}, []string{"a-reader", "z-writer"}))
	writer := clusterRole("writer", rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"escalate", "patch"}, []string{"editable"}))
	editable := clusterRole("editable")
	admin := clusterRole("admin", rule([]string{"*"}, []string{"*"}, []string{"*"}, nil))
	idx := NewIndex(nil, []rbacv1.ClusterRole{start, writer, editable, admin},
		[]rbacv1.RoleBinding{roleBinding("prod", "reader", "ClusterRole", "editable", saSubject("dev", "a-reader"))},
		[]rbacv1.ClusterRoleBinding{
			clusterRoleBinding("start", "start", saSubject("dev", "attacker")),
			clusterRoleBinding("writer", "writer", saSubject("dev", "z-writer")),
			clusterRoleBinding("admin", "admin", saSubject("prod", "admin")),
		}, []corev1.ServiceAccount{saObj("dev", "a-reader"), saObj("dev", "z-writer"), saObj("prod", "admin")})
	result := idx.AnalyzeEscalation(sa("dev", "attacker"))
	if !result.ClusterAdmin || !hasRewritePermission(result, "prod") {
		t.Fatalf("rewritten permissions were not chased across identities: %+v", result)
	}
	reachedAdmin := false
	for _, path := range result.Reached {
		if len(path.Edges) > 0 && path.Edges[len(path.Edges)-1].ToSubject != nil && *path.Edges[len(path.Edges)-1].ToSubject == sa("prod", "admin") {
			reachedAdmin = true
		}
	}
	if !reachedAdmin {
		t.Fatalf("no actual identity path to prod/admin: %+v", result.Reached)
	}
	// The same immutable Index must not retain mutations from a previous query.
	independent := idx.AnalyzeEscalation(sa("dev", "a-reader"))
	if independent.ClusterAdmin || len(independent.Reached) != 0 || hasRewritePermission(independent, "prod") {
		t.Fatalf("rewrite leaked into independent analysis: %+v", independent)
	}
}

func TestAnalyzeEscalation_RewriteBindingExplanationIsDeterministic(t *testing.T) {
	editor := clusterRole("editor", rule([]string{rbacv1.GroupName}, []string{"clusterroles"}, []string{"escalate", "patch"}, []string{"editable"}))
	bindings := []rbacv1.RoleBinding{
		roleBinding("prod", "zeta", "ClusterRole", "editable", saSubject("dev", "attacker")),
		roleBinding("prod", "alpha", "ClusterRole", "editable", saSubject("dev", "attacker")),
	}
	var first string
	for i := 0; i < 2; i++ {
		idx := NewIndex(nil, []rbacv1.ClusterRole{editor, clusterRole("editable")}, bindings, []rbacv1.ClusterRoleBinding{clusterRoleBinding("editor", "editor", saSubject("dev", "attacker"))}, nil)
		result := idx.AnalyzeEscalation(sa("dev", "attacker"))
		checkRewriteResult(t, result, true, "prod")
		fingerprint := escalationFingerprint(result)
		if i == 0 {
			first = fingerprint
		} else if fingerprint != first {
			t.Fatalf("binding order changed the result:\n%s\n%s", first, fingerprint)
		}
		slices.Reverse(bindings)
	}
}

func TestDirectEscalationEdges_PreservesUnrestrictedRewriteCapability(t *testing.T) {
	editor := clusterRole("editor", rule([]string{rbacv1.GroupName}, []string{"roles"}, []string{"escalate", "patch"}, nil))
	idx := NewIndex([]rbacv1.Role{role("prod", "owned"), role("prod", "unbound")}, []rbacv1.ClusterRole{editor},
		[]rbacv1.RoleBinding{roleBinding("prod", "owned", "Role", "owned", saSubject("dev", "attacker"))},
		[]rbacv1.ClusterRoleBinding{clusterRoleBinding("editor", "editor", saSubject("dev", "attacker"))}, nil)
	subject := sa("dev", "attacker")
	capability, acquired := false, false
	for _, edge := range idx.DirectEscalationEdges(subject, idx.DirectRules(subject)) {
		if edge.Primitive != PrimitiveEscalateVerb || edge.Target == nil {
			continue
		}
		if edge.Target.Covers("Role", "prod", "unbound") && edge.PermissionsUnconfirmed {
			capability = true
		}
		if edge.Target.Covers("Role", "prod", "owned") && !edge.PermissionsUnconfirmed && edge.Scope == "prod" {
			acquired = true
		}
	}
	if !capability || !acquired {
		t.Fatalf("rewrite capability=%v, acquired permissions=%v, want both", capability, acquired)
	}
}
