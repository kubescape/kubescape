package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestTakesProviderNamespaceDefault(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"kubernetes_deployment_v1.web.metadata", true},
		{"kubernetes_pod.web.metadata", true},
		{"kubernetes_service_account_v1.ci.metadata", true},
		{"kubernetes_default_service_account_v1.default.metadata", true},
		{"kubernetes_role_v1.reader.metadata", true},
		{"kubernetes_role_binding_v1.reader.metadata", true},
		{"kubernetes_network_policy_v1.deny.metadata", true},
		{"kubernetes_namespace_v1.apps.metadata", false},
		{"kubernetes_cluster_role_v1.admin.metadata", false},
		{"kubernetes_cluster_role_binding_v1.admin.metadata", false},
		{"kubernetes_deployment_v1.web.spec.template.metadata", false},
		{"kubernetes_cron_job_v1.backup.spec.job_template.metadata", false},
		{"kubernetes_role_binding_v1.reader.subject", true},
		{"kubernetes_role_binding.reader.subject", true},
		{"kubernetes_cluster_role_binding_v1.admin.subject", true},
		{"kubernetes_cluster_role_binding.admin.subject", true},
		{"kubernetes_role_binding_v1.reader.role_ref", false},
		{"kubernetes_deployment_v1.web.spec", false},
		{"kubernetes_manifest.web.metadata", false},
		{"metadata", false},
		{"kubernetes_pod_v1", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, takesProviderNamespaceDefault(tc.path))
		})
	}
}

const namespaceDefaultsTerraform = `
resource "kubernetes_deployment_v1" "web" {
  metadata {
    name = "web"
  }
  spec {
    template {
      metadata {
        labels = { app = "web" }
      }
      spec {
        container {
          name  = "web"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_service_account_v1" "pinned" {
  metadata {
    name      = "pinned"
    namespace = "apps"
  }
}

resource "kubernetes_service_account_v1" "null" {
  metadata {
    name      = "null"
    namespace = null
  }
}

resource "kubernetes_service_account_v1" "variable" {
  metadata {
    name      = "variable"
    namespace = var.namespace
  }
}

resource "kubernetes_namespace_v1" "apps" {
  metadata {
    name = "apps"
  }
}

resource "kubernetes_cluster_role_v1" "admin" {
  metadata {
    name = "admin"
  }
  rule {
    api_groups = ["*"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "admin" {
  metadata {
    name = "admin"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "admin"
  }
  subject {
    kind = "ServiceAccount"
    name = "ci"
  }
}

resource "kubernetes_role_binding_v1" "reader" {
  metadata {
    name      = "reader"
    namespace = "apps"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "reader"
  }
  subject {
    kind = "ServiceAccount"
    name = "ci"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "deployer"
    namespace = "apps"
  }
  subject {
    kind      = "Group"
    name      = "auditors"
    api_group = "rbac.authorization.k8s.io"
  }
}
`

func TestExtractTypedResourcesDefaultsMetadataNamespace(t *testing.T) {
	evalCtx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"namespace": cty.StringVal("tools")})}}
	manifests, errs := extractTypedResources(parseTypedHCL(t, namespaceDefaultsTerraform), evalCtx)
	require.Empty(t, errs)
	byName := map[string]map[string]interface{}{}
	for _, m := range manifests {
		byName[m["kind"].(string)+"/"+m["metadata"].(map[string]interface{})["name"].(string)] = m
	}
	metadata := func(name string) map[string]interface{} {
		require.Contains(t, byName, name)
		return byName[name]["metadata"].(map[string]interface{})
	}

	assert.Equal(t, "default", metadata("Deployment/web")["namespace"], "the provider creates it in the default namespace")
	assert.Equal(t, "apps", metadata("ServiceAccount/pinned")["namespace"], "an explicit namespace is kept")
	assert.Equal(t, "default", metadata("ServiceAccount/null")["namespace"], "null is unset to Terraform, so the provider default applies")
	assert.Equal(t, "tools", metadata("ServiceAccount/variable")["namespace"], "a resolved variable is used as is")
	assert.Equal(t, "apps", metadata("RoleBinding/reader")["namespace"])

	for _, name := range []string{"Namespace/apps", "ClusterRole/admin", "ClusterRoleBinding/admin"} {
		assert.NotContains(t, metadata(name), "namespace", "%s is cluster scoped", name)
	}

	template := podSpecAt(t, byName["Deployment/web"], "spec", "template", "metadata")
	assert.NotContains(t, template, "namespace", "a pod template takes the namespace of its resource")
}

func TestExtractTypedResourcesDefaultsSubjectNamespace(t *testing.T) {
	evalCtx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"namespace": cty.StringVal("tools")})}}
	manifests, errs := extractTypedResources(parseTypedHCL(t, namespaceDefaultsTerraform), evalCtx)
	require.Empty(t, errs)
	subjects := map[string][]interface{}{}
	for _, m := range manifests {
		if s, ok := m["subjects"].([]interface{}); ok {
			subjects[m["kind"].(string)] = s
		}
	}

	assert.Equal(t, []interface{}{
		map[string]interface{}{"kind": "ServiceAccount", "name": "ci", "namespace": "default"},
	}, subjects["ClusterRoleBinding"], "the provider fills in the namespace a cluster role binding subject needs")

	assert.Equal(t, []interface{}{
		map[string]interface{}{"kind": "ServiceAccount", "name": "ci", "namespace": "default"},
		map[string]interface{}{"kind": "ServiceAccount", "name": "deployer", "namespace": "apps"},
		map[string]interface{}{"kind": "Group", "name": "auditors", "apiGroup": "rbac.authorization.k8s.io", "namespace": "default"},
	}, subjects["RoleBinding"], "the provider sends default, not the binding's apps namespace, for a subject without one")
}

func TestExtractTypedResourcesDoesNotGuessAnUnresolvedNamespace(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "ci" {
  metadata {
    name      = "ci"
    namespace = var.not_declared
  }
}

resource "kubernetes_role_binding_v1" "reader" {
  metadata {
    name      = "reader"
    namespace = "apps"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "reader"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "ci"
    namespace = var.not_declared
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Len(t, errs, 2, "both unresolved attributes are reported")
	require.Len(t, manifests, 2)
	assert.NotContains(t, manifests[0]["metadata"].(map[string]interface{}), "namespace",
		"a namespace that could not be resolved is left out, not replaced by the default")
	subject := manifests[1]["subjects"].([]interface{})[0].(map[string]interface{})
	assert.NotContains(t, subject, "namespace")
}

// boundServiceAccountRego mirrors how the workload-with-administrative-roles
// rule (C-0272) ties a binding to a ServiceAccount: by the subject's kind, name
// and namespace against the ServiceAccount's own.
const boundServiceAccountRego = `
package test

import rego.v1

bound contains sa.metadata.name if {
	sa := input[_]
	sa.kind == "ServiceAccount"
	binding := input[_]
	binding.kind in {"RoleBinding", "ClusterRoleBinding"}
	subject := binding.subjects[_]
	subject.kind == "ServiceAccount"
	subject.name == sa.metadata.name
	subject.namespace == sa.metadata.namespace
}
`

// TestTerraformBindingReachesServiceAccountInDefaultNamespace scans a
// configuration that, like the provider's own examples, names neither the
// ServiceAccount's namespace nor its subject's. The provider puts both in
// default, so the cluster-admin binding applies to that account.
func TestTerraformBindingReachesServiceAccountInDefaultNamespace(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "kubernetes_service_account_v1" "ci" {
  metadata {
    name = "ci"
  }
}

resource "kubernetes_cluster_role_binding_v1" "ci" {
  metadata {
    name = "ci-admin"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    kind = "ServiceAccount"
    name = "ci"
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	var input []interface{}
	for _, list := range workloads {
		for _, w := range list {
			input = append(input, w.GetObject())
		}
	}
	require.Len(t, input, 2)

	raw, err := json.Marshal(input)
	require.NoError(t, err)
	var decoded interface{}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	rs, err := rego.New(rego.Query("data.test.bound"), rego.Module("test.rego", boundServiceAccountRego), rego.Input(decoded)).Eval(context.Background())
	require.NoError(t, err)
	require.Len(t, rs, 1)
	assert.Equal(t, []interface{}{"ci"}, rs[0].Expressions[0].Value, "default/ci holds the cluster-admin binding")
}

func TestExtractTypedResourcesDoesNotApplyDefaultWhenTryHidesUnresolvableReference(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "ci" {
  metadata {
    name      = "ci"
    namespace = try(kubernetes_namespace_v1.team.metadata[0].name, null)
  }
}

resource "kubernetes_service_account_v1" "unused_fallback" {
  metadata {
    name      = "unused_fallback"
    namespace = try(var.declared_null, var.missing_ns)
  }
}

resource "kubernetes_role_binding_v1" "reader" {
  metadata {
    name      = "reader"
    namespace = "apps"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "reader"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "ci"
    namespace = try(var.missing_ns, null)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "deployer"
    namespace = try(var.missing_ns, "fallback-ns")
  }
  subject {
    kind      = "ServiceAccount"
    name      = "admin"
    namespace = try(var.declared_null, null)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "unused_fallback_var"
    namespace = try(var.declared_null, var.missing_ns)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "unused_fallback_null"
    namespace = try(null, var.missing_ns)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "coalesce_unused_fallback"
    namespace = coalesce(var.declared_null, "default", var.missing_ns)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "coalesce_unresolvable"
    namespace = try(coalesce(var.declared_null, var.missing_ns), null)
  }
  subject {
    kind      = "ServiceAccount"
    name      = "coalesce_mixed_type"
    namespace = coalesce(123, "fallback")
  }
}

resource "kubernetes_service_account_v1" "parenthesized_unused_fallback" {
  metadata {
    name      = "parenthesized_unused_fallback"
    namespace = (try(var.declared_null, var.missing_ns))
  }
}

resource "kubernetes_service_account_v1" "parenthesized_unresolvable_try" {
  metadata {
    name      = "parenthesized_unresolvable_try"
    namespace = (try(var.missing_ns, null))
  }
}

resource "kubernetes_service_account_v1" "string_condition_true" {
  metadata {
    name      = "string_condition_true"
    namespace = var.flag_str_true ? (try(var.declared_null, var.missing_ns)) : "other"
  }
}

resource "kubernetes_service_account_v1" "string_condition_false" {
  metadata {
    name      = "string_condition_false"
    namespace = var.flag_str_false ? "other" : (try(var.declared_null, var.missing_ns))
  }
}

resource "kubernetes_service_account_v1" "caught_diagnostic_try" {
  metadata {
    name      = "caught_diagnostic_try"
    namespace = try([][0], null)
  }
}

resource "kubernetes_service_account_v1" "coalesce_unused_fallback" {
  metadata {
    name      = "coalesce_unused_fallback"
    namespace = coalesce(var.declared_null, "default", var.missing_ns)
  }
}

resource "kubernetes_service_account_v1" "coalesce_unresolvable_try" {
  metadata {
    name      = "coalesce_unresolvable_try"
    namespace = try(coalesce(var.declared_null, var.missing_ns), null)
  }
}

resource "kubernetes_service_account_v1" "coalesce_mixed_type" {
  metadata {
    name      = "coalesce_mixed_type"
    namespace = coalesce(123, "fallback")
  }
}

resource "kubernetes_service_account_v1" "coalesce_caught_diagnostic_try" {
  metadata {
    name      = "coalesce_caught_diagnostic_try"
    namespace = try(coalesce([][0], "fallback"), null)
  }
}

resource "kubernetes_service_account_v1" "template_wrap_try_null" {
  metadata {
    name      = "template_wrap_try_null"
    namespace = "${try(null, var.missing_ns)}"
  }
}

resource "kubernetes_service_account_v1" "template_wrap_try_unresolvable" {
  metadata {
    name      = "template_wrap_try_unresolvable"
    namespace = "${try(var.missing_ns, null)}"
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null":  cty.NullVal(cty.String),
				"flag_str_true":  cty.StringVal("true"),
				"flag_str_false": cty.StringVal("false"),
			}),
		},
		Functions: terraformFunctions,
	}
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Empty(t, errs, "try(...) suppresses diagnostics so no eval errors are returned")
	require.Len(t, manifests, 14)

	byName := map[string]map[string]interface{}{}
	for _, m := range manifests {
		byName[m["kind"].(string)+"/"+m["metadata"].(map[string]interface{})["name"].(string)] = m
	}

	assert.NotContains(t, byName["ServiceAccount/ci"]["metadata"].(map[string]interface{}), "namespace",
		"try(...) hiding an unresolvable reference must not take the provider default namespace")

	assert.Equal(t, "default", byName["ServiceAccount/unused_fallback"]["metadata"].(map[string]interface{})["namespace"],
		"unused fallback referencing unresolvable variable must not prevent provider default when primary operand resolves cleanly to null")

	assert.Equal(t, "default", byName["ServiceAccount/parenthesized_unused_fallback"]["metadata"].(map[string]interface{})["namespace"],
		"parenthesized try(...) with unused fallback must take provider default namespace")

	assert.NotContains(t, byName["ServiceAccount/parenthesized_unresolvable_try"]["metadata"].(map[string]interface{}), "namespace",
		"parenthesized try(...) hiding unresolvable reference must not take provider default namespace")

	assert.Equal(t, "default", byName["ServiceAccount/string_condition_true"]["metadata"].(map[string]interface{})["namespace"],
		"conditional with convertible string 'true' must select true branch and take provider default")

	assert.Equal(t, "default", byName["ServiceAccount/string_condition_false"]["metadata"].(map[string]interface{})["namespace"],
		"conditional with convertible string 'false' must select false branch and take provider default")

	assert.Equal(t, "default", byName["ServiceAccount/caught_diagnostic_try"]["metadata"].(map[string]interface{})["namespace"],
		"caught evaluation diagnostic in try(...) falling back to null must take provider default")

	assert.Equal(t, "default", byName["ServiceAccount/coalesce_unused_fallback"]["metadata"].(map[string]interface{})["namespace"],
		"coalesce with unused fallback referencing unresolvable variable must preserve resolved value")

	assert.NotContains(t, byName["ServiceAccount/coalesce_unresolvable_try"]["metadata"].(map[string]interface{}), "namespace",
		"coalesce falling back to unresolvable variable inside try(...) must not take provider default namespace")

	assert.Equal(t, "123", byName["ServiceAccount/coalesce_mixed_type"]["metadata"].(map[string]interface{})["namespace"],
		"coalesce with mixed number and string arguments must unify to string namespace")

	assert.Equal(t, "default", byName["ServiceAccount/coalesce_caught_diagnostic_try"]["metadata"].(map[string]interface{})["namespace"],
		"caught evaluation diagnostic inside coalesce within try(...) falling back to null must take provider default")

	assert.Equal(t, "default", byName["ServiceAccount/template_wrap_try_null"]["metadata"].(map[string]interface{})["namespace"],
		"interpolation-only template wrap with try(...) falling back cleanly to null must take provider default namespace")

	assert.NotContains(t, byName["ServiceAccount/template_wrap_try_unresolvable"]["metadata"].(map[string]interface{}), "namespace",
		"interpolation-only template wrap with try(...) hiding unresolvable reference must not take provider default namespace")

	subjects := byName["RoleBinding/reader"]["subjects"].([]interface{})
	require.Len(t, subjects, 8)

	s0 := subjects[0].(map[string]interface{})
	assert.Equal(t, "ci", s0["name"])
	assert.NotContains(t, s0, "namespace",
		"subject namespace with unresolvable reference in try(...) must remain unset")

	s1 := subjects[1].(map[string]interface{})
	assert.Equal(t, "deployer", s1["name"])
	assert.Equal(t, "fallback-ns", s1["namespace"],
		"fallback value in try(...) must be preserved")

	s2 := subjects[2].(map[string]interface{})
	assert.Equal(t, "admin", s2["name"])
	assert.Equal(t, "default", s2["namespace"],
		"explicitly resolvable null in try(...) must take provider default")

	s3 := subjects[3].(map[string]interface{})
	assert.Equal(t, "unused_fallback_var", s3["name"])
	assert.Equal(t, "default", s3["namespace"],
		"subject namespace with unused fallback in try(...) must take provider default")

	s4 := subjects[4].(map[string]interface{})
	assert.Equal(t, "unused_fallback_null", s4["name"])
	assert.Equal(t, "default", s4["namespace"],
		"subject namespace with unused fallback after literal null must take provider default")
	s5 := subjects[5].(map[string]interface{})
	assert.Equal(t, "coalesce_unused_fallback", s5["name"])
	assert.Equal(t, "default", s5["namespace"],
		"subject namespace with coalesce unused fallback must take resolved value")

	s6 := subjects[6].(map[string]interface{})
	assert.Equal(t, "coalesce_unresolvable", s6["name"])
	assert.NotContains(t, s6, "namespace",
		"subject namespace with unresolvable coalesce inside try(...) must remain unset")

	s7 := subjects[7].(map[string]interface{})
	assert.Equal(t, "coalesce_mixed_type", s7["name"])
	assert.Equal(t, "123", s7["namespace"],
		"subject namespace with mixed type coalesce must unify to string namespace")
}

func TestExtractTypedResources_InvalidConditionTypeDoesNotPanic(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "invalid_cond" {
  metadata {
    name      = "invalid-cond"
    namespace = var.flag_invalid ? "a" : "b"
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"flag_invalid": cty.StringVal("not-a-bool"),
			}),
		},
		Functions: terraformFunctions,
	}
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.NotEmpty(t, errs, "invalid condition type yields HCL evaluation diagnostic")
	require.Len(t, manifests, 1)
	assert.NotContains(t, manifests[0]["metadata"].(map[string]interface{}), "namespace",
		"invalid condition must be treated as unresolvable and leave default unset without panicking")
}

func TestTerraformDirectory_LocalsCarryingNullThrough(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "variables.tf"), []byte(`
variable "declared_null" {
  type    = string
  default = null
}
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "locals.tf"), []byte(`
locals {
  explicit_null                 = null
  from_var_null                 = var.declared_null
  unused_fallback               = try(var.declared_null, var.missing_ref)
  unresolvable_try              = try(kubernetes_namespace_v1.team.metadata[0].name, null)
  parenthesized_unused_fallback = (try(var.declared_null, var.missing_ref))
  parenthesized_unresolvable    = (try(kubernetes_namespace_v1.team.metadata[0].name, null))
  string_cond_true              = "true" ? (try(var.declared_null, var.missing_ref)) : "other"
  string_cond_false             = "false" ? "other" : (try(var.declared_null, var.missing_ref))
  caught_diagnostic             = try([][0], null)
  coalesce_unused_fallback      = coalesce(var.declared_null, "default", var.missing_ref)
  coalesce_unresolvable         = try(coalesce(var.declared_null, var.missing_ref), null)
  coalesce_mixed_type           = coalesce(123, "fallback")
  template_wrap_try_null        = "${try(null, var.missing_ref)}"
  template_wrap_unresolvable    = "${try(var.missing_ref, null)}"
}
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "kubernetes_service_account_v1" "explicit_null" {
  metadata {
    name      = "explicit-null"
    namespace = local.explicit_null
  }
}

resource "kubernetes_service_account_v1" "from_var_null" {
  metadata {
    name      = "from-var-null"
    namespace = local.from_var_null
  }
}

resource "kubernetes_service_account_v1" "unused_fallback" {
  metadata {
    name      = "unused-fallback"
    namespace = local.unused_fallback
  }
}

resource "kubernetes_service_account_v1" "unresolvable_try" {
  metadata {
    name      = "unresolvable-try"
    namespace = local.unresolvable_try
  }
}

resource "kubernetes_service_account_v1" "parenthesized_unused_fallback" {
  metadata {
    name      = "parenthesized-unused-fallback"
    namespace = local.parenthesized_unused_fallback
  }
}

resource "kubernetes_service_account_v1" "parenthesized_unresolvable" {
  metadata {
    name      = "parenthesized-unresolvable"
    namespace = local.parenthesized_unresolvable
  }
}

resource "kubernetes_service_account_v1" "string_cond_true" {
  metadata {
    name      = "string-cond-true"
    namespace = local.string_cond_true
  }
}

resource "kubernetes_service_account_v1" "string_cond_false" {
  metadata {
    name      = "string-cond-false"
    namespace = local.string_cond_false
  }
}

resource "kubernetes_service_account_v1" "caught_diagnostic" {
  metadata {
    name      = "caught-diagnostic"
    namespace = local.caught_diagnostic
  }
}
resource "kubernetes_service_account_v1" "coalesce_unused_fallback" {
  metadata {
    name      = "coalesce-unused-fallback"
    namespace = local.coalesce_unused_fallback
  }
}

resource "kubernetes_service_account_v1" "coalesce_unresolvable" {
  metadata {
    name      = "coalesce-unresolvable"
    namespace = local.coalesce_unresolvable
  }
}

resource "kubernetes_service_account_v1" "coalesce_mixed_type" {
  metadata {
    name      = "coalesce-mixed-type"
    namespace = local.coalesce_mixed_type
  }
}

resource "kubernetes_service_account_v1" "template_wrap_try_null" {
  metadata {
    name      = "template-wrap-try-null"
    namespace = local.template_wrap_try_null
  }
}

resource "kubernetes_service_account_v1" "template_wrap_unresolvable" {
  metadata {
    name      = "template-wrap-unresolvable"
    namespace = local.template_wrap_unresolvable
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)

	byName := map[string]map[string]interface{}{}
	for _, list := range workloads {
		for _, w := range list {
			obj := w.GetObject()
			meta := obj["metadata"].(map[string]interface{})
			byName[meta["name"].(string)] = meta
		}
	}

	assert.Equal(t, "default", byName["explicit-null"]["namespace"],
		"explicit null local must take provider default namespace")
	assert.Equal(t, "default", byName["from-var-null"]["namespace"],
		"local carrying null from declared variable must take provider default namespace")
	assert.Equal(t, "default", byName["unused-fallback"]["namespace"],
		"local with unused fallback referencing missing variable must take provider default namespace")
	assert.NotContains(t, byName["unresolvable-try"], "namespace",
		"local hiding an unresolvable reference in try(...) must not take provider default namespace")
	assert.Equal(t, "default", byName["parenthesized-unused-fallback"]["namespace"],
		"local with parenthesized unused fallback must take provider default namespace")
	assert.NotContains(t, byName["parenthesized-unresolvable"], "namespace",
		"local with parenthesized unresolvable try(...) must not take provider default namespace")
	assert.Equal(t, "default", byName["string-cond-true"]["namespace"],
		"local with string-valued condition 'true' must take provider default namespace")
	assert.Equal(t, "default", byName["string-cond-false"]["namespace"],
		"local with string-valued condition 'false' must take provider default namespace")
	assert.Equal(t, "default", byName["caught-diagnostic"]["namespace"],
		"local with caught evaluation diagnostic in try(...) falling back to null must take provider default namespace")
	assert.Equal(t, "default", byName["coalesce-unused-fallback"]["namespace"],
		"local with coalesce unused fallback must preserve resolved value")
	assert.NotContains(t, byName["coalesce-unresolvable"], "namespace",
		"local with unresolvable coalesce inside try(...) must not take provider default namespace")
	assert.Equal(t, "123", byName["coalesce-mixed-type"]["namespace"],
		"local with mixed-type coalesce must resolve to string")
	assert.Equal(t, "default", byName["template-wrap-try-null"]["namespace"],
		"local with interpolation-wrapped try(...) falling back cleanly to null must take provider default namespace")
	assert.NotContains(t, byName["template-wrap-unresolvable"], "namespace",
		"local with interpolation-wrapped try(...) hiding unresolvable reference must not take provider default namespace")
}

// A key or attribute missing from a known value is an error that try() catches,
// as in Terraform: the expression is null, so the provider default applies.
func TestExtractTypedResourcesAppliesDefaultWhenTryCatchesAMissingKey(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "map_key" {
  metadata {
    name      = "map_key"
    namespace = try(var.config["namespace"], null)
  }
}

resource "kubernetes_service_account_v1" "object_attribute" {
  metadata {
    name      = "object_attribute"
    namespace = try(var.app.namespace, null)
  }
}

resource "kubernetes_service_account_v1" "local_attribute" {
  metadata {
    name      = "local_attribute"
    namespace = try(local.settings.namespace, null)
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"config": cty.MapValEmpty(cty.String),
				"app":    cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal("web")}),
			}),
			"local": cty.ObjectVal(map[string]cty.Value{
				"settings": cty.EmptyObjectVal,
			}),
		},
		Functions: terraformFunctions,
	}
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Empty(t, errs)
	require.Len(t, manifests, 3)
	for _, manifest := range manifests {
		metadata := manifest["metadata"].(map[string]interface{})
		assert.Equal(t, "default", metadata["namespace"], metadata["name"])
	}
}

func TestHasUnresolvableVariables_Coalesce(t *testing.T) {
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null":  cty.NullVal(cty.String),
				"valid_str":      cty.StringVal("prod"),
				"empty_str":      cty.StringVal(""),
				"declared_true":  cty.True,
				"declared_false": cty.False,
			}),
		},
		Functions: terraformFunctions,
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "first arg is valid non-null string, stops before missing fallback",
			expr: `coalesce(var.valid_str, var.missing)`,
			want: false,
		},
		{
			name: "first arg is literal non-null string, stops before missing fallback",
			expr: `coalesce("prod", var.missing)`,
			want: false,
		},
		{
			name: "first arg is declared null, falls back to unresolvable variable",
			expr: `coalesce(var.declared_null, var.missing)`,
			want: true,
		},
		{
			name: "first arg is empty string, falls back to unresolvable variable",
			expr: `coalesce(var.empty_str, var.missing)`,
			want: true,
		},
		{
			name: "first arg is null, second is valid non-null string, stops before missing fallback",
			expr: `coalesce(var.declared_null, var.valid_str, var.missing)`,
			want: false,
		},
		{
			name: "parenthesized coalesce stops at first valid non-null",
			expr: `(coalesce(var.valid_str, var.missing))`,
			want: false,
		},
		{
			name: "boolean true stops before missing fallback",
			expr: `coalesce(var.declared_true, var.missing)`,
			want: false,
		},
		{
			name: "boolean false is non-null and stops before missing fallback",
			expr: `coalesce(var.declared_false, var.missing)`,
			want: false,
		},
		{
			name: "all args null has no unresolvable variables",
			expr: `coalesce(var.declared_null, null)`,
			want: false,
		},
		{
			name: "mixed type number and string stops before missing fallback",
			expr: `coalesce(123, "fallback", var.missing)`,
			want: false,
		},
		{
			name: "mixed type declared null then number stops before missing fallback",
			expr: `coalesce(var.declared_null, 123, var.missing)`,
			want: false,
		},
		{
			name: "mixed type declared null then missing fallback retains protection",
			expr: `coalesce(var.declared_null, var.missing, 123)`,
			want: true,
		},
		{
			name: "coalesce with runtime evaluation diagnostic is not treated as unresolvable",
			expr: `coalesce([][0], "x")`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte("x = "+tt.expr), "test.tf", hcl.Pos{Line: 1, Column: 1})
			require.False(t, diags.HasErrors())
			attr := file.Body.(*hclsyntax.Body).Attributes["x"]
			got := hasUnresolvableVariables(attr.Expr, evalCtx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasUnresolvableVariables_TemplateWrapExpr(t *testing.T) {
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null": cty.NullVal(cty.String),
				"valid_str":     cty.StringVal("prod"),
			}),
		},
		Functions: terraformFunctions,
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "interpolation wrapping try with primary null preserves default",
			expr: `"${try(null, var.missing)}"`,
			want: false,
		},
		{
			name: "interpolation wrapping try with primary declared null preserves default",
			expr: `"${try(var.declared_null, var.missing)}"`,
			want: false,
		},
		{
			name: "interpolation wrapping try with unresolvable reference retains protection",
			expr: `"${try(var.missing, null)}"`,
			want: true,
		},
		{
			name: "interpolation wrapping coalesce with valid primary stops before missing",
			expr: `"${coalesce(var.valid_str, var.missing)}"`,
			want: false,
		},
		{
			name: "interpolation wrapping coalesce falling back to missing retains protection",
			expr: `"${coalesce(var.declared_null, var.missing)}"`,
			want: true,
		},
		{
			name: "nested parentheses and template wrap",
			expr: `"${(try(null, var.missing))}"`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte("x = "+tt.expr), "test.tf", hcl.Pos{Line: 1, Column: 1})
			require.False(t, diags.HasErrors())
			attr := file.Body.(*hclsyntax.Body).Attributes["x"]
			got := hasUnresolvableVariables(attr.Expr, evalCtx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasUnresolvableVariables_CompoundAndCan(t *testing.T) {
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null": cty.NullVal(cty.String),
				"valid_str":     cty.StringVal("prod"),
				"valid_num":     cty.NumberIntVal(10),
				"valid_obj": cty.ObjectVal(map[string]cty.Value{
					"name": cty.StringVal("my-app"),
				}),
			}),
		},
		Functions: terraformFunctions,
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		// Multi-part string templates (TemplateExpr)
		{
			name: "multi-part template with coalesce and valid string stops before missing fallback",
			expr: `"prefix-${coalesce(var.valid_str, var.missing)}"`,
			want: false,
		},
		{
			name: "multi-part template with trailing literal and coalesce stops before missing fallback",
			expr: `"${coalesce(var.valid_str, var.missing)}-suffix"`,
			want: false,
		},
		{
			name: "multi-part template surrounded by literals stops before missing fallback",
			expr: `"pre-${coalesce(var.valid_str, var.missing)}-post"`,
			want: false,
		},
		{
			name: "multi-part template with try and declared null stops before missing fallback",
			expr: `"prefix-${try(var.declared_null, var.missing)}"`,
			want: false,
		},
		{
			name: "multi-part template with unresolvable reference in coalesce retains protection",
			expr: `"prefix-${coalesce(var.declared_null, var.missing)}"`,
			want: true,
		},
		{
			name: "multi-part template directly referencing missing variable retains protection",
			expr: `"prefix-${var.missing}"`,
			want: true,
		},

		// Tuples (TupleConsExpr)
		{
			name: "tuple with coalesce and valid string stops before missing fallback",
			expr: `[coalesce(var.valid_str, var.missing)]`,
			want: false,
		},
		{
			name: "tuple with multiple elements and valid coalesce stops before missing fallback",
			expr: `["item", coalesce(var.valid_str, var.missing)]`,
			want: false,
		},
		{
			name: "tuple with unresolvable fallback in coalesce retains protection",
			expr: `[coalesce(var.declared_null, var.missing)]`,
			want: true,
		},
		{
			name: "tuple with missing variable retains protection",
			expr: `["item", var.missing]`,
			want: true,
		},

		// Objects (ObjectConsExpr)
		{
			name: "object with coalesce and valid string stops before missing fallback",
			expr: `{ key = coalesce(var.valid_str, var.missing) }`,
			want: false,
		},
		{
			name: "object with unresolvable fallback in coalesce retains protection",
			expr: `{ key = coalesce(var.declared_null, var.missing) }`,
			want: true,
		},
		{
			name: "object with missing variable value retains protection",
			expr: `{ key = var.missing }`,
			want: true,
		},

		// can(...) function calls
		{
			name: "can with valid variable resolves without error",
			expr: `can(var.valid_str)`,
			want: false,
		},
		{
			name: "can with missing variable retains protection",
			expr: `can(var.missing)`,
			want: true,
		},
		{
			name: "can with missing attribute on known object evaluates safely without unresolvable reference",
			expr: `can(var.valid_obj.missing_attr)`,
			want: false,
		},
		{
			name: "can with index out of bounds on empty list evaluates safely",
			expr: `can([][0])`,
			want: false,
		},
		{
			name: "can with coalesce stopping before missing fallback resolves without error",
			expr: `can(coalesce(var.valid_str, var.missing))`,
			want: false,
		},
		{
			name: "conditional guarded by can with valid variable selects true branch",
			expr: `can(var.valid_str) ? var.valid_str : "fallback"`,
			want: false,
		},
		{
			name: "conditional guarded by can with missing variable retains protection",
			expr: `can(var.missing) ? var.missing : "fallback"`,
			want: true,
		},
		{
			name: "conditional guarded by can on missing attribute on known object selects false branch cleanly",
			expr: `can(var.valid_obj.missing_attr) ? var.valid_obj.missing_attr : "fallback"`,
			want: false,
		},

		// Operators & general functions
		{
			name: "unary negation of can with valid variable",
			expr: `!can(var.valid_str)`,
			want: false,
		},
		{
			name: "unary negation of can with missing variable retains protection",
			expr: `!can(var.missing)`,
			want: true,
		},
		{
			name: "binary addition with coalesce stops before missing fallback",
			expr: `coalesce(var.valid_num, var.missing) + 5`,
			want: false,
		},
		{
			name: "binary addition with missing variable retains protection",
			expr: `var.missing + 5`,
			want: true,
		},
		{
			name: "general function call upper wrapping coalesce stops before missing fallback",
			expr: `upper(coalesce(var.valid_str, var.missing))`,
			want: false,
		},
		{
			name: "general function call upper with missing variable retains protection",
			expr: `upper(var.missing)`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte("x = "+tt.expr), "test.tf", hcl.Pos{Line: 1, Column: 1})
			require.False(t, diags.HasErrors())
			attr := file.Body.(*hclsyntax.Body).Attributes["x"]
			got := hasUnresolvableVariables(attr.Expr, evalCtx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractTypedResources_CompoundAndCanExpressions(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "template_coalesce" {
  metadata {
    name      = "template_coalesce"
    namespace = "ns-${coalesce(var.valid_str, var.missing)}"
  }
}

resource "kubernetes_service_account_v1" "template_unresolvable" {
  metadata {
    name      = "template_unresolvable"
    namespace = "ns-${coalesce(var.declared_null, var.missing)}"
  }
}

resource "kubernetes_service_account_v1" "can_guard_valid" {
  metadata {
    name      = "can_guard_valid"
    namespace = can(var.valid_str) ? "custom" : var.missing
  }
}

resource "kubernetes_service_account_v1" "can_guard_missing" {
  metadata {
    name      = "can_guard_missing"
    namespace = can(var.missing) ? var.missing : null
  }
}

resource "kubernetes_service_account_v1" "can_missing_attribute_null" {
  metadata {
    name      = "can_missing_attribute_null"
    namespace = can(var.valid_obj.missing_attr) ? var.valid_obj.missing_attr : null
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null": cty.NullVal(cty.String),
				"valid_str":     cty.StringVal("prod"),
				"valid_obj": cty.ObjectVal(map[string]cty.Value{
					"name": cty.StringVal("my-app"),
				}),
			}),
		},
		Functions: terraformFunctions,
	}

	manifests, _ := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Len(t, manifests, 5)

	byName := map[string]map[string]interface{}{}
	for _, m := range manifests {
		byName[m["metadata"].(map[string]interface{})["name"].(string)] = m
	}

	assert.Equal(t, "ns-prod", byName["template_coalesce"]["metadata"].(map[string]interface{})["namespace"],
		"multi-part template with resolved coalesce should retain resolved value")

	assert.NotContains(t, byName["template_unresolvable"]["metadata"].(map[string]interface{}), "namespace",
		"multi-part template falling back to unresolvable variable should not receive provider default")

	assert.Equal(t, "custom", byName["can_guard_valid"]["metadata"].(map[string]interface{})["namespace"],
		"can() guard on valid variable should select true branch and keep resolved value")

	assert.NotContains(t, byName["can_guard_missing"]["metadata"].(map[string]interface{}), "namespace",
		"can() guard on unresolvable variable should not receive provider default")

	assert.Equal(t, "default", byName["can_missing_attribute_null"]["metadata"].(map[string]interface{})["namespace"],
		"can() guard catching missing attribute on known object should evaluate false branch to null and receive provider default")
}

func TestHasUnresolvableVariables_ObjectKeys(t *testing.T) {
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"valid_str": cty.StringVal("prod"),
			}),
		},
		Functions: terraformFunctions,
	}

	tests := []struct {
		name string
		expr string
		want bool
	}{
		{
			name: "key where try catches a missing variable",
			expr: `{ (try("key", var.missing)) = null }`,
			want: false,
		},
		{
			name: "key from a resolved variable",
			expr: `{ (var.valid_str) = null }`,
			want: false,
		},
		{
			name: "key from a missing variable retains protection",
			expr: `{ (var.missing) = null }`,
			want: true,
		},
		{
			name: "key falling back to a missing variable retains protection",
			expr: `{ (try(var.missing, "key")) = null }`,
			want: true,
		},
		{
			name: "bare name key is a literal string",
			expr: `{ missing = null }`,
			want: false,
		},
		{
			name: "missing variable in the value retains protection",
			expr: `{ (try("key", var.missing)) = var.missing }`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, diags := hclsyntax.ParseConfig([]byte("x = "+tt.expr), "test.tf", hcl.Pos{Line: 1, Column: 1})
			require.False(t, diags.HasErrors())
			attr := file.Body.(*hclsyntax.Body).Attributes["x"]
			got := hasUnresolvableVariables(attr.Expr, evalCtx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractTypedResourcesResolvesObjectKeysThatTryCatches(t *testing.T) {
	src := `
resource "kubernetes_service_account_v1" "key_in_value" {
  metadata {
    name      = "key_in_value"
    namespace = contains(keys({ (try("ns", var.missing)) = true }), "ns") ? "team-a" : null
  }
}

resource "kubernetes_service_account_v1" "key_before_default" {
  metadata {
    name      = "key_before_default"
    namespace = contains(keys({ (try("ns", var.missing)) = true }), "other") ? "team-a" : null
  }
}

resource "kubernetes_service_account_v1" "missing_key" {
  metadata {
    name      = "missing_key"
    namespace = contains(keys({ (var.missing) = true }), "other") ? "team-a" : null
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"var": cty.EmptyObjectVal},
		Functions: terraformFunctions,
	}

	manifests, _ := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Len(t, manifests, 3)

	byName := map[string]map[string]interface{}{}
	for _, m := range manifests {
		byName[m["metadata"].(map[string]interface{})["name"].(string)] = m
	}

	assert.Equal(t, "team-a", byName["key_in_value"]["metadata"].(map[string]interface{})["namespace"],
		"an object key that try() resolves should keep the evaluated namespace")
	assert.Equal(t, "default", byName["key_before_default"]["metadata"].(map[string]interface{})["namespace"],
		"an object key that try() resolves should not block the provider default")
	assert.NotContains(t, byName["missing_key"]["metadata"].(map[string]interface{}), "namespace",
		"an object key from an unresolvable variable should not receive the provider default")
}
