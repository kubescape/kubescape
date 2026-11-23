package cautils

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

func TestTerraformDirectoryDynamicSecurityContext(t *testing.T) {
	for _, privileged := range []bool{true, false} {
		t.Run(fmt.Sprint(privileged), func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
resource "kubernetes_pod_v1" "demo" {
  metadata { name = "privileged-demo" }
  spec {
    container {
      name  = "web"
      image = "nginx:1.27"
      dynamic "security_context" {
        for_each = [1]
        content { privileged = %t }
      }
    }
  }
}`, privileged)})
			obj, errs := terraformObject(t, dir)
			require.Empty(t, errs)
			container := terraformFirstContainer(t, obj)
			assert.Equal(t, map[string]interface{}{"privileged": privileged}, container["securityContext"])
			assert.NotContains(t, container, "dynamic")
		})
	}
}

func TestTerraformDirectoryDynamicBlockIterators(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
locals {
  apps = {
    first  = true
    second = false
  }
}
resource "kubernetes_pod_v1" "demo" {
  dynamic "metadata" {
    for_each = ["demo"]
    content { name = metadata.value }
  }
  spec {
    container {
      name  = "before"
      image = "nginx"
    }
    dynamic "container" {
      for_each = local.apps
      iterator = app
      content {
        name  = app.key
        image = "nginx"
        dynamic "security_context" {
          for_each = [app.value]
          content { privileged = security_context.value }
        }
        dynamic "port" {
          for_each = toset([80, 443])
          iterator = p
          content { container_port = p.value }
        }
      }
    }
    container {
      name  = "after"
      image = "nginx"
    }
  }
}`})
	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs)
	assert.Equal(t, map[string]interface{}{"name": "demo", "namespace": "default"}, obj["metadata"])
	spec := obj["spec"].(map[string]interface{})
	assert.Equal(t, true, spec["automountServiceAccountToken"])
	containers := spec["containers"].([]interface{})
	require.Len(t, containers, 4)
	for i, name := range []string{"before", "first", "second", "after"} {
		assert.Equal(t, name, containers[i].(map[string]interface{})["name"])
	}
	for i, privileged := range []bool{true, false} {
		container := containers[i+1].(map[string]interface{})
		assert.Equal(t, map[string]interface{}{"privileged": privileged}, container["securityContext"])
		ports := container["ports"].([]interface{})
		require.Len(t, ports, 2)
		assert.Equal(t, json.Number("80"), ports[0].(map[string]interface{})["containerPort"])
		assert.Equal(t, json.Number("443"), ports[1].(map[string]interface{})["containerPort"])
	}
}

func TestTerraformDirectoryEmptyDynamicBlock(t *testing.T) {
	for _, collection := range []string{
		`[]`, `{}`, `toset([])`, `var.contexts`, `local.contexts`,
		`try(var.contexts, [])`, `try([], var.missing)`,
		`try(var.settings.missing, [])`, `true ? [] : var.missing`,
		`[for item in [] : var.missing]`,
		`[for item in [1] : var.missing if false]`,
		`local[var.selection]`, `try([], local.unresolved)`,
		`local.options.safe`, `local.options_alias.safe`,
		`local.options[var.field]`,
		`try({ contexts = [] }, var.missing).contexts`,
		`try([], var.missing)[*]`,
		`try(local.tuple[99], [])`, `local.for_options[0]`,
		`local.tuple["0"]`, `local.for_options["0"]`,
		`{for name in ["safe", "other"] : name => name == "safe" ? [] : try(var.missing, [])}.safe`,
		`{for name in ["safe", "other"] : name => (name == "safe" ? [] : try(var.missing, []))...}.safe[0]`,
		`([local.options][*].safe)[0]`,
		`try([], fileset(".", "*.tf"))`,
	} {
		t.Run(collection, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "contexts" { default = [] }
variable "settings" { default = {} }
variable "selection" { default = "contexts" }
variable "field" { default = "safe" }
locals {
  contexts = []
  unresolved = try(var.missing, [])
  options = { safe = [], unrelated = try(var.missing, []) }
  options_alias = local.options
  tuple = [[], try(var.missing, [])]
  for_options = [for choose in [false, true] : choose ? try(var.missing, []) : []]
}
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name  = "web"
      image = "nginx"
      dynamic "security_context" {
        for_each = %s
        content { privileged = var.not_evaluated }
      }
    }
  }
}`, collection)})
			obj, errs := terraformObject(t, dir)
			require.Empty(t, errs, "an empty iteration must not evaluate its content")
			container := terraformFirstContainer(t, obj)
			assert.NotContains(t, container, "securityContext")
			assert.NotContains(t, container, "dynamic")
		})
	}
}

func TestTerraformDirectoryKnownDynamicCollections(t *testing.T) {
	for _, collection := range []string{
		`{ ctx = 1 }`, `{ (try("ctx", var.missing)) = 1 }`,
		`[for item in [1] : try(item, var.missing)]`,
		`[for item in [1] : item if true ? true : can(var.missing)]`,
		`try([1], var.missing)[*]`,
		`[ [1] ][*][try(0, var.missing)]`,
	} {
		t.Run(collection, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = %s
        content { privileged = true }
      }
    }
  }
}`, collection)})
			obj, errs := terraformObject(t, dir)
			require.Empty(t, errs, "known collections must ignore unused unresolved fallbacks")
			assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
		})
	}
}

func TestTerraformDirectoryInvalidDynamicBlocks(t *testing.T) {
	for name, body := range map[string]string{
		"unresolved collection": `for_each = var.missing
content { privileged = true }`,
		"unresolved empty fallback": `for_each = try(var.missing, [])
content { privileged = true }`,
		"unresolved nonempty fallback": `for_each = try(var.missing, [true])
content { privileged = true }`,
		"unresolved nested fallback": `for_each = try(try(var.missing, []), [])
content { privileged = true }`,
		"unresolved condition": `for_each = can(var.missing) ? [1] : []
content { privileged = true }`,
		"unresolved local fallback": `for_each = local.unresolved
content { privileged = true }`,
		"unresolved local alias": `for_each = local.alias
content { privileged = true }`,
		"unresolved selected local": `for_each = local[var.selection]
content { privileged = true }`,
		"unresolved local try": `for_each = try(local.alias, [])
content { privileged = true }`,
		"unresolved comprehension": `for_each = [for item in [1] : try(var.missing, true)]
content { privileged = true }`,
		"unresolved object key": `for_each = { (try(var.missing, "key")) = 1 }
content { privileged = true }`,
		"unresolved relative traversal": `for_each = try(var.missing, { contexts = [] }).contexts
content { privileged = true }`,
		"unresolved splat source": `for_each = try(var.missing, [1])[*]
content { privileged = true }`,
		"unresolved splat index": `for_each = [[1]][*][try(var.missing, 0)]
content { privileged = true }`,
		"unresolved tuple string index": `for_each = local.tuple["0"]
content { privileged = true }`,
		"unresolved comprehension string index": `for_each = local.for_options["0"]
content { privileged = true }`,
		"unresolved object comprehension field": `for_each = {for name in ["safe", "risky"] : name => name == "safe" ? [] : try(var.missing, [])}.risky
content { privileged = true }`,
		"unresolved selected splat field": `for_each = ([local.options][*].risky)[0]
content { privileged = true }`,
		"unsupported collection function": `for_each = try(fileset(".", "*.tf"), [])
content { privileged = true }`,
		"null collection": `for_each = null
content { privileged = true }`,
		"scalar collection": `for_each = true
content { privileged = true }`,
		"invalid iterator": `for_each = [1]
iterator = "item"
content { privileged = true }`,
		"missing content":  `for_each = [1]`,
		"missing for_each": `content { privileged = true }`,
		"duplicate content": `for_each = [1]
content { privileged = true }
content { privileged = false }`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "selection" { default = "unresolved" }
locals {
  unresolved = try(var.missing, [])
  alias = local.unresolved
  tuple = [try(var.missing, []), []]
  for_options = [for chosen in [true, false] : chosen ? try(var.missing, []) : []]
  options = { safe = [], risky = try(var.missing, []) }
}
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name  = "web"
      image = "nginx"
      dynamic "security_context" {
        %s
      }
    }
  }
}`, body)})
			obj, errs := terraformObject(t, dir)
			require.NotEmpty(t, errs, "unresolved dynamic blocks must be reported, not silently passed")
			assert.Contains(t, fmt.Sprint(errs), "dynamic")
			assert.NotContains(t, terraformFirstContainer(t, obj), "dynamic")
		})
	}
}

func TestTerraformDirectoryDynamicContentReferences(t *testing.T) {
	for _, tc := range []struct {
		expression string
		wantErrors bool
	}{
		{`try(var.missing, null)`, true},
		{`local.privileged`, true},
		{`try(var.missing, true)`, true},
		{`try(unavailable(), null)`, true},
		{`var.declared_null`, false},
		{`try(var.settings.privileged, null)`, false},
		{`try(null, var.missing)`, false},
		{`try(null, unavailable())`, false},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "declared_null" { default = null }
variable "settings" { default = {} }
locals { privileged = try(var.missing, null) }
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = [1]
        content { privileged = %s }
      }
    }
  }
}`, tc.expression)})
			_, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs, "generated fields must not silently omit unresolved values")
			} else {
				require.Empty(t, errs, "legitimate null values must stay valid")
			}
		})
	}
}

func TestTerraformDirectoryDynamicFailedComprehensions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		declaration string
		collection  string
		wantErrors  bool
	}{
		{
			"late unresolved object key", `variable "key" { type = string }`,
			`try(({for item in [0, 1] : (item == 0 ? "selected" : try(var.key, "selected")) => [true]}).selected, [])`, true,
		},
		{
			"early unresolved object key", `variable "key" { type = string }`,
			`try(({for item in [1, 0] : (item == 0 ? "selected" : try(var.key, "selected")) => [true]}).selected, [])`, true,
		},
		{
			"resolved object key", `variable "key" { default = "other" }`,
			`try(({for item in [0, 1] : (item == 0 ? "selected" : try(var.key, "selected")) => [true]}).selected, [])`, false,
		},
		{
			"late unresolved filter", `variable "include" { type = bool }`,
			`try(([for item in [0, 1] : [true] if (item == 0 ? true : var.include)])[0], [])`, true,
		},
		{
			"early unresolved filter", `variable "include" { type = bool }`,
			`try(([for item in [1, 0] : [true] if (item == 0 ? true : var.include)])[0], [])`, true,
		},
		{
			"resolved filter", `variable "include" { default = true }`,
			`try(([for item in [0, 1] : [true] if (item == 0 ? true : var.include)])[0], [])`, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
%s
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = %s
        content { privileged = true }
      }
    }
  }
}`, tc.declaration, tc.collection)})
			obj, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs, "failed constructions must not hide unresolved later expressions")
			} else {
				require.Empty(t, errs)
				assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
			}
		})
	}
}

func TestTerraformDirectoryDynamicLocalScopes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		localExpr  string
		iterator   string
		collection string
		wantErrors bool
	}{
		{"module locals ignore iterator var", `try(var.value, [])`, "var", "local.contexts", true},
		{"iterator local shadows module locals", `try(var.missing, [])`, "local", "local.value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
locals { contexts = %s }
resource "kubernetes_pod_v1" "demo" {
  spec {
    dynamic "container" {
      for_each = [[]]
      iterator = %s
      content {
        name = "app"
        image = "nginx"
        dynamic "security_context" {
          for_each = %s
          content { privileged = true }
        }
      }
    }
  }
}`, tc.localExpr, tc.iterator, tc.collection)})
			_, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs, "iterator bindings must not resolve missing module inputs")
			} else {
				require.Empty(t, errs, "iterator bindings must shadow module locals")
			}
		})
	}
}

func TestTerraformDirectoryDynamicChecksPreserveStaticLocals(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
locals { privileged = try(var.missing, true) }
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      security_context { privileged = local.privileged }
      dynamic "port" {
        for_each = [80]
        content { container_port = port.value }
      }
    }
  }
}`})
	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs)
	assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
}

func TestTerraformDynamicBlocksBoundNestedExpansion(t *testing.T) {
	body := parseTypedHCL(t, `
dynamic "container" {
  for_each = range(200)
  content {
    name = "app-${container.key}"
    dynamic "port" {
      for_each = range(200)
      content { container_port = port.value + 1 }
    }
  }
}`)
	var errs []error
	hclBodyToMap(body, &hcl.EvalContext{Functions: terraformFunctions}, &errs, "kubernetes_pod_v1.demo.spec")
	require.NotEmpty(t, errs)
	assert.Contains(t, fmt.Sprint(errs), "dynamic block expansion exceeds the size limit")
}

func TestTerraformDynamicReferenceCacheBoundsNumericKeys(t *testing.T) {
	body := parseTypedHCL(t, `
dynamic "security_context" {
  for_each = try(local.options[1e-100000], [])
  content { privileged = true }
}`)
	locals := parseTypedHCL(t, `options = [[]]`)
	ctx := newTerraformEvalContext(map[string]cty.Value{}, map[string]cty.Value{
		"options": cty.TupleVal([]cty.Value{cty.EmptyTupleVal}),
	})
	var errs []error
	converter := terraformBodyConverter{
		errs: &errs, remaining: maxTerraformLocalSize,
		references: terraformReferenceChecker{
			localExpressions: map[string]hcl.Expression{"options": locals.Attributes["options"].Expr},
			moduleCtx:        ctx,
		},
	}
	converter.bodyToMap(body, ctx, "kubernetes_pod_v1.demo.spec.container", false, false)
	require.Empty(t, errs)
	require.NotEmpty(t, converter.references.localResults)
	for key := range converter.references.localResults {
		assert.Less(t, len(key), 256, "tiny numeric selectors must not expand into large decimal cache keys")
	}
}

func TestTerraformDynamicBlocksStopAfterSizeLimit(t *testing.T) {
	body := parseTypedHCL(t, `
dynamic "container" {
  for_each = [1, 2, 3, 4]
  content { name = counted() }
}`)
	calls := 0
	large := cty.StringVal(strings.Repeat("x", maxTerraformLocalSize+1))
	ctx := &hcl.EvalContext{Functions: map[string]function.Function{
		"counted": function.New(&function.Spec{
			Type: function.StaticReturnType(cty.String),
			Impl: func([]cty.Value, cty.Type) (cty.Value, error) {
				calls++
				return large, nil
			},
		}),
	}}
	var errs []error
	hclBodyToMap(body, ctx, &errs, "kubernetes_pod_v1.demo.spec")
	require.NotEmpty(t, errs)
	assert.Equal(t, 1, calls, "later generated values must not evaluate after the expansion limit fails")
}

func TestTerraformDynamicBlocksExactBudgetReportsOmittedFields(t *testing.T) {
	body := parseTypedHCL(t, `
dynamic "security_context" {
  for_each = [1]
  content { privileged = true }
}`)
	var errs []error
	converter := terraformBodyConverter{errs: &errs, remaining: terraformElementOverhead}
	converter.bodyToMap(body, &hcl.EvalContext{}, "kubernetes_pod_v1.demo.spec.container", false, false)
	require.NotEmpty(t, errs, "reserving block overhead must not silently omit its security fields")
	assert.Contains(t, fmt.Sprint(errs), "dynamic block expansion exceeds the size limit")
}
