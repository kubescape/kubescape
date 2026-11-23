package cautils

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
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
		`concat(local.options.safe, local.options_alias.other)`,
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
  options = { safe = [], other = [], unrelated = try(var.missing, []) }
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

func TestTerraformDirectoryDynamicLookupSelections(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		wantErrors bool
	}{
		{"direct field", `local.options.safe`, false},
		{"selected field", `lookup(local.options, "safe", [])`, false},
		{"local alias", `lookup(local.alias, "safe", [])`, false},
		{"unused default", `lookup({safe = []}, "safe", try(var.unresolved, []))`, false},
		{"unused unavailable default", `lookup({safe = []}, "safe", try(fileset(".", "*.tf"), []))`, false},
		{"unused expanded default", `lookup({safe = []}, "safe", [try(var.unresolved, [])]...)`, false},
		{"expanded arguments", `lookup([{safe = []}, "safe", try(var.unresolved, [])]...)`, false},
		{"missing key", `lookup(local.options, "absent", [])`, false},
		{"selected nested field", `lookup({settings = local.options}, "settings", {}).safe`, false},
		{"selected default field", `lookup({}, "absent", local.options).safe`, false},
		{"selected comprehension", `lookup({for name in ["safe", "other"] : name => (name == "safe" ? [] : try(var.unresolved, []))}, "safe", [])`, false},
		{"omitted unused default", `lookup(local.options, "safe")`, false},
		{"caught missing key", `try(lookup({safe = []}, "absent"), [])`, false},
		{"caught missing key with unrelated input", `try(lookup(local.options, "absent"), [])`, false},
		{"known map default", `lookup(tomap({safe = []}), "safe", [])`, false},
		{"caught invalid source", `try(lookup("not a map", "safe", []), [])`, false},
		{"unresolved key", `lookup({safe = []}, try(var.field, "safe"), [])`, true},
		{"unresolved source", `lookup(try(var.source, {safe = []}), "safe", [])`, true},
		{"unresolved selected value", `lookup(local.options, "unrelated", [])`, true},
		{"unresolved required default", `lookup({}, "absent", try(var.unresolved, []))`, true},
		{"unresolved argument diagnostic", `try(lookup({safe = [true]}, "safe", var.unresolved), [])`, true},
		{"unresolved expanded default", `lookup({}, "absent", [local.options]...).unrelated`, true},
		{"unresolved object key", `lookup({(try(var.field, "safe")) = []}, "absent", [])`, true},
		{"unresolved object key before missing lookup", `try(lookup({(try(var.field, "safe")) = [true]}, "absent"), [])`, true},
		{"unresolved lookup key before missing lookup", `try(lookup({safe = [true]}, try(var.field, "absent")), [])`, true},
		{"unresolved later comprehension key", `lookup({for name in ["safe", "other"] : (name == "safe" ? "safe" : try(var.field, "other")) => []}, "safe", [])`, true},
		{"unresolved map default validation", `lookup(tomap({safe = []}), "safe", try(var.unresolved, []))`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "unresolved" { type = list(bool) }
variable "field" { type = string }
variable "source" { type = map(list(bool)) }
locals {
  options = { safe = [], unrelated = try(var.unresolved, []) }
  alias = local.options
}
resource "kubernetes_pod_v1" "demo" {
  metadata { name = "lookup-review" }
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
}`, tc.expression)})
			obj, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs, "lookup must preserve dependencies needed to select or validate its result")
			} else {
				require.Empty(t, errs, "lookup must ignore values outside the selected result")
				assert.NotContains(t, terraformFirstContainer(t, obj), "securityContext")
			}
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
		`[for item in [{}] : try(item.enabled, true)]`,
		`[for var in [{}] : try(var.enabled, true)]`,
		`[for local in [{}] : try(local.enabled, true)]`,
		`[for item in [{}] : can(item.enabled) ? false : true]`,
		`lookup({contexts = [1]}, "contexts", [])`,
		`lookup({}, "absent", [1])`,
		`lookup({"1" = [1]}, 1, [])`,
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
		{
			"late unresolved noncolliding key", `variable "key" { type = string }`,
			`{for item in [0, 1] : (item == 0 ? "selected" : try(var.key, "other")) => [true]}.selected`, true,
		},
		{
			"late unresolved grouped key", `variable "key" { type = string }`,
			`{for item in [0, 1] : (item == 0 ? "selected" : try(var.key, "other")) => [true]...}.selected[0]`, true,
		},
		{
			"late unresolved successful filter", `variable "include" { type = bool }`,
			`([for item in [0, 1] : [true] if (item == 0 ? true : try(var.include, true))])[0]`, true,
		},
		{
			"unused unresolved value", "",
			`{for item in [0, 1] : (item == 0 ? "selected" : "other") => (item == 0 ? [true] : try(var.missing, []))}.selected`, false,
		},
		{
			"unresolved key after invalid filter", `variable "key" { type = string }`,
			`try({for item in [0, 1, 2] : (item == 2 ? try(var.key, "other") : "selected") => [true] if (item == 1 ? null : true)}.selected, [])`, true,
		},
		{
			"invalid key skips unused value", "",
			`try({for item in [0, 1] : (item == 0 ? "selected" : null) => (item == 0 ? [true] : try(var.missing, []))}.selected, [true])`, false,
		},
		{
			"failed source retains diagnostics", "",
			`try({for item in [0, 1] : "selected" => (item == 0 ? [true] : try(var.missing, [true]))}.selected, [])`, true,
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

func TestTerraformDirectoryDynamicTemplateLoops(t *testing.T) {
	for _, tc := range []struct {
		expression string
		wantErrors bool
		wantName   string
	}{
		{`"app-%{ for item in [1] }${try(unavailable(), "fallback")}%{ endfor }"`, true, ""},
		{`"app-%{ for item in [] }${try(unavailable(), "fallback")}%{ endfor }"`, false, "app-"},
		{`"app-%{ for item in [1] }${try("known", unavailable())}%{ endfor }"`, false, "app-known"},
		{`"app-%{ for item in [{}] }${try(item.name, "fallback")}%{ endfor }"`, false, "app-fallback"},
	} {
		t.Run(tc.expression, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
resource "kubernetes_pod_v1" "demo" {
  spec {
    dynamic "container" {
      for_each = [1]
      content {
        name = %s
        image = "nginx"
      }
    }
  }
}`, tc.expression)})
			obj, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs)
			} else {
				require.Empty(t, errs)
				assert.Equal(t, tc.wantName, terraformFirstContainer(t, obj)["name"])
			}
		})
	}
}

func TestTerraformDynamicSplatEvaluationIsLinear(t *testing.T) {
	for _, filter := range []string{"", " if included(item)"} {
		t.Run(filter, func(t *testing.T) {
			const count = 64
			body := parseTypedHCL(t, fmt.Sprintf(`value = [for item in source() : { enabled = counted(item) }%s][*].enabled`, filter))
			items := make([]cty.Value, count)
			for i := range items {
				items[i] = cty.NumberIntVal(int64(i))
			}
			sourceCalls, valueCalls, filterCalls := 0, 0, 0
			ctx := &hcl.EvalContext{Functions: map[string]function.Function{
				"source": function.New(&function.Spec{
					Type: function.StaticReturnType(cty.TupleVal(items).Type()),
					Impl: func([]cty.Value, cty.Type) (cty.Value, error) {
						sourceCalls++
						return cty.TupleVal(items), nil
					},
				}),
			}}
			for name, calls := range map[string]*int{"counted": &valueCalls, "included": &filterCalls} {
				ctx.Functions[name] = function.New(&function.Spec{
					Params: []function.Parameter{{Name: "item", Type: cty.Number}},
					Type:   function.StaticReturnType(cty.Bool),
					Impl: func([]cty.Value, cty.Type) (cty.Value, error) {
						(*calls)++
						return cty.True, nil
					},
				})
			}
			assert.False(t, hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
			assert.LessOrEqual(t, sourceCalls, 8, "the source must not be evaluated per selected element")
			assert.LessOrEqual(t, valueCalls, 8*count, "the comprehension must not be rebuilt per selected element")
			assert.LessOrEqual(t, filterCalls, 8*count, "filters must not be rechecked per selected element")
			t.Logf("items=%d source=%d values=%d filters=%d", count, sourceCalls, valueCalls, filterCalls)
		})
	}
}

type terraformCountingExpression struct {
	hclsyntax.Expression
	visits *int
}

func (e *terraformCountingExpression) Variables() []hcl.Traversal {
	(*e.visits)++
	return e.Expression.Variables()
}

func TestTerraformDynamicSplatReferenceChecksAreLinear(t *testing.T) {
	const count = 64
	items := make([]cty.Value, count)
	for i := range items {
		items[i] = cty.True
	}
	for _, source := range []string{
		`[for item in var.items : item]`,
		`tolist([for item in var.items : item])`,
		`concat([for item in var.items : item], [])`,
		`flatten([[for item in var.items : item]])`,
		`try(tolist([for item in var.items : item]), [])`,
	} {
		for _, useLocal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/local=%t", source, useLocal), func(t *testing.T) {
				sourceBody := parseTypedHCL(t, "value = "+source)
				sourceExpr := sourceBody.Attributes["value"].Expr
				visits := 0
				hclsyntax.VisitAll(sourceExpr, func(node hclsyntax.Node) hcl.Diagnostics {
					if loop, ok := node.(*hclsyntax.ForExpr); ok {
						loop.ValExpr = &terraformCountingExpression{Expression: loop.ValExpr, visits: &visits}
					}
					return nil
				})
				ctx := newTerraformEvalContext(map[string]cty.Value{"items": cty.TupleVal(items)}, nil)
				checker := terraformReferenceChecker{moduleCtx: ctx}
				var expr hcl.Expression
				if useLocal {
					value, diags := sourceExpr.Value(ctx)
					require.False(t, diags.HasErrors(), diags.Error())
					ctx.Variables["local"] = cty.ObjectVal(map[string]cty.Value{"source": value})
					checker.localExpressions = map[string]hcl.Expression{"source": sourceExpr}
					expr = parseTypedHCL(t, `value = local.source[*]`).Attributes["value"].Expr
				} else {
					// Keep the instrumented source in the actual splat expression.
					splat := parseTypedHCL(t, `value = [][*]`).Attributes["value"].Expr.(*hclsyntax.SplatExpr)
					splat.Source = sourceExpr
					expr = splat
				}
				require.False(t, checker.hasUnresolvableVariables(expr, ctx))
				assert.LessOrEqual(t, visits, 2*count, "wrappers and local aliases must not recheck the entire source per output")
				t.Logf("items=%d reference checks=%d", count, visits)
			})
		}
	}
}

func TestTerraformDynamicNestedSplatReferenceChecksAreLinear(t *testing.T) {
	var previous float64
	for _, count := range []int{128, 256} {
		body := parseTypedHCL(t, `value = (var.items[*])[*]`)
		items := make([]cty.Value, count)
		for i := range items {
			items[i] = cty.True
		}
		ctx := newTerraformEvalContext(map[string]cty.Value{"items": cty.TupleVal(items)}, nil)
		allocs := testing.AllocsPerRun(1, func() {
			require.False(t, hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
		})
		if previous != 0 {
			assert.Less(t, allocs, 3*previous, "doubling a nested splat must not quadruple allocation work")
		}
		t.Logf("items=%d allocations=%.0f", count, allocs)
		previous = allocs
	}
}

func TestTerraformDirectoryDynamicLocalCycles(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
locals { options = try(local["options"].next, { next = [] }) }
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = local.options.next
        content { privileged = true }
      }
    }
  }
}`})
	_, errs := terraformObject(t, dir)
	require.NotEmpty(t, errs, "a computed self-reference must return a loading error")
}

func TestTerraformDynamicReferenceEvaluationScopes(t *testing.T) {
	body := parseTypedHCL(t, `value = [for item in [try(var.enabled, true)] : item][*]`)
	checker := terraformReferenceChecker{}
	for _, tc := range []struct {
		vars       map[string]cty.Value
		unresolved bool
	}{
		{map[string]cty.Value{"enabled": cty.True}, false},
		{map[string]cty.Value{}, true},
	} {
		ctx := newTerraformEvalContext(tc.vars, nil)
		assert.Equal(t, tc.unresolved, checker.hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
		assert.Nil(t, checker.evaluations, "evaluated values must not be retained between checks")
		assert.Nil(t, checker.referenceResults, "completed reference checks must not be retained between checks")
		assert.Nil(t, checker.forItems, "comprehension bindings must not be retained between checks")
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
