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
		{"expanded local default", `lookup({safe = []}, "safe", local.defaults...)`, false},
		{"expanded local arguments", `lookup(local.lookup_args...)`, false},
		{"expanded required local default", `lookup({}, "absent", local.defaults...)`, true},
		{"unresolved expansion arity", `lookup({safe = []}, "safe", local.risky_args...)`, true},
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
variable "args" { type = any }
locals {
  options = { safe = [], unrelated = try(var.unresolved, []) }
  alias = local.options
  defaults = [try(var.unresolved, [])]
  lookup_args = [{safe = []}, "safe", try(var.unresolved, [])]
  risky_args = try(var.args, [try(var.unresolved, [])])
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

func TestTerraformDirectoryDynamicControlDependencies(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		wantErrors bool
		wantBlock  bool
	}{
		{"coalesce type mismatch", `try(coalesce([true], try(var.other, {bad = true})), [])`, true, false},
		{"coalesce type conversion", `coalesce([true], try(var.other, ["false"]))`, true, false},
		{"coalesce unresolved null type", `try(coalesce([{privileged = true}], try(var.other, null)), [])`, true, false},
		{"coalesce unresolved empty string type", `try(coalesce([{privileged = true}], try(var.other, "")), [])`, true, false},
		{"coalesce later missing input widens type", `coalesce([true], var.other)`, true, false},
		{"coalesce ignored null", `coalesce([true], try(null, var.other))`, false, true},
		{"coalesce unused boolean value", `coalesce(true, can(var.enabled)) ? [1] : []`, false, true},
		{"coalesce unused typed fallback", `coalesce(true, try(var.enabled, false)) ? [1] : []`, false, true},
		{"coalesce unused null fallback", `coalesce(true, try(var.enabled, null)) ? [1] : []`, false, true},
		{"coalesce unused typed null fallback", `coalesce(true, try(var.enabled, tostring(null))) ? [1] : []`, false, true},
		{"coalesce unused local boolean", `coalesce(true, local.boolean) ? [1] : []`, false, true},
		{"coalesce unused local alias", `coalesce(true, local.alias) ? [1] : []`, false, true},
		{"coalesce unused tuple values", `coalesce([true], [can(var.enabled)])`, false, true},
		{"coalesce unused object values", `coalesce({contexts = [true]}, {contexts = [can(var.enabled)]}).contexts`, false, true},
		{"coalesce unused conditional value", `coalesce(true, (try(var.enabled, false) ? true : false)) ? [1] : []`, false, true},
		{"coalesce unused function value", `coalesce(true, contains(try(var.other, []), true)) ? [1] : []`, false, true},
		{"coalesce unused lookup value", `coalesce(true, lookup({safe = true}, "absent", can(var.enabled))) ? [1] : []`, false, true},
		{"coalesce unused supplied type", `coalesce([1, true], [var.known, can(var.enabled)])[0] == 1 ? [1] : []`, false, true},
		{"coalesce unused numeric value", `coalesce(1, length(try(var.other, []))) > 0 ? [1] : []`, false, true},
		{"coalesce incompatible function type", `try(coalesce(true, length(try(var.other, []))), [])`, true, false},
		{"coalesce untyped input", `coalesce(true, try(var.untyped, false)) ? [1] : []`, true, false},
		{"coalesce unknown conditional type", `coalesce(true, (true ? try(var.untyped, false) : false)) == true ? [1] : []`, true, false},
		{"coalesce failed branch type hint", `coalesce(1, (can(var.enabled) ? "bad-${[][0]}" : 2)) == 1 ? [1] : []`, true, false},
		{"coalesce null branch type hint", `coalesce(1, (can(var.enabled) ? tostring(null) : 2)) == 1 ? [1] : []`, true, false},
		{"coalesce equal tuple types", `coalesce([true], [false])`, false, true},
		{"coalesce converted tuple types", `coalesce([true], ["false"])`, false, true},
		{"coalesce full argument types", `coalesce(var.numbers, ["2"], try(var.extra, null))[0] == 1 ? [1] : []`, true, false},
		{"coalesce omitted argument type", `coalesce(var.numbers, try(var.extra, toset([2])), ["2"])[0] == 1 ? [1] : []`, true, false},
		{"coalesce stable full argument types", `coalesce(var.numbers, ["2"], [can(var.enabled)])[0] == "1" ? [1] : []`, false, true},
		{"coalesce repeated typed fallbacks", "coalesce(true" + strings.Repeat(", try(var.enabled, false)", 64) + ") ? [1] : []", false, true},
		{"coalesce full argument types with boolean", `coalesce(var.numbers, ["2"], try(var.enabled, null))[0] == 1 ? [1] : []`, true, false},
		{"coalesce nullable can branch", `coalesce(var.numbers, ["2"], (can(var.enabled) ? var.null_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce nullable condition", `coalesce(var.numbers, ["2"], (try(var.enabled, false) ? var.known_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce erroring can branch", `coalesce(var.numbers, ["2"], (can(var.enabled) ? var.numbers[99] : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce erroring Boolean conversion", `coalesce(var.numbers, ["2"], (tobool(can(var.enabled) ? "bad" : "true") ? var.known_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce nullable comparison", `coalesce(var.numbers, ["2"], ((can(var.enabled) ? null : 1) > 0 ? var.known_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce nullable contains collection", `coalesce(var.numbers, ["2"], (contains(can(var.enabled) ? null : [], true) ? var.known_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce independent nullable predicates", `coalesce(var.numbers, ["2"], (can(var.enabled) ? var.known_set : var.null_set), (can(var.include) ? var.null_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce nullable shared condition", `coalesce(var.numbers, ["2"], (try(var.enabled, false) ? var.known_set : var.null_set), (try(var.enabled, false) ? var.null_set : var.known_set))[0] == 1 ? [1] : []`, true, false},
		{"coalesce shared condition erroring arm", `coalesce(var.numbers, ["2"], (can(var.enabled) ? var.known_set : var.null_set), (can(var.enabled) ? var.null_set : var.numbers[99]))[0] == 1 ? [1] : []`, true, false},
		{"nonempty filter missing input", `try([for item in [true] : 1 if var.include || item], [])`, true, false},
		{"nonempty filter constant null", `try([for item in [1] : item if null], [1])`, false, true},
		{"nonempty filter constant invalid type", `try([for item in [1] : item if []], [1])`, false, true},
		{"nonempty filter fixed conditional error", `try([for item in [1] : item if item ? true : false], [1])`, false, true},
		{"nonempty filter fixed null condition", `try([for item in [1] : item if null ? true : false], [1])`, false, true},
		{"filter error type depends on input", `try([for item in [true] : 1 if item ? can(var.known) : length(try(var.untyped, {}))], [])`, true, false},
		{"empty filter missing input", `try([for item in [] : item if var.include], [1])`, true, false},
		{"empty filter unresolved null", `try([for item in [] : item if try(var.include, null)], [1])`, true, false},
		{"empty filter unresolved type", `try([for item in [] : item if try(var.include, [])], [1])`, true, false},
		{"empty filter constant null", `try([for item in [] : item if null], [1])`, false, true},
		{"empty filter constant invalid type", `try([for item in [] : item if []], [1])`, false, true},
		{"empty filter bound iterator", `[for item in [] : var.other if item.enabled]`, false, false},
		{"empty filter bound var", `[for var in [] : var.other if var.enabled]`, false, false},
		{"empty filter unused body", `[for item in [] : var.other if true]`, false, false},
		{"empty filter caught input", `[for item in [] : item if try(var.include, true)]`, false, false},
		{"empty filter static type error", `try([for item in [] : item if item ? 1 : {}], [1])`, false, true},
		{"empty filter invalid operand", `try([for item in [] : item if item + "bad"], [1])`, false, true},
		{"empty filter short circuit", `[for item in [] : item if true || var.include]`, false, false},
		{"logical or left controls", `(true || var.enabled) ? [1] : []`, false, true},
		{"logical and left controls", `(false && var.enabled) ? [] : [1]`, false, true},
		{"logical or right controls", `(var.enabled || true) ? [1] : []`, false, true},
		{"logical and right controls", `(var.enabled && false) ? [] : [1]`, false, true},
		{"logical independent right controls", `(try(var.enabled, true) || true) ? [1] : []`, false, true},
		{"logical unused unavailable call", `(true || contains(fileset(".", "*.tf"), "x")) ? [1] : []`, false, true},
		{"logical required input", `(try(var.enabled, true) || false) ? [1] : []`, true, false},
		{"logical operand conversion", `try((true || try(var.enabled, [true])) ? [1] : [], [])`, true, false},
		{"logical untyped operand conversion", `try((true || try(var.untyped, false)) ? [] : [1], [1])`, true, false},
		{"logical right untyped operand conversion", `try((try(var.untyped, false) || true) ? [] : [1], [1])`, true, false},
		{"logical and untyped operand conversion", `try((false && try(var.untyped, true)) ? [1] : [], [1])`, true, false},
		{"coalesce later argument missing input", `try(coalesce(1, "2", try(var.text, "3"), var.enabled ? [1] : [2]) == "1" ? [] : [1], [1])`, true, false},
		{"coalesce only later argument missing input", `try(coalesce(1, "2", var.enabled ? [1] : [2]) == "1" ? [] : [1], [1])`, true, false},
		{"empty filter successful probe operand conversion", `try([for item in [] : item if true || try(var.untyped, false)], [1])`, true, false},
		{"logical convertible string operand", `(true || (can(var.enabled) ? "true" : "false")) ? [1] : []`, false, true},
		{"logical operand condition conversion", `try((true || (!try(var.untyped, false) ? "true" : "false")) ? [] : [1], [1])`, true, false},
		{"logical nested operand conversion", `try((true || (false || try(var.untyped, false))) ? [] : [1], [1])`, true, false},
		{"coalesce later untyped missing input", `try(coalesce(1, var.untyped) == 1 ? [] : [1], [1])`, true, false},
		{"logical null input index operand", `(true || can(var[null])) ? [1] : []`, false, true},
		{"logical proven Boolean local operand", `(true || local.can_enabled) ? [1] : []`, false, true},
		{"logical inconvertible string operand", `try((true || (can(var.enabled) ? "true" : "maybe")) ? [] : [1], [1])`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "enabled" { type = bool }
variable "include" { type = bool }
variable "other" { type = list(bool) }
variable "untyped" { type = any }
variable "text" { type = string }
variable "known" { default = 1 }
variable "numbers" {
  type = list(number)
  default = [1]
}
variable "extra" { type = set(number) }
variable "known_set" {
  type = set(number)
  default = [2]
}
variable "null_set" {
  type = set(number)
  default = null
}
locals {
  boolean = try(var.enabled, false)
  alias = local.boolean
  can_enabled = can(var.enabled)
}
resource "kubernetes_pod_v1" "demo" {
  metadata { name = "control-dependencies" }
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
				require.NotEmpty(t, errs, "fallbacks must not hide inputs that control expansion")
				assert.Contains(t, fmt.Sprint(errs), "for_each contains unresolved references")
				return
			}
			require.Empty(t, errs)
			container := terraformFirstContainer(t, obj)
			if tc.wantBlock {
				assert.Equal(t, map[string]interface{}{"privileged": true}, container["securityContext"])
			} else {
				assert.NotContains(t, container, "securityContext")
			}
		})
	}
}

func TestTerraformDirectoryDynamicUnusedCanInputs(t *testing.T) {
	for _, expression := range []string{
		`coalesce(var.numbers, ["2"], (can(var.enabled) ? var.extra : var.extra))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (!can(var.enabled) ? var.extra : var.extra))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], ((can(var.enabled) && can(var.enabled)) ? local.alias : local.alias))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (!(can(var.enabled) ? false : false) ? var.extra : var.null_set))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (((can(var.enabled) ? false : false) && can(var.enabled)) ? var.null_set : var.extra))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (tobool(can(var.enabled)) ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (contains([true, false], can(var.enabled)) ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (contains([can(var.enabled)], true) ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (contains([can(var.enabled), "other"], true) ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (length([can(var.enabled)]) == 1 ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (length({enabled = can(var.enabled)}) == 1 ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (tobool(can(var.enabled) ? "true" : "false") ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (can(var.enabled) ? var.extra : var.null_set), (can(var.enabled) ? var.null_set : var.extra))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], (can(var.enabled) ? var.extra : var.null_set), (!can(var.enabled) ? var.extra : var.null_set))[0] == 1 ? [1] : []`,
		`coalesce(var.numbers, ["2"], ((can(var.enabled) ? 1 : 2) > 0 ? var.extra : var.extra2))[0] == 1 ? [1] : []`,
		`try([for item in [false] : item if item ? can(var.enabled) : {}], [1])`,
		`try([for item in [false] : item if item ? tobool(can(var.enabled)) : {}], [1])`,
		`try([for item in [false] : item if item ? contains([true, false], can(var.enabled)) : {}], [1])`,
		`try([for item in [false] : item if item ? contains([can(var.enabled)], true) : {}], [1])`,
		`try([for item in [false] : item if item ? length([can(var.enabled)]) == 1 : {}], [1])`,
		`try([for item in [false] : item if item ? tobool(can(var.enabled) ? "true" : "false") : {}], [1])`,
		`try([for item in [false] : item if item ? (can(var.enabled) ? 1 : 2) > 0 : {}], [1])`,
		`try([for item in [false] : var.unused if item ? can(var.enabled) : {}], [1])`,
		`try([for item in [false] : item if var.enabled ? can(var.enabled) : {}], [1])`,
		`coalesce(var.numbers, ["2"], (can(var.enabled) ? var.extra : var.null_set), (can(var["enabled"]) ? var.null_set : var.extra))[0] == 1 ? [1] : []`,
	} {
		for _, supplied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/supplied=%t", expression, supplied), func(t *testing.T) {
				defaultValue := ""
				if supplied {
					defaultValue = "default = true"
				}
				dir := t.TempDir()
				writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "enabled" {
  type = bool
  %s
}
variable "numbers" {
  type = list(number)
  default = [1]
}
variable "extra" {
  type = set(number)
  default = [2]
}
variable "extra2" {
  type = set(number)
  default = [3]
}
variable "null_set" {
  type = set(number)
  default = null
}
locals { alias = var.extra }
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
}`, defaultValue, expression)})
				obj, errs := terraformObject(t, dir)
				require.Empty(t, errs, "the input cannot change the selected collection")
				assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
			})
		}
	}
}

func TestTerraformDynamicCoalesceTypeChecksAreBounded(t *testing.T) {
	var previous float64
	for _, count := range []int{10, 13} {
		args := []string{`[true]`}
		declared := map[string]terraformVariable{}
		for length := 2; length <= count; length++ {
			name := fmt.Sprintf("optional%d", length)
			elements := make([]cty.Type, length)
			for i := range elements {
				elements[i] = cty.Bool
			}
			declared[name] = terraformVariable{ty: cty.Tuple(elements)}
			args = append(args, "try(var."+name+", [true"+strings.Repeat(", true", length-1)+"])")
		}
		body := parseTypedHCL(t, "value = coalesce("+strings.Join(args, ", ")+")")
		ctx := newTerraformEvalContext(nil, nil)
		allocs := testing.AllocsPerRun(1, func() {
			checker := terraformReferenceChecker{moduleCtx: ctx, declaredVariables: declared}
			require.True(t, checker.hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
		})
		if previous != 0 {
			assert.Less(t, allocs, 3*previous, "adding three optional argument types must not triple analysis work")
		}
		t.Logf("arguments=%d allocations=%.0f", count, allocs)
		previous = allocs
	}
}

func TestTerraformDynamicCoalesceTypeAnalysisMemoryIsLinear(t *testing.T) {
	for _, unresolved := range []bool{false, true} {
		t.Run(fmt.Sprintf("unresolved=%t", unresolved), func(t *testing.T) {
			var previous int64
			for _, count := range []int{1024, 2048} {
				args := make([]string, count)
				for i := range args {
					args[i] = fmt.Sprintf("{field%d = true}", i)
				}
				expression := "coalesce(" + strings.Join(args, ", ") + ")"
				if unresolved {
					expression = "try(coalesce(" + strings.Join(args, ", ") + ", can(var.missing)), [])"
				}
				body := parseTypedHCL(t, "value = "+expression)
				ctx := newTerraformEvalContext(nil, nil)
				require.Equal(t, unresolved, hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
				measurement := testing.Benchmark(func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						hasUnresolvableVariables(body.Attributes["value"].Expr, ctx)
					}
				})
				allocated := measurement.AllocedBytesPerOp()
				if previous != 0 {
					assert.Less(t, allocated, 3*previous, "doubling arguments must not quadruple allocation work")
				}
				t.Logf("arguments=%d bytes=%d", count, allocated)
				previous = allocated
			}
		})
	}
}

func TestTerraformDirectoryDynamicCoalesceInvariantFallbacks(t *testing.T) {
	const count = 2 * maxTypeCombinations
	var variables, fallbacks strings.Builder
	for i := range count {
		// Each distinct tuple type still unifies with list(string) to list(string).
		fmt.Fprintf(&variables, "variable \"t%d\" { type = tuple([%s]) }\n", i, strings.TrimSuffix(strings.Repeat("string, ", i+1), ", "))
		fmt.Fprintf(&fallbacks, ", try(var.t%d, null)", i)
	}
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "names" {
  type = list(string)
  default = ["a"]
}
%s
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = coalesce(var.names%s)[0] == "a" ? [1] : []
        content { privileged = true }
      }
    }
  }
}`, variables.String(), fallbacks.String())})
	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs, "fallbacks of the selected type cannot change unification")
	assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
}

func TestTerraformDynamicCoalesceSharedLocalProofIsBounded(t *testing.T) {
	const count = 256
	source := parseTypedHCL(t, "value = "+strings.Repeat("can(var.missing) || ", count-1)+"can(var.missing)").Attributes["value"].Expr
	expr := parseTypedHCL(t, "value = coalesce(true"+strings.Repeat(", local.alias", count)+")").Attributes["value"].Expr
	ctx := newTerraformEvalContext(nil, map[string]cty.Value{"alias": cty.False})
	allocs := testing.AllocsPerRun(1, func() {
		checker := terraformReferenceChecker{moduleCtx: ctx, localExpressions: map[string]hcl.Expression{"alias": source}}
		require.False(t, checker.hasUnresolvableVariables(expr, ctx), "the local's Boolean value cannot change the result")
	})
	assert.Less(t, allocs, 4_000_000.0, "repeated local references must not repeatedly walk every proof subtree")
	t.Logf("arguments=%d allocations=%.0f", count, allocs)
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
			assert.Nil(t, obj, "the resource is left out rather than scanned without its dynamic block")
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
variable "selection" { default = "options" }
locals { options = try(local[var.selection].next, { next = [] }) }
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
	assert.Contains(t, fmt.Sprint(errs), "for_each contains unresolved references")
}

func TestTerraformDynamicLocalCacheTracksActiveLocals(t *testing.T) {
	body := parseTypedHCL(t, `
a = { safe = [], next = local.b }
b = local.a.safe
first = local.b
second = local.a
`)
	ctx := newTerraformEvalContext(nil, map[string]cty.Value{
		"a": cty.ObjectVal(map[string]cty.Value{"safe": cty.EmptyTupleVal, "next": cty.EmptyTupleVal}),
		"b": cty.EmptyTupleVal,
	})
	checker := terraformReferenceChecker{
		localExpressions: map[string]hcl.Expression{"a": body.Attributes["a"].Expr, "b": body.Attributes["b"].Expr},
		moduleCtx:        ctx,
	}
	require.False(t, checker.hasUnresolvableVariables(body.Attributes["first"].Expr, ctx))
	assert.True(t, checker.hasUnresolvableVariables(body.Attributes["second"].Expr, ctx), "a prior check outside a must not hide the cycle through a")
}

func TestTerraformDynamicLocalCacheReusesSharedDependencies(t *testing.T) {
	const levels = 10
	values := map[string]cty.Value{}
	expressions := map[string]hcl.Expression{}
	visits := 0
	for level := 0; level < levels; level++ {
		for _, prefix := range []string{"a", "b"} {
			name := fmt.Sprintf("%s%d", prefix, level)
			source := "0"
			if level > 0 {
				source = fmt.Sprintf("local.a%d + local.b%d", level-1, level-1)
			}
			body := parseTypedHCL(t, "value = "+source)
			expressions[name] = &terraformCountingExpression{Expression: body.Attributes["value"].Expr, visits: &visits}
			values[name] = cty.NumberIntVal(0)
		}
	}
	ctx := newTerraformEvalContext(nil, values)
	checker := terraformReferenceChecker{localExpressions: expressions, moduleCtx: ctx}
	expr := parseTypedHCL(t, fmt.Sprintf("value = local.a%d", levels-1)).Attributes["value"].Expr
	require.False(t, checker.hasUnresolvableVariables(expr, ctx))
	assert.LessOrEqual(t, visits, 4*levels, "shared acyclic locals must not be rechecked for every path through the graph")
	t.Logf("locals=%d reference checks=%d", len(values), visits)
}

func TestTerraformDynamicSharedSplatLocalDependencies(t *testing.T) {
	for _, levels := range []int{8, 16} {
		t.Run(fmt.Sprint(levels), func(t *testing.T) {
			values := map[string]cty.Value{}
			expressions := map[string]hcl.Expression{}
			visits := 0
			for level := 0; level < levels; level++ {
				for _, prefix := range []string{"a", "b"} {
					name := fmt.Sprintf("%s%d", prefix, level)
					source := "0"
					value := cty.NumberIntVal(0)
					if level > 0 {
						source = fmt.Sprintf("length(([for item in [0, 1] : local.a%d + local.b%d])[*])", level-1, level-1)
						value = cty.NumberIntVal(2)
					}
					body := parseTypedHCL(t, "value = "+source)
					expr := body.Attributes["value"].Expr
					hclsyntax.VisitAll(expr, func(node hclsyntax.Node) hcl.Diagnostics {
						if binary, ok := node.(*hclsyntax.BinaryOpExpr); ok {
							binary.LHS = &terraformCountingExpression{Expression: binary.LHS, visits: &visits}
							binary.RHS = &terraformCountingExpression{Expression: binary.RHS, visits: &visits}
						}
						return nil
					})
					expressions[name] = expr
					values[name] = value
				}
			}
			ctx := newTerraformEvalContext(nil, values)
			checker := terraformReferenceChecker{localExpressions: expressions, moduleCtx: ctx}
			expr := parseTypedHCL(t, fmt.Sprintf("value = [local.a%d]", levels-1)).Attributes["value"].Expr
			require.False(t, checker.hasUnresolvableVariables(expr, ctx))
			t.Logf("locals=%d dependency checks=%d", len(values), visits)
			assert.LessOrEqual(t, visits, 8*levels, "a shared acyclic graph of constant-size local values must stay linear")
		})
	}
}

func TestTerraformDynamicLocalCachePreservesCachedExpressionDependencies(t *testing.T) {
	body := parseTypedHCL(t, `
a = { safe = [], next = local.options["0"] }
b = local.a.safe
options = [for name in [1] : [] if length(local.b) == 0]
first = [local.options[0], local.options["0"]]
third = local.a
`)
	ctx := newTerraformEvalContext(nil, map[string]cty.Value{
		"a":       cty.ObjectVal(map[string]cty.Value{"safe": cty.EmptyTupleVal, "next": cty.EmptyTupleVal}),
		"b":       cty.EmptyTupleVal,
		"options": cty.TupleVal([]cty.Value{cty.EmptyTupleVal}),
	})
	checker := terraformReferenceChecker{
		localExpressions: map[string]hcl.Expression{"a": body.Attributes["a"].Expr, "b": body.Attributes["b"].Expr, "options": body.Attributes["options"].Expr},
		moduleCtx:        ctx,
	}
	require.False(t, checker.hasUnresolvableVariables(body.Attributes["first"].Expr, ctx))
	assert.True(t, checker.hasUnresolvableVariables(body.Attributes["third"].Expr, ctx), "expression caches must not hide dependencies from later local checks")
}

func TestTerraformDynamicCoalesceTypesRejectLocalCycles(t *testing.T) {
	body := parseTypedHCL(t, `
a = local.b
b = local.a
value = coalesce(true, local.a) ? [1] : []
`)
	ctx := newTerraformEvalContext(nil, map[string]cty.Value{"a": cty.True, "b": cty.True})
	checker := terraformReferenceChecker{
		localExpressions: map[string]hcl.Expression{"a": body.Attributes["a"].Expr, "b": body.Attributes["b"].Expr},
		moduleCtx:        ctx,
	}
	assert.True(t, checker.hasUnresolvableVariables(body.Attributes["value"].Expr, ctx))
}

func TestTerraformDirectoryDynamicStoredLocalSelections(t *testing.T) {
	for _, tc := range []struct {
		name       string
		contexts   string
		expression string
		wantErrors bool
		wantBlock  bool
	}{
		{"changed stored value", `[1]`, `local.selected`, true, false},
		{"matching stored value", `[]`, `local.selected`, false, false},
		{"resolved dependency", `[1]`, `local.direct`, false, true},
		{"changed selected field", `[1]`, `local.options.changed`, true, false},
		{"unchanged selected field", `[1]`, `local.options.safe`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{"main.tf": fmt.Sprintf(`
variable "selection" { default = "contexts" }
locals {
  contexts = %s
  selected = try(local[var.selection], [])
  direct = local.contexts
  options = { safe = [], changed = try(local[var.selection], []) }
}
resource "kubernetes_pod_v1" "demo" {
  metadata { name = "stored-locals" }
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
}`, tc.contexts, tc.expression)})
			obj, errs := terraformObject(t, dir)
			if tc.wantErrors {
				require.NotEmpty(t, errs, "the checked local selection must match the value used for expansion")
				assert.Contains(t, fmt.Sprint(errs), "for_each contains unresolved references")
				return
			}
			require.Empty(t, errs)
			if tc.wantBlock {
				assert.Equal(t, map[string]interface{}{"privileged": true}, terraformFirstContainer(t, obj)["securityContext"])
			} else {
				assert.NotContains(t, terraformFirstContainer(t, obj), "securityContext")
			}
		})
	}
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
		assert.Nil(t, checker.expressionTypes, "inferred types must not be retained between checks")
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
