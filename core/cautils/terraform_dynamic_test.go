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
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
resource "kubernetes_pod_v1" "demo" {
  spec {
    container {
      name  = "web"
      image = "nginx"
      dynamic "security_context" {
        for_each = []
        content { privileged = var.not_evaluated }
      }
    }
  }
}`})
	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs, "an empty iteration must not evaluate its content")
	container := terraformFirstContainer(t, obj)
	assert.NotContains(t, container, "securityContext")
	assert.NotContains(t, container, "dynamic")
}

func TestTerraformDirectoryInvalidDynamicBlocks(t *testing.T) {
	for name, body := range map[string]string{
		"unresolved collection": `for_each = var.missing
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
