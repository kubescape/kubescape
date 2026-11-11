package cautils

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseTypedHCL parses HCL source and returns the *hclsyntax.Body the typed
// Terraform conversion helpers work on. Test fixtures must parse cleanly;
// expression evaluation errors are what the conversion tests exercise, not
// syntax errors.
func parseTypedHCL(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "fixture must parse: %s", diags)
	body, ok := file.Body.(*hclsyntax.Body)
	require.True(t, ok, "fixture must be hclsyntax")
	return body
}

func TestSnakeToCamel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"multi-word attribute", "image_pull_secrets", "imagePullSecrets"},
		{"no underscore passes through", "apiVersion", "apiVersion"},
		{"single word", "spec", "spec"},
		{"empty segment from double underscore is skipped", "host__alias", "hostAlias"},
		{"trailing underscore segment is dropped", "trailing_", "trailing"},
		{"leading and trailing underscores are dropped", "_init_container_", "InitContainer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, snakeToCamel(tc.in))
		})
	}
}

func TestFieldNameFor(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plural override wins for container", "container", "containers"},
		{"plural override for init_container", "init_container", "initContainers"},
		{"plural override for sysctl", "sysctl", "sysctls"},
		{"plural override for http_header", "http_header", "httpHeaders"},
		{"non-overridden label falls back to camelCase", "metadata", "metadata"},
		{"multi-word fallback", "image_pull_policy", "imagePullPolicy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fieldNameFor(tc.in))
		})
	}
}

func TestHclResourceBodyToMapStripsMetaArguments(t *testing.T) {
	// depends_on and provider reference other resources/providers that the
	// var-only evalCtx can never resolve; they must be stripped before
	// expression evaluation rather than failing into errs. Top-level
	// lifecycle, provisioner and connection are Terraform meta blocks and
	// must be stripped the same way.
	src := `
resource "kubernetes_deployment" "app" {
  depends_on  = [kubernetes_pod.elsewhere]
  provider    = kubernetes.alt
  count       = 1
  for_each    = {}
  lifecycle {
    ignore_changes = ["metadata"]
  }
  provisioner "local-exec" {
    command = "echo"
  }
  connection {
    type = "ssh"
  }
  metadata {
    name = "app"
  }
  spec {
    replicas = 2
  }
}
`
	body := parseTypedHCL(t, src)
	require.Len(t, body.Blocks, 1)

	var errs []error
	out := hclResourceBodyToMap(body.Blocks[0].Body, &hcl.EvalContext{}, &errs, "kubernetes_deployment.app")

	require.Empty(t, errs, "meta-arguments must be stripped before evaluation, not left to fail")

	want := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "app"},
		"spec":     map[string]interface{}{"replicas": json.Number("2")},
	}
	assert.Equal(t, want, out)

	for _, stripped := range []string{"depends_on", "provider", "count", "for_each", "lifecycle", "provisioner", "connection"} {
		assert.NotContains(t, out, stripped)
	}
}

func TestHclBodyToMapKeepsNestedLifecycle(t *testing.T) {
	// resourceMetaBlocks apply ONLY at the resource's top level. A container's
	// own lifecycle block (postStart/preStop hooks) is a legitimate Kubernetes
	// field and must still be converted, with snake_case nested keys camelCased.
	src := `
container {
  name = "app"
  lifecycle {
    post_start {
      exec = ["sleep", "30"]
    }
  }
}
`
	body := parseTypedHCL(t, src)
	require.Len(t, body.Blocks, 1)

	var errs []error
	out := hclBodyToMap(body.Blocks[0].Body, &hcl.EvalContext{}, &errs, "container")

	require.Empty(t, errs)
	want := map[string]interface{}{
		"name": "app",
		"lifecycle": map[string]interface{}{
			"postStart": map[string]interface{}{
				"exec": []interface{}{"sleep", "30"},
			},
		},
	}
	assert.Equal(t, want, out)
}

func TestHclBodyToMapRepeatableBlocks(t *testing.T) {
	t.Run("repeated blocks encode as an array in source order", func(t *testing.T) {
		src := `
metadata {
  name = "one"
}
container {
  name = "c1"
}
container {
  name = "c2"
}
`
		var errs []error
		out := hclBodyToMap(parseTypedHCL(t, src), &hcl.EvalContext{}, &errs, "pod")

		require.Empty(t, errs)
		want := map[string]interface{}{
			"metadata": map[string]interface{}{"name": "one"},
			"containers": []interface{}{
				map[string]interface{}{"name": "c1"},
				map[string]interface{}{"name": "c2"},
			},
		}
		assert.Equal(t, want, out)
	})

	t.Run("single repeatable block still encodes as an array", func(t *testing.T) {
		src := `
container {
  name = "solo"
}
`
		var errs []error
		out := hclBodyToMap(parseTypedHCL(t, src), &hcl.EvalContext{}, &errs, "pod")

		require.Empty(t, errs)
		want := map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{"name": "solo"}},
		}
		assert.Equal(t, want, out)
	})
}

func TestExtractTypedResources(t *testing.T) {
	src := `
resource "kubernetes_deployment_v1" "web" {
  replicas = 3
}

resource "kubernetes_pod" "explicit-name" {
  metadata {
    name = "custom-name"
  }
}

resource "kubernetes_role_binding" "rb" {
}

resource "kubernetes_deployment" "legacy-web" {
  replicas = 2
}

resource "kubernetes_foo_bar" "unsupported" {
  name = "skip-me"
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 4, "unsupported resource types must be skipped")

	assert.Equal(t, "apps/v1", manifests[0]["apiVersion"])
	assert.Equal(t, "Deployment", manifests[0]["kind"])
	assert.Equal(t, json.Number("3"), manifests[0]["replicas"])
	assert.Equal(t, map[string]interface{}{"name": "web"}, manifests[0]["metadata"], "metadata.name must be defaulted from the Terraform label")

	assert.Equal(t, "v1", manifests[1]["apiVersion"])
	assert.Equal(t, "Pod", manifests[1]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "custom-name"}, manifests[1]["metadata"], "explicit metadata.name must be preserved")

	assert.Equal(t, "rbac.authorization.k8s.io/v1", manifests[2]["apiVersion"])
	assert.Equal(t, "RoleBinding", manifests[2]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "rb"}, manifests[2]["metadata"])

	assert.Equal(t, "apps/v1", manifests[3]["apiVersion"])
	assert.Equal(t, "Deployment", manifests[3]["kind"])
	assert.Equal(t, json.Number("2"), manifests[3]["replicas"])
	assert.Equal(t, map[string]interface{}{"name": "legacy-web"}, manifests[3]["metadata"])
}

func TestExtractTypedResourcesSkipsInvalidBlocks(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"non-resource block with two labels", `not_a_resource "kubernetes_deployment" "ignored" {}`},
		{"resource block with no labels", `resource {}`},
		{"resource block with one label", `resource "kubernetes_deployment" {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifests, errs := extractTypedResources(parseTypedHCL(t, tc.src), &hcl.EvalContext{})

			assert.Empty(t, errs)
			assert.Empty(t, manifests)
		})
	}
}

func TestExtractTypedResourcesCollectsUnresolvableAttributes(t *testing.T) {
	// Attributes that cannot be evaluated against the var-only evalCtx are
	// recorded in errs and left unset rather than guessed at, matching the
	// kubernetes_manifest policy.
	src := `
resource "kubernetes_config_map" "bad" {
  data = var.missing
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Len(t, errs, 1)
	require.Len(t, manifests, 1)

	obj := manifests[0]
	assert.Equal(t, "v1", obj["apiVersion"])
	assert.Equal(t, "ConfigMap", obj["kind"])
	assert.Equal(t, map[string]interface{}{"name": "bad"}, obj["metadata"])
	assert.NotContains(t, obj, "data", "unresolvable attributes must be left unset")
}

func TestExtractTypedResourcesNonHclBody(t *testing.T) {
	// A body that is not hclsyntax (e.g. an empty body) yields nothing rather
	// than guessing.
	manifests, errs := extractTypedResources(hcl.EmptyBody(), &hcl.EvalContext{})

	assert.Nil(t, manifests)
	assert.Nil(t, errs)
}
