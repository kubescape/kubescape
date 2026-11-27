package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// terraformUnresolvedConfig holds an unrelated privileged pod next to
// resources that use values the scan can't resolve: another resource's
// attribute, a data source and a variable without a value.
const terraformUnresolvedConfig = `
variable "image" {
  type = string
}

resource "kubernetes_namespace_v1" "apps" {
  metadata { name = "apps" }
}

resource "kubernetes_pod_v1" "plain" {
  metadata {
    name      = "plain"
    namespace = "default"
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
      security_context { privileged = true }
    }
  }
}

resource "kubernetes_pod_v1" "web" {
  metadata {
    name      = "web"
    namespace = kubernetes_namespace_v1.apps.metadata[0].name
  }
  spec {
    host_pid = true
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}

resource "kubernetes_pod_v1" "configured" {
  metadata {
    name = data.kubernetes_config_map_v1.settings.data.name
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}

resource "kubernetes_pod_v1" "custom_image" {
  metadata { name = "custom-image" }
  spec {
    container {
      name  = "c"
      image = var.image
    }
  }
}
`

// Regression test: one resource with an unresolved value used to make the
// loader skip every resource of the Terraform configuration.
func TestLoadResourcesFromTerraform_UnresolvedResourceSkipsOnlyThatResource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input func(dir string) string
	}{
		{name: "the configuration directory", input: func(dir string) string { return dir }},
		{name: "a parent directory", input: func(dir string) string { return filepath.Dir(dir) }},
		{name: "a .tf file", input: func(dir string) string { return filepath.Join(dir, "main.tf") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(resolvedTempDir(t), "infra")
			require.NoError(t, os.MkdirAll(dir, 0o750))
			writeTerraformFiles(t, dir, map[string]string{"main.tf": terraformUnresolvedConfig})

			workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), tc.input(dir), nil)
			require.NoError(t, err, "valid Terraform must not fail the scan")

			byName := workloadsByName(t, workloads)
			require.Equal(t, []string{"apps", "plain"}, sortedNames(byName),
				"resources with unresolved values are left out; the rest is scanned")
			container := byName["plain"].GetObject()["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})
			assert.Equal(t, map[string]interface{}{"privileged": true}, container["securityContext"])

			// The resources left out are reported against the configuration, by
			// address; the reason carries no labels or file names.
			require.Len(t, skips, 1)
			assert.Equal(t, dir, skips[0].Path)
			assert.Equal(t, []string{"kubernetes_pod_v1.web", "kubernetes_pod_v1.configured", "kubernetes_pod_v1.custom_image"}, skips[0].Resources)
			assert.Contains(t, skips[0].Reason, "3 Terraform resource(s) not scanned")
			for _, label := range []string{"web", "configured", "custom_image", "main.tf"} {
				assert.NotContains(t, skips[0].Reason, label, "labels and file names stay out of the reason, which --hide can't anonymize")
			}
		})
	}
}

// An unresolved count or for_each leaves out only that resource too.
func TestLoadResourcesFromTerraform_UnresolvedInstancesSkipOnlyThatResource(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
variable "replicas" {
  type = number
}

resource "kubernetes_pod_v1" "plain" {
  metadata { name = "plain" }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}

resource "kubernetes_pod_v1" "counted" {
  count = var.replicas
  metadata { name = "counted-${count.index}" }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}
`})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"plain"}, sortedNames(workloadsByName(t, workloads)))
	require.Len(t, skips, 1)
	assert.Equal(t, []string{"kubernetes_pod_v1.counted"}, skips[0].Resources)
	assert.Equal(t, dir, skips[0].Path)
}

func TestLoadResourcesFromTerraform_TypedTopLevelTryAndCan(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
variable "settings" {
  default = { image = "nginx:1.27" }
}

resource "kubernetes_config_map_v1" "unresolved-try" {
  data = try(data.kubernetes_config_map_v1.settings.data, { image = "fallback" })
}

resource "kubernetes_config_map_v1" "unresolved-can" {
  immutable = can(data.kubernetes_config_map_v1.settings.data)
}

resource "kubernetes_config_map_v1" "resolved" {
  data      = try(var.settings, data.kubernetes_config_map_v1.settings.data)
  immutable = can(var.settings.image)
}

resource "kubernetes_config_map_v1" "optional" {
  data      = { image = try(var.settings.optional, "fallback") }
  immutable = can(var.settings.optional)
}
`})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.NoError(t, err)
	byName := workloadsByName(t, workloads)
	assert.Equal(t, []string{"optional", "resolved"}, sortedNames(byName))
	require.Contains(t, byName, "resolved")
	resolved := byName["resolved"].GetObject()
	assert.Equal(t, map[string]interface{}{"image": "nginx:1.27"}, resolved["data"])
	assert.Equal(t, true, resolved["immutable"])
	require.Contains(t, byName, "optional")
	optional := byName["optional"].GetObject()
	assert.Equal(t, map[string]interface{}{"image": "fallback"}, optional["data"])
	assert.Equal(t, false, optional["immutable"])

	require.Len(t, skips, 1)
	assert.Equal(t, dir, skips[0].Path)
	assert.ElementsMatch(t, []string{"kubernetes_config_map_v1.unresolved-try", "kubernetes_config_map_v1.unresolved-can"}, skips[0].Resources)
}

// A configuration error that isn't about one resource, such as a malformed
// tfvars file, still fails the configuration as before.
func TestLoadResourcesFromTerraform_ConfigurationErrorStillFails(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf":          terraformUnresolvedConfig,
		"terraform.tfvars": `image = `,
	})

	_, _, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terraform.tfvars")
}

// Malformed HCL fails the directory, as before: nothing in the configuration
// can be trusted when it can't be parsed.
func TestLoadResourcesFromTerraform_MalformedHCLStillFails(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": terraformUnresolvedConfig,
		"broken.tf": `resource "kubernetes_pod_v1" "broken" {
  metadata {
`,
	})

	_, _, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.tf")
}
