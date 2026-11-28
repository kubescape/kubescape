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

// A kubernetes_manifest that can't be resolved is left out and reported the
// same way as a typed resource, instead of only being logged.
func TestLoadResourcesFromTerraform_UnresolvedKubernetesManifestIsReported(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
variable "image" {
  type = string
}

variable "replicas" {
  type = number
}

resource "kubernetes_namespace_v1" "apps" {
  metadata { name = "apps" }
}

resource "kubernetes_manifest" "plain" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "plain", namespace = "default" }
    spec       = { containers = [{ name = "c", image = "nginx:1.27" }] }
  }
}

resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web", namespace = kubernetes_namespace_v1.apps.metadata[0].name }
    spec       = { containers = [{ name = "c", image = "nginx:1.27" }] }
  }
}

resource "kubernetes_manifest" "decoded" {
  manifest = yamldecode("{apiVersion: v1, kind: Pod, metadata: {name: decoded}}")
}

resource "kubernetes_manifest" "custom_image" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "custom-image", namespace = "default" }
    spec       = { containers = [{ name = "c", image = var.image }] }
  }
}

resource "kubernetes_manifest" "counted" {
  count = var.replicas
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "counted-${count.index}", namespace = "default" }
    spec       = { containers = [{ name = "c", image = "nginx:1.27" }] }
  }
}
`})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"apps", "plain"}, sortedNames(workloadsByName(t, workloads)))
	require.Len(t, skips, 1)
	assert.Equal(t, dir, skips[0].Path)
	assert.Equal(t, []string{
		"kubernetes_manifest.web", "kubernetes_manifest.decoded",
		"kubernetes_manifest.custom_image", "kubernetes_manifest.counted",
	}, skips[0].Resources)
	assert.Contains(t, skips[0].Reason, "4 Terraform resource(s) not scanned")
}

// When only some instances of a kubernetes_manifest can't be resolved, the
// whole resource is left out, like a typed resource, so it isn't reported as
// not scanned while part of it is.
func TestLoadResourcesFromTerraform_PartlyUnresolvedKubernetesManifestIsLeftOut(t *testing.T) {
	dir := resolvedTempDir(t)
	writeTerraformFiles(t, dir, map[string]string{"main.tf": `
resource "kubernetes_manifest" "plain" {
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = "plain", namespace = "default" }
  }
}

resource "kubernetes_manifest" "indexed" {
  count = 2
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = ["first"][count.index], namespace = "default" }
  }
}
`})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"plain"}, sortedNames(workloadsByName(t, workloads)))
	require.Len(t, skips, 1)
	assert.Equal(t, []string{"kubernetes_manifest.indexed"}, skips[0].Resources)
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
