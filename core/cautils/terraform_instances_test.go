package cautils

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// workloadsByName flattens loaded workloads into a map from metadata.name.
func workloadsByName(t *testing.T, workloads map[string][]workloadinterface.IMetadata) map[string]workloadinterface.IMetadata {
	t.Helper()
	byName := map[string]workloadinterface.IMetadata{}
	for _, wls := range workloads {
		for _, wl := range wls {
			require.NotContains(t, byName, wl.GetName(), "every instance must have its own name")
			byName[wl.GetName()] = wl
		}
	}
	return byName
}

func sortedNames(byName map[string]workloadinterface.IMetadata) []string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Regression test for #5589: a resource with count or for_each made the whole
// directory fail to render, so an unrelated resource next to it was not
// scanned either.
func TestLoadResourcesFromTerraform_CountAndForEachInstances(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "plain" {
  metadata { name = "plain" }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
      security_context { privileged = true }
    }
  }
}

resource "kubernetes_pod_v1" "counted" {
  count = 2
  metadata { name = "counted-${count.index}" }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}

resource "kubernetes_pod_v1" "svc" {
  for_each = toset(["api", "worker"])
  metadata { name = each.key }
  spec {
    host_pid = true
    container {
      name  = each.value
      image = "nginx:1.27"
    }
  }
}

resource "kubernetes_pod_v1" "tiers" {
  for_each = { front = "nginx:1.27", back = "redis:7" }
  metadata { name = "tier-${each.key}" }
  spec {
    container {
      name  = each.key
      image = each.value
    }
  }
}
`,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	byName := workloadsByName(t, workloads)
	assert.Equal(t, []string{"api", "counted-0", "counted-1", "plain", "tier-back", "tier-front", "worker"}, sortedNames(byName))

	container := func(name string) map[string]interface{} {
		spec := byName[name].GetObject()["spec"].(map[string]interface{})
		return spec["containers"].([]interface{})[0].(map[string]interface{})
	}
	assert.Equal(t, map[string]interface{}{"privileged": true}, container("plain")["securityContext"], "the unrelated pod is scanned as written")
	assert.Equal(t, true, byName["api"].GetObject()["spec"].(map[string]interface{})["hostPID"])
	assert.Equal(t, "worker", container("worker")["name"], "each.value of a set is its element")
	assert.Equal(t, "redis:7", container("tier-back")["image"], "each.value of a map is the value for the key")
	assert.Equal(t, "front", container("tier-front")["name"])
}

func TestTerraformDirectory_GetWorkloads_ResourceInstances(t *testing.T) {
	tests := []struct {
		name  string
		meta  string
		names []string
	}{
		{name: "count without count.index", meta: `count = 2`, names: []string{"web", "web"}},
		{name: "count of zero", meta: `count = 0`},
		{name: "count from a variable default", meta: `count = var.replicas`, names: []string{"web", "web", "web"}},
		{name: "count from a local", meta: `count = local.enabled ? 1 : 0`, names: []string{"web"}},
		{name: "for_each over an empty set", meta: `for_each = toset([])`},
		{name: "for_each over a set of numbers", meta: `for_each = toset([1, 2])`, names: []string{"web", "web"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{
				"main.tf": `
variable "replicas" {
  default = 3
}

locals {
  enabled = true
}

resource "kubernetes_service_account_v1" "web" {
  ` + tt.meta + `
  metadata { name = "web" }
}
`,
			})
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
			var names []string
			for _, wl := range workloads[filepath.Join(dir, "main.tf")] {
				names = append(names, wl.GetName())
			}
			assert.Equal(t, tt.names, names)
		})
	}
}

func TestTerraformDirectory_GetWorkloads_UnresolvableInstancesAreErrors(t *testing.T) {
	tests := []struct {
		name    string
		meta    string
		wantErr string
	}{
		{name: "count from a variable without a default", meta: `count = var.unset`, wantErr: "count"},
		{name: "for_each from a variable without a default", meta: `for_each = var.unset`, wantErr: "for_each"},
		{name: "count and for_each together", meta: "count = 1\n  for_each = toset([\"a\"])", wantErr: "cannot be used together"},
		{name: "for_each over a list", meta: `for_each = ["a", "b"]`, wantErr: "use toset()"},
		{name: "negative count", meta: `count = -1`, wantErr: "whole number"},
		{name: "fractional count", meta: `count = 1.5`, wantErr: "whole number"},
		{name: "count that is not a number", meta: `count = "many"`, wantErr: "count must be a number"},
		{name: "null count", meta: `count = null`, wantErr: "known, non-null"},
		{name: "count over the size limit", meta: `count = 100000000`, wantErr: "size limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformFiles(t, dir, map[string]string{
				"main.tf": `
variable "unset" {}

resource "kubernetes_service_account_v1" "web" {
  ` + tt.meta + `
  metadata { name = "web" }
}
`,
			})
			_, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.NotEmpty(t, errs, "an unresolved count or for_each must not be guessed at")
			assert.ErrorContains(t, errs[0], "kubernetes_service_account_v1.web")
			assert.ErrorContains(t, errs[0], tt.wantErr)
		})
	}
}

func TestTerraformDirectory_GetWorkloads_KubernetesManifestInstances(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
variable "unset" {}

resource "kubernetes_manifest" "cm" {
  count = 2
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = "cm-${count.index}", namespace = "default" }
  }
}

resource "kubernetes_manifest" "unresolved" {
  count = var.unset
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = "unresolved", namespace = "default" }
  }
}
`,
	})
	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs, "an unresolved kubernetes_manifest is skipped with a warning, as before")
	var names []string
	for _, wl := range workloads[filepath.Join(dir, "main.tf")] {
		names = append(names, wl.GetName())
	}
	assert.Equal(t, []string{"cm-0", "cm-1"}, names)
}
