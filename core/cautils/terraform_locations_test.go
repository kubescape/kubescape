package cautils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformDirectory_GetWorkloads_RecordsSourceLocations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`variable "x" {
  default = 1
}

resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name = "shop"
  }
}

resource "kubernetes_manifest" "cm" {
  count = 2
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = "cm-${count.index}", namespace = "shop" }
  }
}

  resource "kubernetes_deployment_v1" "web" {
  metadata {
    name      = "web"
    namespace = "shop"
  }
  spec {
    selector {
      match_labels = { app = "web" }
    }
    template {
      metadata {
        labels = { app = "web" }
      }
      spec {
        host_pid = true
        container {
          name  = "web"
          image = "nginx:1.27"
        }
      }
    }
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	require.Len(t, workloads[path], 4)

	// kubernetes_manifest blocks are extracted before typed resources, and
	// each count instance points at its shared resource block.
	want := map[string]SourceLocation{
		"ConfigMap/cm-0": {Line: 11, Column: 1},
		"ConfigMap/cm-1": {Line: 11, Column: 1},
		"Namespace/shop": {Line: 5, Column: 1},
		"Deployment/web": {Line: 20, Column: 3},
	}
	got := map[string]SourceLocation{}
	for _, w := range workloads[path] {
		lw, ok := w.(interface{ GetPath() string })
		require.True(t, ok)
		location, ok := TerraformSourceLocation(lw.GetPath())
		require.True(t, ok, "no source location for %s", lw.GetPath())
		got[w.GetKind()+"/"+w.GetName()] = location
	}
	assert.Equal(t, want, got)
}

func TestTerraformSourceLocation_UnknownPath(t *testing.T) {
	_, ok := TerraformSourceLocation(filepath.Join(t.TempDir(), "deploy.yaml") + ":0")
	assert.False(t, ok)
}
