package cautils

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

	td := NewTerraformDirectory(dir)
	workloads, errs := td.GetWorkloads(dir)
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
		location, ok := td.SourceLocations()[lw.GetPath()]
		require.True(t, ok, "no source location for %s", lw.GetPath())
		got[w.GetKind()+"/"+w.GetName()] = location
	}
	assert.Equal(t, want, got)
}

// Two scans in one process, such as the MCP server, can produce workloads with
// the same relative path ("main.tf:0"). Each scan keeps its own locations.
func TestTerraformDirectory_SourceLocations_PerScan(t *testing.T) {
	scan := func(leadingLines int) (string, map[string]SourceLocation) {
		dir := t.TempDir()
		src := strings.Repeat("\n", leadingLines) + `resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name = "shop"
  }
}
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(src), 0o600))
		t.Chdir(dir)
		td := NewTerraformDirectory(".")
		workloads, errs := td.GetWorkloads(".")
		require.Empty(t, errs)
		for _, wls := range workloads {
			require.Len(t, wls, 1)
			return wls[0].(interface{ GetPath() string }).GetPath(), td.SourceLocations()
		}
		require.FailNow(t, "no workloads")
		return "", nil
	}

	firstPath, first := scan(0)
	secondPath, second := scan(9)
	require.Equal(t, firstPath, secondPath, "both scans should use the same relative path")
	assert.Equal(t, SourceLocation{Line: 1, Column: 1}, first[firstPath])
	assert.Equal(t, SourceLocation{Line: 10, Column: 1}, second[secondPath])
}

// A directory's locations are those of its last GetWorkloads call.
func TestTerraformDirectory_SourceLocations_ResetOnGetWorkloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	write := func(leadingLines int) {
		require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("\n", leadingLines)+`resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name = "shop"
  }
}
`), 0o600))
	}
	td := NewTerraformDirectory(dir)

	write(0)
	_, errs := td.GetWorkloads(dir)
	require.Empty(t, errs)
	assert.Equal(t, map[string]SourceLocation{path + ":0": {Line: 1, Column: 1}}, td.SourceLocations())

	write(4)
	_, errs = td.GetWorkloads(dir)
	require.Empty(t, errs)
	assert.Equal(t, map[string]SourceLocation{path + ":0": {Line: 5, Column: 1}}, td.SourceLocations())
}

func TestLoadResourcesFromTerraformWithLocations(t *testing.T) {
	root := t.TempDir()
	for name, leadingLines := range map[string]int{"a": 0, "b": 3} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Repeat("\n", leadingLines)+`resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name = "`+name+`"
  }
}
`), 0o600))
	}

	workloads, skips, locations, err := LoadResourcesFromTerraformWithLocations(context.Background(), root, nil)
	require.NoError(t, err)
	require.Empty(t, skips)
	require.Len(t, workloads, 2)
	assert.Equal(t, map[string]SourceLocation{
		filepath.Join(root, "a", "main.tf") + ":0": {Line: 1, Column: 1},
		filepath.Join(root, "b", "main.tf") + ":0": {Line: 4, Column: 1},
	}, locations)
}
