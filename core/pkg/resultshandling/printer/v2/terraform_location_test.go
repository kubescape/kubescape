package printer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveFixLocation_Terraform checks that findings on resources converted
// from Terraform point at their resource block, not at line 1 (#5710).
func TestResolveFixLocation_Terraform(t *testing.T) {
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

	td := cautils.NewTerraformDirectory(dir)
	workloads, errs := td.GetWorkloads(dir)
	require.Empty(t, errs)

	// The files loader records each Terraform resource's block on the scan's
	// session, by resource ID.
	session := cautils.NewOPASessionObjMock()
	session.TerraformSourceLocations = map[string]cautils.SourceLocation{}
	ids := map[string]string{}
	for _, w := range workloads[path] {
		session.AllResources[w.GetID()] = w
		session.TerraformSourceLocations[w.GetID()] = td.SourceLocations()[w.(*localworkload.LocalWorkload).GetPath()]
		ids[w.GetKind()] = w.GetID()
	}
	require.Contains(t, ids, "Deployment")
	require.Contains(t, ids, "Namespace")

	// The fix path can't be resolved in a .tf file, so the location is the
	// resource block, whether or not a YAML location resolver is available.
	ac := &resourcesresults.ResourceAssociatedControl{}
	assert.Equal(t, locationresolver.Location{Line: 11, Column: 1}, resolveFixLocation(session, nil, ac, ids["Deployment"]))
	assert.Equal(t, locationresolver.Location{Line: 5, Column: 1}, resolveFixLocation(session, nil, ac, ids["Namespace"]))
	assert.Equal(t, 11, codeQualityLine(session, nil, ac, ids["Deployment"]))
}

func TestResolveFixLocation_NonTerraformFallsBackToLineOne(t *testing.T) {
	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "demo"},
	})
	lw.SetPath(filepath.Join(t.TempDir(), "deploy.yaml") + ":0")

	session := cautils.NewOPASessionObjMock()
	session.AllResources[lw.GetID()] = lw

	ac := &resourcesresults.ResourceAssociatedControl{}
	assert.Equal(t, locationresolver.Location{Line: 1, Column: 1}, resolveFixLocation(session, nil, ac, lw.GetID()))
	_, ok := terraformResourceLocation(session, lw.GetID())
	assert.False(t, ok)
	_, ok = terraformResourceLocation(nil, lw.GetID())
	assert.False(t, ok)
}
