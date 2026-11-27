package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNestedDynamicTerraformFailureRecordsSkippedModule(t *testing.T) {
	for _, collection := range []string{
		`var.security_contexts`, `try(var.security_contexts, [])`, `local.contexts`,
		`coalesce(var.numbers, ["2"], try(var.extra, null))[0] == 1 ? [1] : []`,
		`try([for item in [true] : 1 if var.include || item], [])`,
		`try((true || try(var.choice, false)) ? [] : [1], [1])`,
	} {
		t.Run(collection, func(t *testing.T) {
			dir := t.TempDir()
			good := filepath.Join(dir, "modules", "good")
			bad := filepath.Join(dir, "modules", "bad")
			require.NoError(t, os.MkdirAll(good, 0o750))
			require.NoError(t, os.MkdirAll(bad, 0o750))
			writeTerraformFixture(t, good, terraformPodFixture)
			badFile := writeTerraformFixture(t, bad, fmt.Sprintf(`
variable "security_contexts" {
  type = list(object({ privileged = bool }))
}
variable "numbers" {
  type = list(number)
  default = [1]
}
variable "extra" { type = set(number) }
variable "include" { type = bool }
variable "choice" { type = any }
locals { contexts = try(var.security_contexts, []) }
resource "kubernetes_pod_v1" "risky" {
  spec {
    container {
      name  = "app"
      image = "nginx"
      dynamic "security_context" {
        for_each = %s
        content { privileged = security_context.value.privileged }
      }
    }
  }
}`, collection))
			require.NoError(t, os.Rename(badFile, filepath.Join(bad, "payroll-prod.tf")))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "safe.yaml"), []byte(singlePodManifest), 0o600))

			_, workloads, skips, err := getResourcesFromPath(context.Background(), dir, cautils.HelmValueOptions{}, nil)
			require.NoError(t, err, "valid files must remain scannable")
			require.Len(t, workloads, 2, "keep the root YAML and the good Terraform module")
			require.Len(t, skips, 1, "the failed module must lower scan coverage")
			assert.Equal(t, bad, skips[0].Path)
			assert.Contains(t, skips[0].Reason, "Terraform")
			assert.NotContains(t, skips[0].Reason, "risky", "report reasons must not expose source resource labels under --hide")
			assert.NotContains(t, skips[0].Reason, "payroll-prod.tf", "report reasons must not expose source filenames under --hide")
		})
	}
}

// The files loader records the Terraform resource block of each resource it
// loads from a .tf file, by resource ID, in the map the caller passes for the
// scan. Two inputs scanned in one process get separate maps.
func TestGetResourcesFromInputRecordsTerraformLocations(t *testing.T) {
	load := func(leadingLines int) map[string]cautils.SourceLocation {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Repeat("\n", leadingLines)+`resource "kubernetes_namespace_v1" "ns" {
  metadata {
    name = "shop"
  }
}
`), 0o600))
		locations := map[string]cautils.SourceLocation{}
		_, _, workloads, _, err := getResourcesFromInput(context.Background(), dir, cautils.HelmValueOptions{}, nil, cautils.DefaultGitCloneDepth, locations)
		require.NoError(t, err)
		require.Len(t, workloads, 1)
		require.Contains(t, locations, workloads[0].GetID())
		return locations
	}

	first := load(0)
	second := load(6)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	for _, location := range first {
		assert.Equal(t, cautils.SourceLocation{Line: 1, Column: 1}, location)
	}
	for _, location := range second {
		assert.Equal(t, cautils.SourceLocation{Line: 7, Column: 1}, location)
	}
}
