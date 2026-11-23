package resourcehandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
