package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jsonDeploymentNoSecurityContext = `{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "demo",
    "namespace": "default"
  },
  "spec": {
    "template": {
      "spec": {
        "containers": [
          {
            "name": "app",
            "image": "nginx"
          }
        ]
      }
    }
  }
}
`

// A scan reads .json manifests as well as YAML, and `kubescape fix` keeps a
// JSON manifest JSON. apply_remediation returns the patched content for the
// caller to write back to file_path, so for a .json file it must still be JSON.
func TestApplyRemediation_JSONManifestStaysJSON(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "deployment.json")
	require.NoError(t, os.WriteFile(fixture, []byte(jsonDeploymentNoSecurityContext), 0o600))

	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonDeploymentNoSecurityContext), &obj))
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath("deployment.json:0")
	res := &reporthandling.Resource{
		ResourceID: lw.GetID(),
		Object:     lw.GetObject(),
		Source:     &reporthandling.Source{FileType: reporthandling.SourceTypeJson, Path: dir},
	}
	stubScanReport(t, remediationReport(dir, res,
		remediationFailedControl("C-0016", "Allow privilege escalation",
			remediationFailedRuleWithFix("spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation", "false"),
		),
	))

	resp := callReport(t, map[string]any{"path": fixture, "control_ids": "C-0016"})

	require.Len(t, resp.Files, 1)
	assert.Equal(t, fixture, resp.Files[0].FilePath)
	assert.Equal(t, 1, resp.FixedControlInstances)

	var patched map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Files[0].PatchedYAML), &patched),
		"the patched content of a .json manifest must still parse as JSON:\n%s", resp.Files[0].PatchedYAML)
	containers := patched["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
	securityContext := containers[0].(map[string]any)["securityContext"].(map[string]any)
	assert.Equal(t, false, securityContext["allowPrivilegeEscalation"])
}
