package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unsetSecurityContextTerraform = `
resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    template {
      metadata {
        labels = { app = "app" }
      }
      spec {
        security_context {
          fs_group     = ""
          run_as_group = null
        }
        container {
          name  = "app"
          image = "nginx"
          security_context {
            run_as_user                = null
            run_as_group               = ""
            privileged                 = null
            allow_privilege_escalation = false
          }
        }
      }
    }
  }
}
`

// Terraform treats an argument set to null as if it were not there, and the provider
// leaves runAsUser, runAsGroup and fsGroup unset for "". Neither may reach the
// manifest as a value, or a rule reads the field as set.
func TestExtractTypedResourcesLeavesNullAndEmptyIDsUnset(t *testing.T) {
	byName := typedManifestsByName(t, unsetSecurityContextTerraform)

	podSpec := byName["Deployment/app"]["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	podContext := podSpec["securityContext"].(map[string]interface{})
	assert.NotContains(t, podContext, "fsGroup")
	assert.NotContains(t, podContext, "runAsGroup")

	containerContext := podSpec["containers"].([]interface{})[0].(map[string]interface{})["securityContext"].(map[string]interface{})
	assert.NotContains(t, containerContext, "runAsUser")
	assert.NotContains(t, containerContext, "runAsGroup")
	assert.NotContains(t, containerContext, "privileged")
	assert.Equal(t, false, containerContext["allowPrivilegeEscalation"], "false is a value, not an unset field")
}

// runAsUserLookupRego mirrors how the non-root-containers rule (C-0013) reads a
// container's user: the container's runAsUser when it is defined, else 0, which the
// rule reports as root. A field present as null or "" is defined.
const runAsUserLookupRego = `
package test

import rego.v1

run_as_user(container) := value if {
	value := container.securityContext.runAsUser
} else := 0

runs_as_root if {
	some container in input.spec.template.spec.containers
	run_as_user(container) == 0
}
`

// The common module pattern for an optional input: a variable that defaults to
// null. The container runs as the image's user, possibly root, and must be seen so.
func TestTerraformDirectoryNullVariableLeavesRunAsUserUnset(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
variable "run_as_user" {
  type    = number
  default = null
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    template {
      metadata {
        labels = { app = "app" }
      }
      spec {
        container {
          name  = "app"
          image = "nginx"
          security_context {
            run_as_user = var.run_as_user
          }
        }
      }
    }
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	var found bool
	for _, list := range workloads {
		for _, w := range list {
			if w.GetKind() != "Deployment" {
				continue
			}
			found = true
			raw, err := json.Marshal(w.GetObject())
			require.NoError(t, err)
			var input interface{}
			require.NoError(t, json.Unmarshal(raw, &input))

			rs, err := rego.New(rego.Query("data.test.runs_as_root"), rego.Module("test.rego", runAsUserLookupRego), rego.Input(input)).Eval(context.Background())
			require.NoError(t, err)
			assert.True(t, len(rs) == 1 && rs[0].Expressions[0].Value == true,
				"a run_as_user left null is not set, so the container may run as root: %s", raw)
		}
	}
	require.True(t, found, "the Deployment must be extracted")
}
