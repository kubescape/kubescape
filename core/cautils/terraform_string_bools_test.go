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

func TestAttributeValueForQuotedBools(t *testing.T) {
	sc := "kubernetes_deployment_v1.web.spec.template.spec.container.security_context"
	podSpec := "kubernetes_deployment_v1.web.spec.template.spec"
	cases := []struct {
		name     string
		path     string
		attrName string
		in       interface{}
		want     interface{}
	}{
		{"privileged true", sc, "privileged", "true", true},
		{"privileged false", sc, "privileged", "false", false},
		{"privileged 1", sc, "privileged", "1", true},
		{"privileged 0", sc, "privileged", "0", false},
		{"read_only_root_filesystem", sc, "read_only_root_filesystem", "true", true},
		{"allow_privilege_escalation", sc, "allow_privilege_escalation", "false", false},
		{"host_network", podSpec, "host_network", "true", true},
		{"host_pid", podSpec, "host_pid", "true", true},
		{"bool literal stays", sc, "privileged", true, true},
		{"Terraform rejects other spellings", sc, "privileged", "yes", "yes"},
		{"Terraform rejects capitalised true", sc, "privileged", "True", "True"},
		{"string field stays a string", podSpec + ".container.env", "value", "true", "true"},
		{"container name stays a string", podSpec + ".container", "name", "true", "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, attributeValueFor(tc.path, tc.attrName, tc.in))
		})
	}
}

func TestTerraformDirectoryQuotedBools(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
variable "security" {
  type = map(string)
  default = {
    privileged = "true"
  }
}

resource "kubernetes_deployment_v1" "web" {
  metadata {
    name = "web"
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
        host_network = "true"
        container {
          name  = "app"
          image = "nginx:1.27.0"
          env {
            name  = "DEBUG"
            value = "true"
          }
          security_context {
            privileged                 = var.security["privileged"]
            read_only_root_filesystem  = "true"
            allow_privilege_escalation = "false"
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
			podSpec := w.GetObject()["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
			assert.Equal(t, true, podSpec["hostNetwork"], "Terraform turns \"true\" into a bool for a bool argument")
			container := podSpec["containers"].([]interface{})[0].(map[string]interface{})
			securityContext := container["securityContext"].(map[string]interface{})
			assert.Equal(t, true, securityContext["privileged"], "a map(string) value is still converted at the bool argument")
			assert.Equal(t, true, securityContext["readOnlyRootFilesystem"])
			assert.Equal(t, false, securityContext["allowPrivilegeEscalation"])
			env := container["env"].([]interface{})[0].(map[string]interface{})
			assert.Equal(t, "true", env["value"], "an env value is a string argument and stays a string")
		}
	}
	require.True(t, found, "the Deployment must be extracted")
}

const quotedBoolsPodTerraform = `
resource "kubernetes_pod_v1" "web" {
  metadata {
    name   = "web"
    labels = { app = "web", privileged = "true" }
  }
  spec {
    host_ipc = "true"
    container {
      name  = "app"
      image = "nginx:1.27.0"
      security_context {
        privileged = "1"
      }
    }
  }
}
`

func TestExtractTypedResourcesQuotedBoolsPod(t *testing.T) {
	pod := typedManifestsByName(t, quotedBoolsPodTerraform)["Pod/web"]
	spec := pod["spec"].(map[string]interface{})
	assert.Equal(t, true, spec["hostIPC"])
	container := spec["containers"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, true, container["securityContext"].(map[string]interface{})["privileged"], `Terraform reads "1" as true for a bool`)
	labels := pod["metadata"].(map[string]interface{})["labels"].(map[string]interface{})
	assert.Equal(t, "true", labels["privileged"], "a label value is a string even when its key is a bool field name")
}

// privilegedPodRego mirrors the comparisons the privileged container (C-0057)
// and host IPC (C-0038) rules make: the fields have to be the bool true.
const privilegedPodRego = `
package test

import rego.v1

privileged if input.spec.containers[_].securityContext.privileged == true

host_ipc if input.spec.hostIPC == true
`

func TestQuotedPrivilegedIsSeenAsPrivileged(t *testing.T) {
	raw, err := json.Marshal(typedManifestsByName(t, quotedBoolsPodTerraform)["Pod/web"])
	require.NoError(t, err)
	var input interface{}
	require.NoError(t, json.Unmarshal(raw, &input))

	eval := func(query string) bool {
		rs, err := rego.New(rego.Query(query), rego.Module("test.rego", privilegedPodRego), rego.Input(input)).Eval(context.Background())
		require.NoError(t, err)
		return len(rs) == 1 && rs[0].Expressions[0].Value == true
	}

	assert.True(t, eval("data.test.privileged"), `privileged = "1" is a privileged container`)
	assert.True(t, eval("data.test.host_ipc"), `host_ipc = "true" shares the host IPC namespace`)
}
