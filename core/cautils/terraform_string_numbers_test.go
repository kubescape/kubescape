package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttributeValueForIntOrStringPorts(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		attrName string
		in       interface{}
		want     interface{}
	}{
		{"service target_port digits", "kubernetes_service_v1.web.spec.port", "target_port", "8080", json.Number("8080")},
		{"unversioned service target_port digits", "kubernetes_service.web.spec.port", "target_port", "443", json.Number("443")},
		{"service target_port leading zeros", "kubernetes_service_v1.web.spec.port", "target_port", "0080", json.Number("80")},
		{"service target_port name", "kubernetes_service_v1.web.spec.port", "target_port", "http", "http"},
		{"service target_port mixed", "kubernetes_service_v1.web.spec.port", "target_port", "8080a", "8080a"},
		{"service target_port number literal", "kubernetes_service_v1.web.spec.port", "target_port", json.Number("8080"), json.Number("8080")},
		{"target_port outside a service", "kubernetes_deployment_v1.web.spec.port", "target_port", "8080", "8080"},
		{"service port name attribute", "kubernetes_service_v1.web.spec.port", "name", "8080", "8080"},
		{"liveness http_get port", "kubernetes_deployment_v1.web.spec.template.spec.container.liveness_probe.http_get", "port", "8080", json.Number("8080")},
		{"readiness tcp_socket port", "kubernetes_pod_v1.web.spec.container.readiness_probe.tcp_socket", "port", "5432", json.Number("5432")},
		{"lifecycle hook http_get port", "kubernetes_pod_v1.web.spec.container.lifecycle.post_start.http_get", "port", "9000", json.Number("9000")},
		{"named probe port", "kubernetes_pod_v1.web.spec.container.liveness_probe.http_get", "port", "health", "health"},
		{"http_get path stays a string", "kubernetes_pod_v1.web.spec.container.liveness_probe.http_get", "path", "200", "200"},
		{"container port name stays a string", "kubernetes_pod_v1.web.spec.container.port", "name", "8080", "8080"},
		{"relative http_get path", "http_get", "port", "8080", json.Number("8080")},
		{"relative service port path", "port", "target_port", "8080", json.Number("8080")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, attributeValueFor(tc.path, tc.attrName, tc.in))
		})
	}
}

const quotedPortsTerraform = `
resource "kubernetes_deployment_v1" "web" {
  metadata {
    name      = "web"
    namespace = "prod"
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
        container {
          name  = "web"
          image = "nginx"
          port {
            container_port = 8080
          }
          liveness_probe {
            http_get {
              path = "/healthz"
              port = "8080"
            }
          }
          readiness_probe {
            tcp_socket {
              port = "8080"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "web" {
  metadata {
    name      = "web"
    namespace = "prod"
  }
  spec {
    type     = "LoadBalancer"
    selector = { app = "web" }
    port {
      port        = 80
      target_port = "8080"
    }
  }
}

resource "kubernetes_service_v1" "named" {
  metadata {
    name      = "named"
    namespace = "prod"
  }
  spec {
    type     = "NodePort"
    selector = { app = "web" }
    port {
      port        = 81
      target_port = "http"
    }
  }
}
`

func typedManifestsByName(t *testing.T, src string) map[string]map[string]interface{} {
	t.Helper()
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	byName := make(map[string]map[string]interface{}, len(manifests))
	for _, m := range manifests {
		key := m["kind"].(string) + "/" + m["metadata"].(map[string]interface{})["name"].(string)
		byName[key] = m
	}
	return byName
}

func TestExtractTypedResourcesQuotedIntOrStringPorts(t *testing.T) {
	byName := typedManifestsByName(t, quotedPortsTerraform)

	servicePort := byName["Service/web"]["spec"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, json.Number("8080"), servicePort["targetPort"])
	assert.Equal(t, json.Number("80"), servicePort["port"])

	namedPort := byName["Service/named"]["spec"].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "http", namedPort["targetPort"], "a port name stays a name")

	container := byName["Deployment/web"]["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})
	httpGet := container["livenessProbe"].(map[string]interface{})["httpGet"].(map[string]interface{})
	assert.Equal(t, json.Number("8080"), httpGet["port"])
	assert.Equal(t, "/healthz", httpGet["path"])
	tcpSocket := container["readinessProbe"].(map[string]interface{})["tcpSocket"].(map[string]interface{})
	assert.Equal(t, json.Number("8080"), tcpSocket["port"])
}

func TestTerraformDirectoryQuotedTargetPort(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
variable "target_port" {
  type    = string
  default = "8080"
}

resource "kubernetes_service_v1" "web" {
  metadata {
    name = "web"
  }
  spec {
    type     = "LoadBalancer"
    selector = { app = "web" }
    port {
      port        = 80
      target_port = var.target_port
    }
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	var found bool
	for _, list := range workloads {
		for _, w := range list {
			if w.GetKind() != "Service" {
				continue
			}
			found = true
			ports := w.GetObject()["spec"].(map[string]interface{})["ports"].([]interface{})
			assert.Equal(t, json.Number("8080"), ports[0].(map[string]interface{})["targetPort"],
				"a string variable holding a port number becomes a number, as the provider does")
		}
	}
	require.True(t, found, "the Service must be extracted")
}

// targetPortResolvesRego mirrors how the exposure-to-internet rule (C-0256)
// decides whether a Service's targetPort reaches a workload: a number always
// does, a string has to name one of the container's ports.
const targetPortResolvesRego = `
package test

import rego.v1

resolves if {
	port := input.service.spec.ports[_]
	not is_string(port.targetPort)
}

resolves if {
	port := input.service.spec.ports[_]
	is_string(port.targetPort)
	container_port := input.workload.spec.template.spec.containers[_].ports[_]
	container_port.name == port.targetPort
}
`

func TestQuotedTargetPortResolvesToTheWorkload(t *testing.T) {
	byName := typedManifestsByName(t, quotedPortsTerraform)
	query, err := rego.New(rego.Query("data.test.resolves"), rego.Module("test.rego", targetPortResolvesRego)).PrepareForEval(context.Background())
	require.NoError(t, err)

	resolves := func(service string) bool {
		raw, err := json.Marshal(map[string]interface{}{"service": byName["Service/"+service], "workload": byName["Deployment/web"]})
		require.NoError(t, err)
		var input interface{}
		require.NoError(t, json.Unmarshal(raw, &input))
		rs, err := query.Eval(context.Background(), rego.EvalInput(input))
		require.NoError(t, err)
		return len(rs) == 1 && rs[0].Expressions[0].Value == true
	}

	assert.True(t, resolves("web"), `target_port = "8080" reaches the container listening on 8080`)
	assert.False(t, resolves("named"), "a target port name with no matching container port still does not resolve")
}

func TestAttributeValueForSecurityContextIDs(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		attrName string
		in       interface{}
		want     interface{}
	}{
		{"container run_as_user root", "kubernetes_pod_v1.web.spec.container.security_context", "run_as_user", "0", json.Number("0")},
		{"container run_as_group", "kubernetes_pod_v1.web.spec.container.security_context", "run_as_group", "1000", json.Number("1000")},
		{"pod run_as_user", "kubernetes_deployment_v1.web.spec.template.spec.security_context", "run_as_user", "1000", json.Number("1000")},
		{"pod fs_group", "kubernetes_deployment_v1.web.spec.template.spec.security_context", "fs_group", "2000", json.Number("2000")},
		{"leading zeros", "kubernetes_pod_v1.web.spec.security_context", "run_as_user", "000", json.Number("0")},
		{"number literal is untouched", "kubernetes_pod_v1.web.spec.security_context", "run_as_user", json.Number("0"), json.Number("0")},
		{"windows user name stays a string", "kubernetes_pod_v1.web.spec.security_context.windows_options", "run_as_username", "1000", "1000"},
		{"fs_group_change_policy stays a string", "kubernetes_pod_v1.web.spec.security_context", "fs_group_change_policy", "Always", "Always"},
		{"run_as_user outside a security context", "kubernetes_pod_v1.web.spec.container", "run_as_user", "0", "0"},
		{"relative security context path", "security_context", "run_as_group", "0", json.Number("0")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, attributeValueFor(tc.path, tc.attrName, tc.in))
		})
	}
}

const quotedSecurityContextTerraform = `
resource "kubernetes_deployment_v1" "root" {
  metadata {
    name = "root"
  }
  spec {
    selector {
      match_labels = { app = "root" }
    }
    template {
      metadata {
        labels = { app = "root" }
      }
      spec {
        security_context {
          run_as_user  = "0"
          run_as_group = "0"
          fs_group     = "2000"
        }
        container {
          name  = "app"
          image = "nginx"
          security_context {
            run_as_user  = "0"
            run_as_group = "3000"
          }
        }
      }
    }
  }
}
`

func TestExtractTypedResourcesQuotedSecurityContextIDs(t *testing.T) {
	byName := typedManifestsByName(t, quotedSecurityContextTerraform)

	podSpec := byName["Deployment/root"]["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
	podContext := podSpec["securityContext"].(map[string]interface{})
	assert.Equal(t, json.Number("0"), podContext["runAsUser"])
	assert.Equal(t, json.Number("0"), podContext["runAsGroup"])
	assert.Equal(t, json.Number("2000"), podContext["fsGroup"])

	containerContext := podSpec["containers"].([]interface{})[0].(map[string]interface{})["securityContext"].(map[string]interface{})
	assert.Equal(t, json.Number("0"), containerContext["runAsUser"])
	assert.Equal(t, json.Number("3000"), containerContext["runAsGroup"])
}

// runsAsRootRego mirrors the comparison the non-root-containers rule (C-0013)
// makes on the container's own securityContext: a runAsUser or runAsGroup
// equal to the number 0 is root.
const runsAsRootRego = `
package test

import rego.v1

root_user if input.spec.template.spec.containers[_].securityContext.runAsUser == 0

root_group if input.spec.template.spec.containers[_].securityContext.runAsGroup == 0
`

func TestQuotedRootUserIsSeenAsRoot(t *testing.T) {
	byName := typedManifestsByName(t, quotedSecurityContextTerraform)
	raw, err := json.Marshal(byName["Deployment/root"])
	require.NoError(t, err)
	var input interface{}
	require.NoError(t, json.Unmarshal(raw, &input))

	eval := func(query string) bool {
		rs, err := rego.New(rego.Query(query), rego.Module("test.rego", runsAsRootRego), rego.Input(input)).Eval(context.Background())
		require.NoError(t, err)
		return len(rs) == 1 && rs[0].Expressions[0].Value == true
	}

	assert.True(t, eval("data.test.root_user"), `run_as_user = "0" is a root user`)
	assert.False(t, eval("data.test.root_group"), `run_as_group = "3000" is not the root group`)
}
