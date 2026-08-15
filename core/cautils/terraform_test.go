package cautils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformDirectory_GetWorkloads_MapsSysctls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(path, []byte(`
resource "kubernetes_pod_v1" "example" {
  metadata {
    name      = "sysctl-test"
    namespace = "default"
  }
  spec {
    security_context {
      sysctl {
        name  = "net.ipv4.ip_local_port_range"
        value = "1024 65535"
      }
    }
    container {
      name  = "pause"
      image = "registry.k8s.io/pause:3.9"
    }
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	require.Len(t, workloads[path], 1)

	obj := workloads[path][0].GetObject()
	spec := obj["spec"].(map[string]interface{})
	securityContext := spec["securityContext"].(map[string]interface{})
	assert.NotContains(t, securityContext, "sysctl")
	sysctls, ok := securityContext["sysctls"].([]interface{})
	require.True(t, ok, "securityContext.sysctls must be an array")
	require.Len(t, sysctls, 1)
	assert.Equal(t, "net.ipv4.ip_local_port_range", sysctls[0].(map[string]interface{})["name"])
}

func TestTerraformDirectory_GetWorkloads(t *testing.T) {
	td := NewTerraformDirectory("testdata/terraform")
	workloads, errs := td.GetWorkloads("testdata/terraform")
	require.Empty(t, errs)
	require.Contains(t, workloads, "testdata/terraform/main.tf")

	wls := workloads["testdata/terraform/main.tf"]
	require.Len(t, wls, 1)
	assert.Equal(t, "Deployment", wls[0].GetKind())
	assert.Equal(t, "nginx", wls[0].GetName())
	assert.Equal(t, "default", wls[0].GetNamespace())
}

func TestTerraformDirectory_GetWorkloads_TypedResource_MetaArgsAndNestedArrays(t *testing.T) {
	td := NewTerraformDirectory("testdata/terraform_typed_meta")
	workloads, errs := td.GetWorkloads("testdata/terraform_typed_meta")
	require.Empty(t, errs)

	wls := workloads["testdata/terraform_typed_meta/main.tf"]
	var sts workloadinterface.IMetadata
	for _, w := range wls {
		if w.GetKind() == "StatefulSet" {
			sts = w
		}
	}
	require.NotNil(t, sts, "expected a StatefulSet workload")
	assert.Equal(t, "web", sts.GetName())

	obj := sts.GetObject()

	assert.NotContains(t, obj, "dependsOn")
	assert.NotContains(t, obj, "count")
	assert.NotContains(t, obj, "provider")
	assert.NotContains(t, obj, "lifecycle")

	spec := obj["spec"].(map[string]interface{})

	selector := spec["selector"].(map[string]interface{})
	matchExprs, ok := selector["matchExpressions"].([]interface{})
	require.True(t, ok, "expected selector.matchExpressions to be an array")
	require.Len(t, matchExprs, 1)
	assert.Equal(t, "app", matchExprs[0].(map[string]interface{})["key"])

	vcts, ok := spec["volumeClaimTemplates"].([]interface{})
	require.True(t, ok, "expected spec.volumeClaimTemplates to be an array")
	require.Len(t, vcts, 1)

	tmplSpec := spec["template"].(map[string]interface{})["spec"].(map[string]interface{})
	containers := tmplSpec["containers"].([]interface{})
	require.Len(t, containers, 1)
	c := containers[0].(map[string]interface{})
	httpGet := c["readinessProbe"].(map[string]interface{})["httpGet"].(map[string]interface{})
	headers, ok := httpGet["httpHeaders"].([]interface{})
	require.True(t, ok, "expected httpGet.httpHeaders to be an array")
	require.Len(t, headers, 1)
	assert.Equal(t, "X-Custom-Header", headers[0].(map[string]interface{})["name"])
}

func TestIsTerraformFile(t *testing.T) {
	assert.True(t, IsTerraformFile("main.tf"))
	assert.False(t, IsTerraformFile("main.yaml"))
}

func TestTerraformDirectory_GetWorkloads_TypedResource(t *testing.T) {
	td := NewTerraformDirectory("testdata/terraform_typed")
	workloads, errs := td.GetWorkloads("testdata/terraform_typed")
	require.Empty(t, errs)
	require.Contains(t, workloads, "testdata/terraform_typed/main.tf")

	wls := workloads["testdata/terraform_typed/main.tf"]
	require.Len(t, wls, 1)
	assert.Equal(t, "Deployment", wls[0].GetKind())
	assert.Equal(t, "nginx-typed", wls[0].GetName())
	assert.Equal(t, "default", wls[0].GetNamespace())

	obj := wls[0].GetObject()
	spec, ok := obj["spec"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "2", fmt.Sprintf("%v", spec["replicas"]))

	tmplSpec := spec["template"].(map[string]interface{})["spec"].(map[string]interface{})
	containers, ok := tmplSpec["containers"].([]interface{})
	require.True(t, ok)
	require.Len(t, containers, 1)
	c := containers[0].(map[string]interface{})
	assert.Equal(t, "nginx", c["name"])
	assert.Equal(t, "nginx:1.25", c["image"])

	ports, ok := c["ports"].([]interface{})
	require.True(t, ok)
	require.Len(t, ports, 1)
	assert.Equal(t, "80", fmt.Sprintf("%v", ports[0].(map[string]interface{})["containerPort"]))
}
func TestTerraformDirectory_GetWorkloads_PreservesLargeIntegerPrecision(t *testing.T) {
	td := NewTerraformDirectory("testdata/terraform_bignum")
	workloads, errs := td.GetWorkloads("testdata/terraform_bignum")
	require.Empty(t, errs)
	require.NotEmpty(t, workloads)

	var found bool
	for _, wls := range workloads {
		for _, w := range wls {
			obj := w.GetObject()
			meta, ok := obj["metadata"].(map[string]interface{})
			if !ok {
				continue
			}
			if v, ok := meta["generation"]; ok {
				assert.Equal(t, "9007199254740993", fmt.Sprintf("%v", v))
				found = true
			}
		}
	}
	assert.True(t, found, "expected to find the big-number annotation in scanned output")
}
