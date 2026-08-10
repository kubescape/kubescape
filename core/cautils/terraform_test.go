package cautils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestIsTerraformFile(t *testing.T) {
	assert.True(t, IsTerraformFile("main.tf"))
	assert.False(t, IsTerraformFile("main.yaml"))
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
			ann, ok := meta["annotations"].(map[string]interface{})
			if !ok {
				continue
			}
			if v, ok := ann["big-number"]; ok {
				assert.Equal(t, "9007199254740993", fmt.Sprintf("%v", v))
				found = true
			}
		}
	}
	assert.True(t, found, "expected to find the big-number annotation in scanned output")
}
