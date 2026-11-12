package getter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultControlInputs(t *testing.T) {
	t.Parallel()

	inputs, err := DefaultControlInputs()
	require.NoError(t, err)
	require.NotNil(t, inputs)
	assert.NotEmpty(t, inputs)

	// Known keys from the embedded default-config-inputs.json
	require.Contains(t, inputs, "insecureCapabilities")
	assert.Contains(t, inputs["insecureCapabilities"], "SYS_ADMIN")
	assert.Contains(t, inputs["insecureCapabilities"], "NET_ADMIN")

	require.Contains(t, inputs, "listOfDangerousArtifacts")
	assert.Contains(t, inputs["listOfDangerousArtifacts"], "bin/bash")
	assert.Contains(t, inputs["listOfDangerousArtifacts"], "bin/busybox")

	require.Contains(t, inputs, "sensitiveInterfaces")
	assert.Contains(t, inputs["sensitiveInterfaces"], "jenkins")
	assert.Contains(t, inputs["sensitiveInterfaces"], "kubernetes-dashboard")
}
