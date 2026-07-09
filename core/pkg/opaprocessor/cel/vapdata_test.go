package cel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests guard the prerequisite the loader (loader.go) //go:embeds: the
// vendored bundle is actually in the tree and looks like the cel-admission-library
// release, so `make sync-vap` populated it and did not, say, leave an empty
// directory or an HTML error page. (vapdataDir is declared in loader.go.)

// TestVapdataBundlePresent checks the three files the engine relies on exist and
// are non-empty.
func TestVapdataBundlePresent(t *testing.T) {
	for _, name := range []string{
		"kubescape-validating-admission-policies.yaml",
		"basic-control-configuration.yaml",
		"policy-configuration-definition.yaml",
	} {
		info, err := os.Stat(filepath.Join(vapdataDir, name))
		require.NoErrorf(t, err, "%s must be vendored (run `make sync-vap`)", name)
		assert.NotZerof(t, info.Size(), "%s must not be empty", name)
	}
}

// TestVapdataHasValidatingAdmissionPolicies checks the policy file is the VAP
// bundle and carries a known control, so we did not vendor the wrong artifact.
func TestVapdataHasValidatingAdmissionPolicies(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vapdataDir, "kubescape-validating-admission-policies.yaml"))
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "kind: ValidatingAdmissionPolicy")
	assert.Contains(t, content, "controlId: C-0017")
}

// TestVapdataBasicControlConfiguration checks the params file is the control
// configuration the loader resolves paramKind values against.
func TestVapdataBasicControlConfiguration(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vapdataDir, "basic-control-configuration.yaml"))
	require.NoError(t, err)

	content := string(data)
	assert.True(t, strings.Contains(content, "kind: ControlConfiguration"), "expected a ControlConfiguration document")
	assert.Contains(t, content, "settings:")
}
