package cel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbeddedLibraryYAMLServesTheVendoredBundle proves the deployable stream
// is exactly the vendored files (read via the on-disk copies of the embedded
// dir, like the vapdata sanity tests), so deploy-library serves the same bundle
// the engine evaluates.
func TestEmbeddedLibraryYAMLServesTheVendoredBundle(t *testing.T) {
	out, err := EmbeddedLibraryYAML()
	require.NoError(t, err)

	for _, name := range deployFiles {
		data, err := os.ReadFile(filepath.Join(vapdataDir, name))
		require.NoError(t, err)
		assert.Contains(t, out, string(data), "%s must be in the deployable stream verbatim", name)
	}
}

// TestEmbeddedLibraryYAMLApplyOrder proves the documents come out in apply
// order: the CRD before the ControlConfiguration instance that needs it, and
// the policies last.
func TestEmbeddedLibraryYAMLApplyOrder(t *testing.T) {
	out, err := EmbeddedLibraryYAML()
	require.NoError(t, err)

	crd := strings.Index(out, "kind: CustomResourceDefinition")
	config := strings.Index(out, "kind: ControlConfiguration")
	policies := strings.Index(out, "kind: ValidatingAdmissionPolicy")

	require.GreaterOrEqual(t, crd, 0, "stream must contain the params CRD")
	require.GreaterOrEqual(t, config, 0, "stream must contain the control configuration")
	require.GreaterOrEqual(t, policies, 0, "stream must contain the policies")
	assert.Less(t, crd, config, "CRD must precede the configuration instance")
	assert.Less(t, config, policies, "configuration must precede the policies")
}
