package resourcehandler

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceHandlerSentinels_Distinct(t *testing.T) {
	sentinels := []error{
		ErrResourceNotFound,
		ErrAmbiguousResource,
		ErrResourceHasParent,
		ErrNotWorkload,
		ErrSecretScanDenied,
		ErrResourceNotInDiscovery,
	}

	for i, s1 := range sentinels {
		require.NotNil(t, s1, "sentinel %d must not be nil", i)
		for j, s2 := range sentinels {
			if i != j {
				assert.NotEqual(t, s1, s2, "sentinels at index %d and %d must be distinct", i, j)
			}
		}
	}
}

func TestResourceHandlerSentinels_WrappingSitesExist(t *testing.T) {
	// Note: this is a source-level heuristic check, not a formal AST proof,
	// designed to catch accidental deletion of wrapping sites.
	//
	// It verifies that each sentinel name appears inside a fmt.Errorf call
	// containing %w as a format verb and passing the sentinel as an operand.

	sentinelNames := []string{
		"ErrResourceNotFound",
		"ErrAmbiguousResource",
		"ErrResourceHasParent",
		"ErrNotWorkload",
		"ErrSecretScanDenied",
		"ErrResourceNotInDiscovery",
	}

	sourceFiles := []string{
		"k8sresources.go",
		"filesloaderutils.go",
	}

	for _, name := range sentinelNames {
		found := false
		pattern := regexp.MustCompile(`fmt\.Errorf\(.*%w.*,\s*` + regexp.QuoteMeta(name) + `\)`)
		for _, file := range sourceFiles {
			content, err := os.ReadFile(file)
			require.NoError(t, err)
			for _, line := range regexp.MustCompile(`\r?\n`).Split(string(content), -1) {
				if pattern.MatchString(line) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("sentinel %s is not wrapped with %%w in any source file; "+
				"the MCP error classifier depends on this wrapping", name)
		}
	}
}
