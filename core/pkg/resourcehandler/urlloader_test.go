package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadResourcesFromUrl(t *testing.T) {
	t.Run("load resources from local path", func(t *testing.T) {
		// Create a temporary directory with test YAML files
		tmpDir, err := os.MkdirTemp("", "urlloader-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		// Create a test YAML file
		yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: adservice
  namespace: default
spec:
  replicas: 1
---
apiVersion: v1
kind: Service
metadata:
  name: adservice
  namespace: default
spec:
  ports:
  - port: 9555`

		yamlPath := filepath.Join(tmpDir, "adservice.yaml")
		err = os.WriteFile(yamlPath, []byte(yamlContent), 0600)
		require.NoError(t, err)

		// Test loading resources from the local path
		// Note: Since the giturl library expects git URLs, this test validates
		// that the function returns an error when giturl parsing fails
		workloads, err := LoadResourcesFromUrl(context.Background(), []string{tmpDir})

		// The function should return an error when giturl parsing fails
		assert.Error(t, err)
		assert.Nil(t, workloads)
		assert.Contains(t, err.Error(), "failed to parse Git URL")
	})

	t.Run("empty input patterns", func(t *testing.T) {
		workloads, err := LoadResourcesFromUrl(context.Background(), []string{})
		assert.Nil(t, err)
		assert.Nil(t, workloads)
	})

	t.Run("invalid URL returns parse error", func(t *testing.T) {
		workloads, err := LoadResourcesFromUrl(context.Background(), []string{"not-a-valid-url"})
		assert.Error(t, err)
		assert.Nil(t, workloads)
		assert.Contains(t, err.Error(), "failed to parse Git URL")
	})

	// NOTE: Testing the actual download functionality would require either:
	// 1. Making the git client injectable (interface for DownloadFilesWithExtension)
	// 2. Using a local git fixture like TestSetContextMetadata
	// The current test only validates early returns (empty input, invalid URL parsing)
	// Full coverage of DownloadFilesWithExtension, filepath.Ext, and cautils.ReadFile
	// would require dependency injection or deterministic Git fixtures.
}
