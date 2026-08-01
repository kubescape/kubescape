package resourcehandler

import (
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
		// that the function handles the case where giturl parsing fails gracefully
		workloads, err := LoadResourcesFromUrl([]string{tmpDir})

		// The function should return nil, nil when giturl parsing fails
		assert.Nil(t, err)
		assert.Nil(t, workloads)
	})

	t.Run("empty input patterns", func(t *testing.T) {
		workloads, err := LoadResourcesFromUrl([]string{})
		assert.Nil(t, err)
		assert.Nil(t, workloads)
	})
}
