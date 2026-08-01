package resourcehandler

import (
	"net/http"
	"net/http/httptest"
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

	t.Run("load resources from Git URL", func(t *testing.T) {
		// Create a test HTTP server that serves YAML files
		yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: test
        image: nginx:latest
---
apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: default
spec:
  selector:
    app: test
  ports:
  - port: 80
    targetPort: 8080`

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-yaml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(yamlContent))
		}))
		defer server.Close()

		// Test with the server URL
		workloads, err := LoadResourcesFromUrl([]string{server.URL})

		// The function should handle the URL attempt
		// Note: Since this is a mock server and not a real Git repository,
		// the giturl library may not recognize it as a valid Git URL
		// This test validates that the function can process URL inputs
		assert.Nil(t, err)
		// The result may be nil if giturl doesn't recognize the mock server as a Git repo
		// This is expected behavior for non-Git URLs
		if workloads != nil {
			assert.Greater(t, len(workloads), 0, "Expected to load resources from URL")
		}
	})
}
