package pss

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLocalWorkloads_SingleFile(t *testing.T) {
	yamlContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-dep
  namespace: prod
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "dep.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

	objs, err := ParseLocalWorkloads([]string{filePath})
	require.NoError(t, err)
	require.Len(t, objs, 1)
	assert.Equal(t, "Deployment", objs[0].GetKind())
	assert.Equal(t, "nginx-dep", objs[0].GetName())
	assert.Equal(t, "prod", objs[0].GetNamespace())
}

func TestParseLocalWorkloads_MultiDoc(t *testing.T) {
	yamlContent := `
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  ports:
  - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
      - name: web
        image: web:latest
---
# empty doc

---
apiVersion: v1
kind: Pod
metadata:
  name: standalone-pod
spec:
  containers:
  - name: box
    image: busybox
`
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "multi.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

	objs, err := ParseLocalWorkloads([]string{filePath})
	require.NoError(t, err)
	// Service and empty doc should be skipped, only Deployment and Pod kept
	require.Len(t, objs, 2)
	assert.Equal(t, "Deployment", objs[0].GetKind())
	assert.Equal(t, "web-app", objs[0].GetName())
	assert.Equal(t, "Pod", objs[1].GetKind())
	assert.Equal(t, "standalone-pod", objs[1].GetName())
}

func TestParseLocalWorkloads_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "dep.yaml")
	file2 := filepath.Join(tmpDir, "pod.json")
	file3 := filepath.Join(tmpDir, "notes.txt")

	require.NoError(t, os.WriteFile(file1, []byte(`
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-stateful
spec:
  template:
    spec:
      containers:
      - name: db
        image: postgres
`), 0600))

	require.NoError(t, os.WriteFile(file2, []byte(`{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "json-pod"},
  "spec": {
    "containers": [{"name": "c", "image": "redis"}]
  }
}`), 0600))

	require.NoError(t, os.WriteFile(file3, []byte("Just some plain text"), 0600))

	objs, err := ParseLocalWorkloads([]string{tmpDir})
	require.NoError(t, err)
	require.Len(t, objs, 2)

	kinds := []string{objs[0].GetKind(), objs[1].GetKind()}
	assert.Contains(t, kinds, "StatefulSet")
	assert.Contains(t, kinds, "Pod")
}

func TestParseLocalWorkloads_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(":: bad yaml ::"), 0600))

	_, err := ParseLocalWorkloads([]string{filePath})
	assert.Error(t, err)
}

func TestParseLocalWorkloads_NonExistent(t *testing.T) {
	_, err := ParseLocalWorkloads([]string{"/non/existent/file.yaml"})
	assert.Error(t, err)
}

func TestParseLocalWorkloadsFromReader(t *testing.T) {
	content := `
apiVersion: batch/v1
kind: Job
metadata:
  name: batch-job
spec:
  template:
    spec:
      containers:
      - name: worker
        image: worker:v1
`
	objs, err := ParseLocalWorkloadsFromReader(strings.NewReader(content), "stdin")
	require.NoError(t, err)
	require.Len(t, objs, 1)
	assert.Equal(t, "Job", objs[0].GetKind())
	assert.Equal(t, "batch-job", objs[0].GetName())
}

func TestParseLocalWorkloads_ListEnvelopes(t *testing.T) {
	t.Run("generic List with Pod and non-workload", func(t *testing.T) {
		yamlContent := `
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Service
  metadata:
    name: svc-1
- apiVersion: v1
  kind: Pod
  metadata:
    name: pod-in-list
  spec:
    containers:
    - name: c1
      image: nginx
`
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "list.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

		objs, err := ParseLocalWorkloads([]string{filePath})
		require.NoError(t, err)
		require.Len(t, objs, 1)
		assert.Equal(t, "Pod", objs[0].GetKind())
		assert.Equal(t, "pod-in-list", objs[0].GetName())
	})

	t.Run("typed PodList restores item kind and apiVersion", func(t *testing.T) {
		yamlContent := `
apiVersion: v1
kind: PodList
items:
- metadata:
    name: pod-in-podlist
  spec:
    containers:
    - name: c1
      image: nginx
`
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "podlist.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

		objs, err := ParseLocalWorkloads([]string{filePath})
		require.NoError(t, err)
		require.Len(t, objs, 1)
		assert.Equal(t, "Pod", objs[0].GetKind())
		assert.Equal(t, "v1", objs[0].GetAPIVersion())
		assert.Equal(t, "pod-in-podlist", objs[0].GetName())
	})

	t.Run("named CR with List suffix is not treated as list envelope", func(t *testing.T) {
		yamlContent := `
apiVersion: example.com/v1
kind: AllowList
metadata:
  name: my-allowlist
spec:
  items:
  - allowed: true
`
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "allowlist.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

		objs, err := ParseLocalWorkloads([]string{filePath})
		require.NoError(t, err)
		// AllowList is not a supported workload kind and has identity, so it is skipped
		assert.Empty(t, objs)
	})

	t.Run("malformed List envelope returns error", func(t *testing.T) {
		yamlContent := `
apiVersion: v1
kind: List
items: not-an-array
`
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "bad-list.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

		_, err := ParseLocalWorkloads([]string{filePath})
		assert.Error(t, err)
		assert.ErrorContains(t, err, "items must be an array")
	})

	t.Run("nested List expands recursively", func(t *testing.T) {
		yamlContent := `
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: PodList
  items:
  - metadata:
      name: nested-pod
    spec:
      containers:
      - name: c1
        image: nginx
`
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "nested.yaml")
		require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0600))

		objs, err := ParseLocalWorkloads([]string{filePath})
		require.NoError(t, err)
		require.Len(t, objs, 1)
		assert.Equal(t, "Pod", objs[0].GetKind())
		assert.Equal(t, "nested-pod", objs[0].GetName())
	})
}
