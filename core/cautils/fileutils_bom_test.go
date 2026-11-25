package cautils

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// utf8BOM is the byte order mark that Windows editors, and PowerShell's
// Out-File -Encoding utf8, write at the start of a file.
const utf8BOM = "\xef\xbb\xbf"

const bomPodJSON = `{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web", "namespace": "default"}, "spec": {"containers": [{"name": "c", "image": "nginx"}]}}`

const bomPodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: default
spec:
  containers:
    - name: c
      image: nginx
`

// A byte order mark is not part of the document. A JSON manifest that starts
// with one has to load like the same manifest without it, as the YAML reader
// already does for a .yaml file.
func TestReadFileSkipsUTF8ByteOrderMark(t *testing.T) {
	tests := []struct {
		name    string
		format  FileFormat
		content string
	}{
		{name: "json", format: JSON_FILE_FORMAT, content: bomPodJSON},
		{name: "yaml", format: YAML_FILE_FORMAT, content: bomPodYAML},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plain, err := ReadFile([]byte(tt.content), tt.format)
			require.NoError(t, err)
			require.Len(t, plain, 1)

			withBOM, err := ReadFile([]byte(utf8BOM+tt.content), tt.format)
			require.NoError(t, err)
			require.Len(t, withBOM, 1)
			assert.Equal(t, plain[0].GetObject(), withBOM[0].GetObject())
		})
	}
}

// A scan of a directory has to pick up a JSON manifest saved with a byte order
// mark, not report it as a file it failed to parse.
func TestLoadResourcesFromFilesReadsJSONManifestWithByteOrderMark(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "pod.json")
	require.NoError(t, os.WriteFile(path, []byte(utf8BOM+bomPodJSON), 0o600))

	workloads, skipped, err := LoadResourcesFromFiles(context.Background(), root, root, nil)

	require.NoError(t, err)
	assert.Empty(t, skipped)
	require.Len(t, workloads[path], 1)
	assert.Equal(t, "Pod", workloads[path][0].GetKind())
	assert.Equal(t, "web", workloads[path][0].GetName())
}
