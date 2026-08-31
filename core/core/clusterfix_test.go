package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func fixResource(namespace, kind, name string) *reporthandling.Resource {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
	}
	if namespace != "" {
		obj["metadata"].(map[string]any)["namespace"] = namespace
	}
	return &reporthandling.Resource{ResourceID: namespace + "/" + kind + "/" + name, Object: obj}
}

func renderedFix(namespace, kind, name, manifest string) fixhandler.RenderedFix {
	return fixhandler.RenderedFix{Resource: fixResource(namespace, kind, name), Manifest: manifest}
}

// --- filenames ------------------------------------------------------------

func TestClusterFixFileName(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		kind      string
		resource  string
		want      string
	}{
		{
			name:      "namespaced resource",
			namespace: "default",
			kind:      "Deployment",
			resource:  "nginx",
			want:      "default_Deployment_nginx.yaml",
		},
		{
			name:     "cluster-scoped resource omits the namespace segment",
			kind:     "ClusterRole",
			resource: "admin",
			want:     "ClusterRole_admin.yaml",
		},
		{
			name:      "separators in a name cannot build a path",
			namespace: "default",
			kind:      "Deployment",
			resource:  "../../etc/passwd",
			want:      "default_Deployment_etc-passwd.yaml",
		},
		{
			name:      "a name that is only traversal still yields a filename",
			namespace: "default",
			kind:      "Deployment",
			resource:  "..",
			want:      "default_Deployment_resource.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clusterFixFileName(fixResource(tt.namespace, tt.kind, tt.resource))
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, string(os.PathSeparator), "a filename must never contain a separator")
			assert.NotContains(t, got, "..")
		})
	}
}

// --- stdout ---------------------------------------------------------------

func TestPrintClusterFixes_ProducesAValidDocumentStream(t *testing.T) {
	var buf bytes.Buffer
	err := printClusterFixes(&buf, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "nginx", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\n"),
		renderedFix("kube-system", "DaemonSet", "node-exporter", "apiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: node-exporter\n"),
	})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "# default/Deployment/nginx")
	assert.Contains(t, out, "# kube-system/DaemonSet/node-exporter")

	// The whole stream has to parse as multiple YAML documents, or the pipe
	// into `kubectl apply -f -` is worthless.
	decoder := yaml.NewDecoder(strings.NewReader(out))
	var docs []map[string]any
	for {
		var doc map[string]any
		err := decoder.Decode(&doc)
		if err != nil {
			break
		}
		docs = append(docs, doc)
	}
	require.Len(t, docs, 2, "both manifests must decode as separate documents")
	assert.Equal(t, "Deployment", docs[0]["kind"])
	assert.Equal(t, "DaemonSet", docs[1]["kind"])
}

// TestPrintClusterFixes_NormalizesTrailingNewline guards the separator: without
// exactly one trailing newline the next `---` lands on the previous field's
// line and the stream stops parsing.
func TestPrintClusterFixes_NormalizesTrailingNewline(t *testing.T) {
	for _, manifest := range []string{
		"kind: Deployment",         // none
		"kind: Deployment\n",       // one
		"kind: Deployment\n\n\n\n", // several
	} {
		var buf bytes.Buffer
		require.NoError(t, printClusterFixes(&buf, []fixhandler.RenderedFix{
			renderedFix("default", "Deployment", "a", manifest),
			renderedFix("default", "Deployment", "b", "kind: Service\n"),
		}))
		assert.Contains(t, buf.String(), "kind: Deployment\n---\n", "input %q broke the separator", manifest)
	}
}

func TestPrintClusterFixes_ClusterScopedLabel(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printClusterFixes(&buf, []fixhandler.RenderedFix{
		renderedFix("", "ClusterRole", "admin", "kind: ClusterRole\n"),
	}))
	assert.Contains(t, buf.String(), "# ClusterRole/admin")
}

// --- output directory -----------------------------------------------------

func TestWriteClusterFixes_WritesOneFilePerResource(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixes")

	written, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "nginx", "kind: Deployment\n"),
		renderedFix("kube-system", "DaemonSet", "node-exporter", "kind: DaemonSet\n"),
	}, false)
	require.NoError(t, err)
	require.Len(t, written, 2)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "the directory should be created and hold one file per resource")

	content, err := os.ReadFile(filepath.Join(dir, "default_Deployment_nginx.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "kind: Deployment\n", string(content))
}

func TestWriteClusterFixes_RefusesNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "precious.yaml"), []byte("keep me"), 0600))

	_, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "nginx", "kind: Deployment\n"),
	}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not empty")

	// The existing file must be untouched by the refusal.
	content, err := os.ReadFile(filepath.Join(dir, "precious.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(content))
}

func TestWriteClusterFixes_NoConfirmAllowsNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "existing.yaml"), []byte("x"), 0600))

	written, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "nginx", "kind: Deployment\n"),
	}, true)
	require.NoError(t, err)
	assert.Len(t, written, 1)
}

// TestWriteClusterFixes_CannotEscapeOutputDir is the case to read first: the
// resource name comes from the report, which `kubescape fix` treats as
// untrusted input.
func TestWriteClusterFixes_CannotEscapeOutputDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "fixes")
	outside := filepath.Join(root, "escaped.yaml")

	written, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("..", "Deployment", "../escaped", "kind: Deployment\n"),
	}, false)
	require.NoError(t, err)
	require.Len(t, written, 1)

	assert.NoFileExists(t, outside, "a report-supplied name must not write outside the output directory")
	for _, path := range written {
		assert.Equal(t, filepath.Clean(dir), filepath.Dir(path))
	}
}
