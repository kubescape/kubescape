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

// TestPrintClusterFixes_LabelCannotInjectDocuments covers the report being
// untrusted input: a newline in a resource name would close the comment the
// label sits in and let the remainder become further YAML documents in a stream
// the user is about to pipe into kubectl.
func TestPrintClusterFixes_LabelCannotInjectDocuments(t *testing.T) {
	for _, name := range []string{
		"nginx\n---\nkind: Evil",
		"nginx\r---\rkind: Evil",
		"nginx\r\n---\r\nkind: Evil",
	} {
		var buf bytes.Buffer
		require.NoError(t, printClusterFixes(&buf, []fixhandler.RenderedFix{
			renderedFix("default", "Deployment", name, "kind: Deployment\n"),
		}))

		decoder := yaml.NewDecoder(strings.NewReader(buf.String()))
		var docs []map[string]any
		for {
			var doc map[string]any
			if err := decoder.Decode(&doc); err != nil {
				break
			}
			docs = append(docs, doc)
		}
		require.Len(t, docs, 1, "a crafted name must not add documents: %q", buf.String())
		assert.Equal(t, "Deployment", docs[0]["kind"])

		// The injected text may survive inside the comment — that is harmless.
		// What must not happen is it escaping onto a line of its own, so every
		// line carrying it has to still be the comment.
		separators := 0
		for _, line := range strings.Split(buf.String(), "\n") {
			if line == "---" {
				separators++
			}
			if strings.Contains(line, "Evil") {
				assert.Truef(t, strings.HasPrefix(line, "#"),
					"injected text escaped the comment onto its own line: %q", line)
			}
		}
		assert.Equal(t, 1, separators, "a crafted name must not introduce a second document separator")
	}
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

// TestWriteClusterFixes_DisambiguatesCollidingNames guards against silently
// dropping a manifest: the base name omits the API group and version, and
// sanitizing folds separators into dashes, so two distinct resources can reduce
// to one filename and the second would overwrite the first.
func TestWriteClusterFixes_DisambiguatesCollidingNames(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixes")

	// "a/b" and "a-b" both sanitize to "a-b".
	written, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "a/b", "kind: Deployment\nmetadata:\n  name: first\n"),
		renderedFix("default", "Deployment", "a-b", "kind: Deployment\nmetadata:\n  name: second\n"),
	}, false)
	require.NoError(t, err)
	require.Len(t, written, 2)

	assert.NotEqual(t, written[0], written[1], "colliding names must resolve to distinct files")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "both manifests must survive")

	// Naming must be stable across runs, or every run churns the output dir.
	again, err := writeClusterFixes(filepath.Join(t.TempDir(), "again"), []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "a/b", "kind: Deployment\n"),
		renderedFix("default", "Deployment", "a-b", "kind: Deployment\n"),
	}, false)
	require.NoError(t, err)
	assert.Equal(t, filepath.Base(written[0]), filepath.Base(again[0]))
	assert.Equal(t, filepath.Base(written[1]), filepath.Base(again[1]))
}

// TestWriteClusterFixes_KeepsPlainNamesWhenUnique keeps the common case
// readable: disambiguation only kicks in on an actual collision.
func TestWriteClusterFixes_KeepsPlainNamesWhenUnique(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixes")

	written, err := writeClusterFixes(dir, []fixhandler.RenderedFix{
		renderedFix("default", "Deployment", "nginx", "kind: Deployment\n"),
		renderedFix("kube-system", "DaemonSet", "kube-proxy", "kind: DaemonSet\n"),
	}, false)
	require.NoError(t, err)

	assert.Equal(t, "default_Deployment_nginx.yaml", filepath.Base(written[0]))
	assert.Equal(t, "kube-system_DaemonSet_kube-proxy.yaml", filepath.Base(written[1]))
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
