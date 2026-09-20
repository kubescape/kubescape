package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outputDirHandler is a handler whose fixes go to outputDir instead of in place.
func outputDirHandler(baseDir, outputDir string) *FixHandler {
	return &FixHandler{
		fixInfo:       &metav1.FixInfo{OutputDir: outputDir},
		reportObj:     &reporthandlingv2.PostureReport{},
		localBasePath: baseDir,
	}
}

// imageFix pins the image of the pod in document documentIndex of source.
func imageFix(source, relativePath string, documentIndex int) ResourceFixInfo {
	expression := "select(di==" + strconv.Itoa(documentIndex) + ").spec.containers[0].image |= \"nginx:1.25\""
	return ResourceFixInfo{
		FilePath:      source,
		relativePath:  relativePath,
		DocumentIndex: documentIndex,
		YamlExpressions: map[string]armotypes.FixPath{
			expression: {Path: "spec.containers[0].image", Value: "nginx:1.25"},
		},
	}
}

const twoPods = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: first\nspec:\n  containers:\n  - name: c\n    image: nginx\n" +
	"---\n" +
	"apiVersion: v1\nkind: Pod\nmetadata:\n  name: second\nspec:\n  containers:\n  - name: c\n    image: nginx\n"

// TestApplyChanges_OutputDirMirrorsTheScannedTree covers #3847 at the write
// site. The fixed copy keeps the relative path the report recorded, nested
// directories included, and the source is not touched. The manifest holds two
// documents and only the second is fixed: the copy must still be the whole
// file, since a copy holding just the fixed resource could not replace its
// source.
func TestApplyChanges_OutputDirMirrorsTheScannedTree(t *testing.T) {
	baseDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(baseDir, "k8s", "prod"), 0750))
	source := writeManifest(t, filepath.Join(baseDir, "k8s", "prod"), "pods.yaml", twoPods)
	outputDir := filepath.Join(t.TempDir(), "fixed")

	h := outputDirHandler(baseDir, outputDir)
	count, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(source, "k8s/prod/pods.yaml", 1)})

	require.Empty(t, errs)
	assert.Equal(t, 1, count)

	fixedCopy, err := os.ReadFile(filepath.Join(outputDir, "k8s", "prod", "pods.yaml"))
	require.NoError(t, err, "the copy must mirror the source's relative path")
	assert.Contains(t, string(fixedCopy), "name: first", "the unfixed document must be carried into the copy")
	assert.Contains(t, string(fixedCopy), "name: second")
	assert.Contains(t, string(fixedCopy), "image: nginx:1.25", "the copy must carry the fix")

	unchanged, err := os.ReadFile(source)
	require.NoError(t, err)
	assert.Equal(t, twoPods, string(unchanged), "the source must not be modified")
}

// TestApplyChanges_OutputDirCopyKeepsTheSourcePermissions: the copy is the same
// manifest, so a fixed copy of a private file must not come out more readable
// than the original.
func TestApplyChanges_OutputDirCopyKeepsTheSourcePermissions(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("permission bits are not meaningful on Windows")
	}

	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods) // written 0600
	outputDir := filepath.Join(t.TempDir(), "fixed")

	h := outputDirHandler(baseDir, outputDir)
	_, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})
	require.Empty(t, errs)

	info, err := os.Stat(filepath.Join(outputDir, "pod.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestOutputPaths_Refusals pins the plans OutputPaths must refuse before
// anything is written, each because it could not do what --output-dir promises.
func TestOutputPaths_Refusals(t *testing.T) {
	baseDir := t.TempDir()
	otherDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	sameNameElsewhere := writeManifest(t, otherDir, "pod.yaml", twoPods)

	tests := []struct {
		name      string
		outputDir string
		resources []ResourceFixInfo
		wantErr   string
	}{
		{
			// The relative path is report input. The source side already
			// containment-checks it against the scanned directory; the output
			// side has to hold the same line against the output directory.
			name:      "relative path that climbs out of the output directory",
			outputDir: filepath.Join(t.TempDir(), "fixed"),
			resources: []ResourceFixInfo{imageFix(source, "../../escaped.yaml", 0)},
			wantErr:   "outside the output directory",
		},
		{
			// Output directory == scanned directory: every copy lands on its
			// own source, which is an in-place fix under another name.
			name:      "output directory is the scanned directory",
			outputDir: baseDir,
			resources: []ResourceFixInfo{imageFix(source, "pod.yaml", 0)},
			wantErr:   "would overwrite",
		},
		{
			// The inputs of a multi-input scan each resolve against their own
			// root, so two of them can record the same relative path. One copy
			// would silently replace the other.
			name:      "two sources map to the same destination",
			outputDir: filepath.Join(t.TempDir(), "fixed"),
			resources: []ResourceFixInfo{imageFix(source, "pod.yaml", 0), imageFix(sameNameElsewhere, "pod.yaml", 0)},
			wantErr:   "would both be written to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := outputDirHandler(baseDir, tt.outputDir)

			_, err := h.OutputPaths(tt.resources)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)

			// ApplyChanges has to refuse the same plans with nothing written:
			// it is the only caller that can write, and it must not depend on
			// its own caller having asked OutputPaths first.
			count, errs := h.ApplyChanges(context.Background(), tt.resources)
			assert.Equal(t, 0, count)
			require.Len(t, errs, 1)
			assert.Contains(t, errs[0].Error(), tt.wantErr)
			for _, source := range []string{source, sameNameElsewhere} {
				unchanged, readErr := os.ReadFile(source)
				require.NoError(t, readErr)
				assert.Equal(t, twoPods, string(unchanged), "a refused plan must not modify any source")
			}
		})
	}
}

// TestOutputPaths_PlansOneDestinationPerFile: resources that share a manifest
// share its copy, and a resource with no recorded relative path falls back to
// the manifest's base name rather than being dropped.
func TestOutputPaths_PlansOneDestinationPerFile(t *testing.T) {
	baseDir := t.TempDir()
	shared := writeManifest(t, baseDir, "pods.yaml", twoPods)
	noRelativePath := writeManifest(t, baseDir, "other.yaml", twoPods)
	outputDir := filepath.Join(t.TempDir(), "fixed")

	h := outputDirHandler(baseDir, outputDir)
	paths, err := h.OutputPaths([]ResourceFixInfo{
		imageFix(shared, "pods.yaml", 0),
		imageFix(shared, "pods.yaml", 1),
		imageFix(noRelativePath, "", 0),
		{inMemory: true},
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		shared:         filepath.Join(outputDir, "pods.yaml"),
		noRelativePath: filepath.Join(outputDir, "other.yaml"),
	}, paths)
}
