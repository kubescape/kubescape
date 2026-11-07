package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

func TestApplyChanges_RejectsStaleResourceTargets(t *testing.T) {
	const original = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: original, namespace: production}\nspec:\n  replicas: 1\n"
	const originalJSON = "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"name\":\"original\"},\"spec\":{\"replicas\":1}}"
	other := strings.Replace(original, "name: original", "name: other", 1)
	tests := []struct {
		name, extension, scanned, current string
		afterPlanning, outputCopy         bool
	}{
		{name: "inserted YAML document", extension: ".yaml", scanned: original, current: other + "---\n" + original},
		{name: "different namespace", extension: ".yaml", scanned: original, current: strings.Replace(original, "production", "staging", 1)},
		{name: "different kind", extension: ".yaml", scanned: original, current: strings.Replace(original, "Deployment", "StatefulSet", 1)},
		{name: "different API version", extension: ".yaml", scanned: original, current: strings.Replace(original, "apps/v1", "apps/v1beta1", 1)},
		{name: "deleted document after planning", extension: ".yaml", scanned: other + "---\n" + original, current: other, afterPlanning: true},
		{name: "duplicate identity", extension: ".yaml", scanned: original, current: original + "---\n" + original},
		{name: "another fix in the same file", extension: ".yaml", scanned: other + "---\n" + original, current: other + "---\n" + strings.Replace(original, "production", "staging", 1)},
		{name: "edit after planning for output copy", extension: ".yaml", scanned: original, current: other + "---\n" + original, afterPlanning: true, outputCopy: true},
		{name: "replaced JSON resource", extension: ".json", scanned: originalJSON, current: strings.Replace(originalJSON, "original", "other", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			filename := "bundle" + tt.extension
			path := writeManifest(t, dir, filename, tt.scanned)
			loaded, _, err := cautils.LoadResourcesFromFiles(ctx, path, dir, nil)
			require.NoError(t, err)
			require.NotEmpty(t, loaded[path])

			var resources []reporthandling.Resource
			var results []resourcesresults.Result
			fileType := reporthandling.SourceTypeYaml
			if tt.extension == ".json" {
				fileType = reporthandling.SourceTypeJson
			}
			for _, workload := range loaded[path] {
				resource := reporthandling.NewResource(workload.GetObject())
				resource.Source = &reporthandling.Source{Path: dir, RelativePath: filename, FileType: fileType}
				resources = append(resources, *resource)
				results = append(results, resourcesresults.Result{
					ResourceID:         resource.GetID(),
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-1", "replicas", failedRuleWithFix("spec.replicas", "2"))},
				})
			}
			h := newHandlerForResources(dir, results, resources, true)
			if tt.outputCopy {
				h.fixInfo.OutputDir = filepath.Join(t.TempDir(), "fixed")
			}
			if !tt.afterPlanning {
				require.NoError(t, os.WriteFile(path, []byte(tt.current), 0600))
			}
			fixes := h.PrepareResourcesToFix(ctx)
			require.Len(t, fixes, len(resources))
			if tt.afterPlanning {
				require.NoError(t, os.WriteFile(path, []byte(tt.current), 0600))
			}

			count, errs := h.ApplyChanges(ctx, fixes)
			require.Zero(t, count, "the file with a stale fix target must not be counted as fixed")
			require.Len(t, errs, 1)
			require.ErrorContains(t, errs[0], "re-scan")
			require.Equal(t, tt.current, fileContentOf(t, path))
			if tt.outputCopy {
				require.NoFileExists(t, filepath.Join(h.fixInfo.OutputDir, filename))
			}
		})
	}
}
