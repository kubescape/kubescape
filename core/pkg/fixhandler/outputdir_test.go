package fixhandler

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
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

// TestApplyChanges_OutputDirRefusesASymlinkThatLeavesTheDirectory: the relative
// path is report input and --no-confirm lets the output directory already have
// content, so a symlink below it could carry a write somewhere else. "sub/x"
// passes OutputPaths' lexical check, and only resolving it shows where it goes.
func TestApplyChanges_OutputDirRefusesASymlinkThatLeavesTheDirectory(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	outputDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(outputDir, "sub")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	h := outputDirHandler(baseDir, outputDir)
	count, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(source, "sub/pod.yaml", 0)})

	assert.Equal(t, 0, count)
	require.Len(t, errs, 1)
	assert.NoFileExists(t, filepath.Join(outside, "pod.yaml"), "nothing may be written outside the output directory")
}

// TestApplyChanges_OutputDirRefusesADestinationItAlreadyWrote: two destinations
// that OutputPaths sees as different paths can still be one file. A link in the
// directory stands in here for the case-insensitive filesystem where Pod.yaml
// and pod.yaml are the same file. Whichever is written second must be refused
// rather than truncate the first.
func TestApplyChanges_OutputDirRefusesADestinationItAlreadyWrote(t *testing.T) {
	baseDir := t.TempDir()
	otherDir := t.TempDir()
	first := writeManifest(t, baseDir, "a.yaml", twoPods)
	second := writeManifest(t, otherDir, "b.yaml", twoPods)
	outputDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outputDir, "a.yaml"), nil, 0600))
	if err := os.Symlink("a.yaml", filepath.Join(outputDir, "b.yaml")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	h := outputDirHandler(baseDir, outputDir)
	count, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(first, "a.yaml", 0), imageFix(second, "b.yaml", 0)})

	assert.Equal(t, 1, count, "one of the two must be written")
	require.Len(t, errs, 1, "and the other refused")
	assert.Contains(t, errs[0].Error(), "already written")
}

// TestApplyChanges_OutputDirTightensAnExistingDestination: the mode passed to
// OpenFile only applies to a file it creates. An existing, more readable
// destination must not keep its mode once it holds a private manifest.
func TestApplyChanges_OutputDirTightensAnExistingDestination(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("permission bits are not meaningful on Windows")
	}

	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods) // written 0600
	outputDir := t.TempDir()
	existing := filepath.Join(outputDir, "pod.yaml")
	require.NoError(t, os.WriteFile(existing, []byte("stale"), 0600))
	require.NoError(t, os.Chmod(existing, 0644)) // wider than the 0600 source

	h := outputDirHandler(baseDir, outputDir)
	_, errs := h.ApplyChanges(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})
	require.Empty(t, errs)

	info, err := os.Stat(existing)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// --- multi-input scans (#4042) --------------------------------------------

// podManifest is a single Pod whose image fixImage pins.
func podManifest(name string) string {
	return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\nspec:\n  containers:\n  - name: c\n    image: nginx\n"
}

// fixImage is a failed control whose fix pins the Pod's image.
func fixImage() resourcesresults.ResourceAssociatedControl {
	return failedControl("C-0057", "Privileged", failedRuleWithFix("spec.containers[0].image", "nginx:1.25"))
}

// manifestInput is one manifest of a test report: the root the scan read it
// from and its path relative to that root.
type manifestInput struct {
	root, relativePath, name string
	resources                int // resources the file declares; 0 means 1
}

// reportOf builds a handler over a report shaped like the ones the scanner
// writes: every manifest's root is on its resources[] entry, results carry no
// raw resource, and the report-wide base path is the first root only, as a
// multi-input scan records it.
func reportOf(t *testing.T, inputs []manifestInput) *FixHandler {
	t.Helper()
	var resources []reporthandling.Resource
	var results []resourcesresults.Result
	for _, in := range inputs {
		count := in.resources
		if count == 0 {
			count = 1
		}
		for i := 0; i < count; i++ {
			resource := buildResource(t, in.root, filepath.ToSlash(in.relativePath), "Pod", in.name+strconv.Itoa(i), 0)
			resources = append(resources, *resource)
			results = append(results, resourcesresults.Result{
				ResourceID:         resource.GetID(),
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{fixImage()},
			})
		}
	}
	return newHandlerForResources(inputs[0].root, results, resources, false)
}

// twoInputsOutsideGit lays out the case from #4042: two scan inputs outside a
// git repository, so each is its own root, both holding a deploy.yaml.
func twoInputsOutsideGit(t *testing.T) (root string, inputs []manifestInput) {
	t.Helper()
	root = t.TempDir()
	for _, in := range []struct{ dir, name string }{{"apps/web/k8s", "web"}, {"infra/db/k8s", "db"}} {
		dir := filepath.Join(root, filepath.FromSlash(in.dir))
		require.NoError(t, os.MkdirAll(dir, 0750))
		writeManifest(t, dir, "deploy.yaml", podManifest(in.name))
		inputs = append(inputs, manifestInput{root: dir, relativePath: "deploy.yaml", name: in.name})
	}
	return root, inputs
}

// TestMultiInputScan_FixesSameNamedFilesInPlace is the root cause of #4042.
// Each input records its file as "deploy.yaml", so counting resources per file
// by the recorded path saw one file declaring two resources, read that as a
// kind: List wrapper and skipped both. Nothing about it was specific to
// --output-dir: plain in-place fixing of the scan fixed nothing either.
func TestMultiInputScan_FixesSameNamedFilesInPlace(t *testing.T) {
	root, inputs := twoInputsOutsideGit(t)
	h := reportOf(t, inputs)

	planned := h.PrepareResourcesToFix(context.Background())
	require.Len(t, planned, 2, "two files that share a relative path are still two files: %+v", h.UnfixedControls())

	count, errs := h.ApplyChanges(context.Background(), planned)
	require.Empty(t, errs)
	assert.Equal(t, 2, count)
	for _, dir := range []string{"apps/web/k8s", "infra/db/k8s"} {
		fixed, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir), "deploy.yaml"))
		require.NoError(t, err)
		assert.Contains(t, string(fixed), "image: nginx:1.25", dir)
	}
}

// TestMultiInputScan_KeepsTheWrappedManifestGuard: keying the per-file count
// by the real file must not weaken the guard it feeds. A genuine kind: List in
// one input is still skipped while a same-named plain manifest in the other is
// fixed.
func TestMultiInputScan_KeepsTheWrappedManifestGuard(t *testing.T) {
	root := t.TempDir()
	listDir := filepath.Join(root, "apps", "web", "k8s")
	plainDir := filepath.Join(root, "infra", "db", "k8s")
	require.NoError(t, os.MkdirAll(listDir, 0750))
	require.NoError(t, os.MkdirAll(plainDir, 0750))
	list := writeManifest(t, listDir, "deploy.yaml", "apiVersion: v1\nkind: List\nitems:\n- kind: Pod\n- kind: Pod\n")
	writeManifest(t, plainDir, "deploy.yaml", podManifest("db"))

	h := reportOf(t, []manifestInput{
		{root: listDir, relativePath: "deploy.yaml", name: "web", resources: 2},
		{root: plainDir, relativePath: "deploy.yaml", name: "db"},
	})

	planned := h.PrepareResourcesToFix(context.Background())
	require.Len(t, planned, 1)
	assert.Equal(t, filepath.Join(plainDir, "deploy.yaml"), planned[0].FilePath)
	require.Len(t, h.UnfixedControls(), 2)
	for _, unfixed := range h.UnfixedControls() {
		assert.Contains(t, unfixed.Reason, "several resources in one document")
	}

	_, errs := h.ApplyChanges(context.Background(), planned)
	require.Empty(t, errs)
	untouched, err := os.ReadFile(list)
	require.NoError(t, err)
	assert.NotContains(t, string(untouched), "nginx:1.25", "the List must not be edited")
}

// TestOutputPaths_MultiInputRecreatesTheTree: each root's recorded paths start
// afresh, so with several roots a copy keeps its path below the directory they
// share. Both deploy.yaml files get their own place, the same tree a scan of
// the same inputs inside a git repository produces.
func TestOutputPaths_MultiInputRecreatesTheTree(t *testing.T) {
	root, inputs := twoInputsOutsideGit(t)
	outputDir := filepath.Join(t.TempDir(), "fixed")
	h := reportOf(t, inputs)
	h.fixInfo.OutputDir = outputDir

	planned := h.PrepareResourcesToFix(context.Background())
	count, errs := h.ApplyChanges(context.Background(), planned)
	require.Empty(t, errs)
	assert.Equal(t, 2, count)

	for _, dir := range []string{"apps/web/k8s", "infra/db/k8s"} {
		fixedCopy, err := os.ReadFile(filepath.Join(outputDir, filepath.FromSlash(dir), "deploy.yaml"))
		require.NoError(t, err, "the copy must recreate the tree below the inputs' shared directory")
		assert.Contains(t, string(fixedCopy), "image: nginx:1.25")

		original, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dir), "deploy.yaml"))
		require.NoError(t, err)
		assert.NotContains(t, string(original), "nginx:1.25", "the source must not be modified")
	}
}

// TestOutputPaths_LayoutFollowsTheScanNotTheFixes: where a copy lands depends
// on what was scanned, not on which files happen to need a fix. Derived from
// the files being written, a run that fixed only one input's file — a
// --include-controls selection, or the other input having been fixed since —
// would see a single root and write fixed/deploy.yaml where the same scan put
// fixed/apps/web/k8s/deploy.yaml the run before.
func TestOutputPaths_LayoutFollowsTheScanNotTheFixes(t *testing.T) {
	_, inputs := twoInputsOutsideGit(t)
	outputDir := filepath.Join(t.TempDir(), "fixed")
	h := reportOf(t, inputs)
	h.fixInfo.OutputDir = outputDir

	planned := h.PrepareResourcesToFix(context.Background())
	require.Len(t, planned, 2)
	var webOnly []ResourceFixInfo
	for _, rfi := range planned {
		if filepath.Dir(rfi.FilePath) == inputs[0].root {
			webOnly = append(webOnly, rfi)
		}
	}
	require.Len(t, webOnly, 1)

	paths, err := h.OutputPaths(webOnly)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(outputDir, "apps", "web", "k8s", "deploy.yaml"), paths[webOnly[0].FilePath])
}

// TestOutputPaths_SingleRootKeepsTheRecordedPaths: a scan with one root
// already records a tree, and its layout must not change. Inside a git
// repository that root is the repository however many inputs were scanned, and
// the recorded paths start there.
func TestOutputPaths_SingleRootKeepsTheRecordedPaths(t *testing.T) {
	repo := t.TempDir()
	for _, dir := range []string{"apps/web/k8s", "infra/db/k8s"} {
		require.NoError(t, os.MkdirAll(filepath.Join(repo, filepath.FromSlash(dir)), 0750))
		writeManifest(t, filepath.Join(repo, filepath.FromSlash(dir)), "deploy.yaml", podManifest("x"))
	}
	outputDir := filepath.Join(t.TempDir(), "fixed")
	h := reportOf(t, []manifestInput{
		{root: repo, relativePath: "apps/web/k8s/deploy.yaml", name: "web"},
		{root: repo, relativePath: "infra/db/k8s/deploy.yaml", name: "db"},
	})
	h.fixInfo.OutputDir = outputDir

	paths, err := h.OutputPaths(h.PrepareResourcesToFix(context.Background()))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		filepath.Join(outputDir, "apps", "web", "k8s", "deploy.yaml"),
		filepath.Join(outputDir, "infra", "db", "k8s", "deploy.yaml"),
	}, mapValues(paths))
}

// TestOutputPaths_IgnoresARootBasePathRejected: a report records each
// manifest's root itself, and --base-path exists for reports that are not
// trusted to. A root it rejects is not where the file is read from — that falls
// back to the report-wide path — so it must not shape the output tree either.
// Taken from the report as-is, it would have been a second root, and every
// copy would be nested below whatever directory it shares with the real one.
func TestOutputPaths_IgnoresARootBasePathRejected(t *testing.T) {
	trusted := t.TempDir()
	scanned := filepath.Join(trusted, "k8s")
	require.NoError(t, os.MkdirAll(scanned, 0750))
	writeManifest(t, scanned, "deploy.yaml", podManifest("web"))
	writeManifest(t, scanned, "other.yaml", podManifest("db"))
	outputDir := filepath.Join(t.TempDir(), "fixed")

	h := reportOf(t, []manifestInput{
		{root: scanned, relativePath: "deploy.yaml", name: "web"},
		{root: t.TempDir(), relativePath: "other.yaml", name: "db"}, // claims a root outside --base-path
	})
	h.fixInfo.BasePath = trusted
	h.fixInfo.OutputDir = outputDir

	planned := h.PrepareResourcesToFix(context.Background())
	require.Len(t, planned, 2)
	paths, err := h.OutputPaths(planned)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		filepath.Join(outputDir, "deploy.yaml"),
		filepath.Join(outputDir, "other.yaml"),
	}, mapValues(paths))
}

func mapValues(m map[string]string) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}
