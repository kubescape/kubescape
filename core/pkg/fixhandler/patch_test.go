package fixhandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// patchHandler is a handler that exports to a patch file.
func patchHandler(baseDir, reportFile string) *FixHandler {
	return &FixHandler{
		fixInfo:       &metav1.FixInfo{OutputPatch: "remediation.patch", ReportFile: reportFile},
		reportObj:     &reporthandlingv2.PostureReport{},
		localBasePath: baseDir,
	}
}

// applyPatchTo applies patch with git inside a copy of the given files and
// returns the copy's directory.
func applyPatchTo(t *testing.T, files map[string]string, patch string) string {
	t.Helper()
	requireTool(t, "git")
	dir := t.TempDir()
	for name, content := range files {
		target := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
		require.NoError(t, os.WriteFile(target, []byte(content), 0o600))
	}
	applyWithGit(t, dir, patch)
	return dir
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestBuildPatch_OneManifest(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	h := patchHandler(baseDir, "")

	result, err := h.BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})

	require.NoError(t, err)
	assert.Equal(t, 1, result.Files)
	assert.Equal(t, 1, result.Resources)
	assert.True(t, strings.HasPrefix(result.Patch, "diff --git a/pod.yaml b/pod.yaml\n--- a/pod.yaml\n+++ b/pod.yaml\n"), result.Patch)
	assert.Contains(t, result.Patch, "-    image: nginx\n+    image: nginx:1.25\n")

	patched := applyPatchTo(t, map[string]string{"pod.yaml": twoPods}, result.Patch)
	assert.Contains(t, readText(t, filepath.Join(patched, "pod.yaml")), "image: nginx:1.25")
}

// TestBuildPatch_AppliedPatchEqualsTheFixedCopy is the check that the patch is
// not a second fixer: applying it to a clean copy must give byte for byte what
// --output-dir writes for the same fixes.
func TestBuildPatch_AppliedPatchEqualsTheFixedCopy(t *testing.T) {
	baseDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(baseDir, "k8s"), 0o750))
	first := writeManifest(t, baseDir, "pods.yaml", twoPods)
	second := writeManifest(t, filepath.Join(baseDir, "k8s"), "more.yaml", twoPods)
	fixes := []ResourceFixInfo{
		imageFix(first, "pods.yaml", 0),
		imageFix(first, "pods.yaml", 1),
		imageFix(second, "k8s/more.yaml", 1),
	}

	outputDir := filepath.Join(t.TempDir(), "fixed")
	copies := outputDirHandler(baseDir, outputDir)
	_, errs := copies.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), fixes)
	require.NoError(t, err)
	require.Equal(t, 2, result.Files)
	require.Equal(t, 3, result.Resources)

	patched := applyPatchTo(t, map[string]string{"pods.yaml": twoPods, "k8s/more.yaml": twoPods}, result.Patch)
	for _, name := range []string{"pods.yaml", "k8s/more.yaml"} {
		assert.Equal(t, readText(t, filepath.Join(outputDir, filepath.FromSlash(name))), readText(t, filepath.Join(patched, filepath.FromSlash(name))), name)
	}
}

func TestBuildPatch_MultipleFilesAreSortedByPath(t *testing.T) {
	baseDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(baseDir, "b"), 0o750))
	zeta := writeManifest(t, baseDir, "zeta.yaml", twoPods)
	nested := writeManifest(t, filepath.Join(baseDir, "b"), "pods.yaml", twoPods)
	alpha := writeManifest(t, baseDir, "alpha.yaml", twoPods)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{
		imageFix(zeta, "zeta.yaml", 0), imageFix(nested, "b/pods.yaml", 0), imageFix(alpha, "alpha.yaml", 0),
	})

	require.NoError(t, err)
	var order []string
	for _, line := range strings.Split(result.Patch, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			order = append(order, line)
		}
	}
	assert.Equal(t, []string{
		"diff --git a/alpha.yaml b/alpha.yaml",
		"diff --git a/b/pods.yaml b/b/pods.yaml",
		"diff --git a/zeta.yaml b/zeta.yaml",
	}, order, "the same fixes must always give the same patch")
}

// TestBuildPatch_OnlyTheFixedDocumentChanges: a multi-document file stays one
// section, and the documents that are not fixed are not part of any change.
func TestBuildPatch_OnlyTheFixedDocumentChanges(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pods.yaml", twoPods)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pods.yaml", 1)})

	require.NoError(t, err)
	assert.Equal(t, 1, result.Files)
	var changed []string
	for _, line := range strings.Split(result.Patch, "\n") {
		if (strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+")) && !strings.HasPrefix(line, "---") && !strings.HasPrefix(line, "+++") {
			changed = append(changed, line)
		}
	}
	require.Len(t, changed, 2, "one line out, one line in: %v", changed)
	assert.Equal(t, "-    image: nginx", changed[0])
	assert.Equal(t, "+    image: nginx:1.25", changed[1])

	patched := applyPatchTo(t, map[string]string{"pods.yaml": twoPods}, result.Patch)
	got := readText(t, filepath.Join(patched, "pods.yaml"))
	assert.Equal(t, 1, strings.Count(got, "nginx:1.25"), "only the second pod is fixed")
	assert.Contains(t, got, "name: first")
}

func TestBuildPatch_KeepsCommentsAndFormatting(t *testing.T) {
	const manifest = "# Managed by the platform team.\n" +
		"apiVersion: v1\n" +
		"kind: Pod\n" +
		"metadata:\n" +
		"  name:   first   # keep the odd spacing\n" +
		"  labels: {app: web,   tier: front}\n" +
		"spec:\n" +
		"  containers:\n" +
		"  - name: c\n" +
		"    # pinned by the fix\n" +
		"    image: nginx   # trailing comment\n" +
		"    args: [\"a\",   'b']\n"
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", manifest)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})

	require.NoError(t, err)
	var removed, added int
	for _, line := range strings.Split(result.Patch, "\n") {
		switch {
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			removed++
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			added++
		}
	}
	assert.Equal(t, 1, removed, "only the image line may change:\n%s", result.Patch)
	assert.Equal(t, 1, added, result.Patch)

	patched := readText(t, filepath.Join(applyPatchTo(t, map[string]string{"pod.yaml": manifest}, result.Patch), "pod.yaml"))
	for _, kept := range []string{"# Managed by the platform team.", "name:   first   # keep the odd spacing", "{app: web,   tier: front}", "# pinned by the fix", "args: [\"a\",   'b']"} {
		assert.Contains(t, patched, kept)
	}
}

func TestBuildPatch_JSONManifest(t *testing.T) {
	const manifest = "{\n  \"apiVersion\": \"v1\",\n  \"kind\": \"Pod\",\n  \"metadata\": {\"name\": \"first\"},\n  \"spec\": {\"containers\": [{\"name\": \"c\", \"image\": \"nginx\"}]}\n}\n"
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.json", manifest)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.json", 0)})

	require.NoError(t, err)
	require.Equal(t, 1, result.Files)
	patched := readText(t, filepath.Join(applyPatchTo(t, map[string]string{"pod.json": manifest}, result.Patch), "pod.json"))
	assert.Contains(t, patched, "nginx:1.25")
	assert.True(t, strings.HasPrefix(strings.TrimSpace(patched), "{"), "a JSON manifest stays JSON:\n%s", patched)
}

func TestBuildPatch_NoChangeIsNotInThePatch(t *testing.T) {
	baseDir := t.TempDir()
	changing := writeManifest(t, baseDir, "changing.yaml", twoPods)
	fixed := strings.ReplaceAll(twoPods, "image: nginx\n", "image: nginx:1.25\n")
	alreadyFixed := writeManifest(t, baseDir, "fixed.yaml", fixed)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{
		imageFix(changing, "changing.yaml", 0), imageFix(alreadyFixed, "fixed.yaml", 0),
	})

	require.NoError(t, err)
	assert.Equal(t, 1, result.Files, "a manifest the fix leaves as it is has no section")
	assert.Equal(t, 1, result.Resources)
	assert.NotContains(t, result.Patch, "fixed.yaml")
}

func TestBuildPatch_NothingToChangeGivesAnEmptyPatch(t *testing.T) {
	baseDir := t.TempDir()
	fixed := strings.ReplaceAll(twoPods, "image: nginx\n", "image: nginx:1.25\n")
	source := writeManifest(t, baseDir, "pods.yaml", fixed)

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pods.yaml", 0)})

	require.NoError(t, err)
	assert.Empty(t, result.Patch)
	assert.Zero(t, result.Files)

	empty, err := patchHandler(baseDir, "").BuildPatch(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, empty.Patch)
}

// TestBuildPatch_NeverModifiesTheManifests: exporting must not apply anything.
func TestBuildPatch_NeverModifiesTheManifests(t *testing.T) {
	baseDir := t.TempDir()
	first := writeManifest(t, baseDir, "a.yaml", twoPods)
	second := writeManifest(t, baseDir, "b.yaml", twoPods)
	infoBefore, err := os.Stat(first)
	require.NoError(t, err)

	_, err = patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(first, "a.yaml", 0), imageFix(second, "b.yaml", 1)})
	require.NoError(t, err)

	assert.Equal(t, twoPods, readText(t, first))
	assert.Equal(t, twoPods, readText(t, second))
	infoAfter, err := os.Stat(first)
	require.NoError(t, err)
	assert.Equal(t, infoBefore.ModTime(), infoAfter.ModTime(), "the manifest must not even be rewritten with the same content")
	entries, err := os.ReadDir(baseDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "no file may be left beside the manifests")
}

func TestBuildPatch_ReadOnlyManifestIsFine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	require.NoError(t, os.Chmod(source, 0o400))

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})

	require.NoError(t, err, "a patch only reads the manifest, which an in-place fix could not do here")
	assert.Equal(t, 1, result.Files)
}

func TestBuildPatch_AllOrNothingWhenAManifestFails(t *testing.T) {
	baseDir := t.TempDir()
	good := writeManifest(t, baseDir, "good.yaml", twoPods)
	missing := filepath.Join(baseDir, "missing.yaml")

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(good, "good.yaml", 0), imageFix(missing, "missing.yaml", 0)})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing.yaml")
	assert.Nil(t, result, "a patch that left a file out would read as complete")
}

func TestBuildPatch_NotARegularFile(t *testing.T) {
	baseDir := t.TempDir()
	dir := filepath.Join(baseDir, "dir.yaml")
	require.NoError(t, os.Mkdir(dir, 0o750))

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(dir, "dir.yaml", 0)})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestNotRegular)
	assert.Nil(t, result)
}

func TestBuildPatch_OversizedManifestRejected(t *testing.T) {
	t.Setenv(cautils.MaxFileSizeEnvVar, "")
	baseDir := t.TempDir()
	source := filepath.Join(baseDir, "pod.yaml")
	f, err := os.OpenFile(source, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(cautils.DefaultMaxFileSize+1))
	require.NoError(t, f.Close())

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestTooLarge)
	assert.Nil(t, result)
}

func TestBuildPatch_MaxFileSizeEnvVar(t *testing.T) {
	t.Run("lower override rejects manifest", func(t *testing.T) {
		t.Setenv(cautils.MaxFileSizeEnvVar, "100")
		baseDir := t.TempDir()
		source := writeManifest(t, baseDir, "pod.yaml", twoPods)
		result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrManifestTooLarge)
		assert.Nil(t, result)
	})

	t.Run("higher override permits manifest", func(t *testing.T) {
		t.Setenv(cautils.MaxFileSizeEnvVar, "10000")
		baseDir := t.TempDir()
		source := writeManifest(t, baseDir, "pod.yaml", twoPods)
		result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestBuildPatch_Cancelled(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := patchHandler(baseDir, "").BuildPatch(ctx, []ResourceFixInfo{imageFix(source, "pod.yaml", 0)})

	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, result)
}

func TestBuildPatch_RefusedPlans(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	otherDir := t.TempDir()
	other := writeManifest(t, otherDir, "pod.yaml", twoPods)

	tests := []struct {
		name      string
		resources []ResourceFixInfo
		wantErr   string
	}{
		{"a relative path that climbs out of the patch's root", []ResourceFixInfo{imageFix(source, "../../escaped.yaml", 0)}, "outside the scanned directory"},
		{"an absolute relative path", []ResourceFixInfo{imageFix(source, source, 0)}, "outside the scanned directory"},
		{"two manifests with the same path", []ResourceFixInfo{imageFix(source, "pod.yaml", 0), imageFix(other, "pod.yaml", 0)}, "would both appear in the patch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), tt.resources)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Nil(t, result)
		})
	}
}

func TestBuildPatch_InMemoryResourcesAreNotPatched(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	live := imageFix(source, "pod.yaml", 0)
	live.inMemory = true

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{live})

	require.NoError(t, err)
	assert.Empty(t, result.Patch, "a cluster object has no manifest to patch")
}

func TestBuildPatch_LargeManifest(t *testing.T) {
	var manifest strings.Builder
	for i := 0; i < 400; i++ {
		if i > 0 {
			manifest.WriteString("---\n")
		}
		fmt.Fprintf(&manifest, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\nspec:\n  containers:\n  - name: c\n    image: nginx\n", i)
	}
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "big.yaml", manifest.String())
	// The stale-manifest guard checks the document against the resource the
	// report names, so the fix must name pod-300 and not the first pod.
	fix := imageFix(source, "big.yaml", 300)
	fix.Resource = podResource("pod-300")

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), []ResourceFixInfo{fix})

	require.NoError(t, err)
	assert.Less(t, len(result.Patch), 1024, "one changed line in %d must stay a small patch", strings.Count(manifest.String(), "\n"))
	patched := readText(t, filepath.Join(applyPatchTo(t, map[string]string{"big.yaml": manifest.String()}, result.Patch), "big.yaml"))
	assert.Equal(t, 1, strings.Count(patched, "nginx:1.25"))
}

func TestCheckPatchDestination(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	report := writeManifest(t, baseDir, "report.json", "{}")
	existing := writeManifest(t, t.TempDir(), "old.patch", "old patch")
	fixes := []ResourceFixInfo{imageFix(source, "pod.yaml", 0)}
	h := patchHandler(baseDir, report)

	t.Run("a new file in an existing directory", func(t *testing.T) {
		assert.NoError(t, h.CheckPatchDestination(filepath.Join(t.TempDir(), "new.patch"), fixes, false))
	})
	t.Run("a missing directory", func(t *testing.T) {
		err := h.CheckPatchDestination(filepath.Join(t.TempDir(), "missing", "new.patch"), fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot write the patch")
	})
	t.Run("a parent that is a file", func(t *testing.T) {
		err := h.CheckPatchDestination(filepath.Join(source, "new.patch"), fixes, true)
		require.Error(t, err)
	})
	t.Run("a directory", func(t *testing.T) {
		err := h.CheckPatchDestination(t.TempDir(), fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is a directory")
	})
	t.Run("an existing file is refused without --no-confirm", func(t *testing.T) {
		err := h.CheckPatchDestination(existing, fixes, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Contains(t, err.Error(), "--no-confirm")
	})
	t.Run("an existing file is replaced with --no-confirm", func(t *testing.T) {
		assert.NoError(t, h.CheckPatchDestination(existing, fixes, true))
	})
	t.Run("a scanned manifest is refused even with --no-confirm", func(t *testing.T) {
		err := h.CheckPatchDestination(source, fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scanned manifest")
	})
	t.Run("the report is refused even with --no-confirm", func(t *testing.T) {
		err := h.CheckPatchDestination(report, fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the report")
	})
	t.Run("a hard link to a scanned manifest is refused", func(t *testing.T) {
		link := filepath.Join(baseDir, "hardlink.patch")
		if err := os.Link(source, link); err != nil {
			t.Skipf("cannot create a hard link here: %v", err)
		}
		err := h.CheckPatchDestination(link, fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scanned manifest")
	})
	t.Run("a link to a scanned manifest is refused", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link.patch")
		if err := os.Symlink(source, link); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}
		err := h.CheckPatchDestination(link, fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scanned manifest")
	})
}

func TestWritePatch(t *testing.T) {
	t.Run("writes the whole patch, readable by its owner only", func(t *testing.T) {
		destination := filepath.Join(t.TempDir(), "remediation.patch")

		require.NoError(t, WritePatch(destination, "the patch\n"))

		assert.Equal(t, "the patch\n", readText(t, destination))
		if runtime.GOOS != "windows" {
			info, err := os.Stat(destination)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
		entries, err := os.ReadDir(filepath.Dir(destination))
		require.NoError(t, err)
		assert.Len(t, entries, 1, "no temporary file may be left behind")
	})

	t.Run("replaces an existing file whole", func(t *testing.T) {
		destination := writeManifest(t, t.TempDir(), "remediation.patch", strings.Repeat("old content\n", 100))

		require.NoError(t, WritePatch(destination, "new\n"))

		assert.Equal(t, "new\n", readText(t, destination))
	})

	t.Run("leaves nothing when the directory is missing", func(t *testing.T) {
		parent := t.TempDir()

		err := WritePatch(filepath.Join(parent, "missing", "remediation.patch"), "x")

		require.Error(t, err)
		entries, readErr := os.ReadDir(parent)
		require.NoError(t, readErr)
		assert.Empty(t, entries)
	})

	t.Run("leaves the existing file and no temporary file when the rename fails", func(t *testing.T) {
		parent := t.TempDir()
		destination := filepath.Join(parent, "remediation.patch")
		require.NoError(t, os.Mkdir(destination, 0o750)) // a directory cannot be replaced by a file

		err := WritePatch(destination, "x")

		require.Error(t, err)
		entries, readErr := os.ReadDir(parent)
		require.NoError(t, readErr)
		require.Len(t, entries, 1, "only the directory remains")
		assert.Equal(t, "remediation.patch", entries[0].Name())
	})

	t.Run("a directory that cannot be written to", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("directory permissions are not enforced here")
		}
		parent := t.TempDir()
		require.NoError(t, os.Chmod(parent, 0o500))
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

		err := WritePatch(filepath.Join(parent, "remediation.patch"), "x")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "error writing the patch")
	})
}

// TestBuildPatch_ResourceCount pins what PatchResult.Resources counts: the
// resources whose own fixes change their manifest, each once. Counting the
// planned fixes instead would claim more than the patch carries.
func TestBuildPatch_ResourceCount(t *testing.T) {
	pinned := strings.Replace(twoPods, "image: nginx\n", "image: nginx:1.25\n", 1) // the first pod is already fixed

	tests := []struct {
		name         string
		manifest     string
		fixes        func(source string) []ResourceFixInfo
		wantFiles    int
		wantResource int
	}{
		{
			name:     "one resource",
			manifest: twoPods,
			fixes: func(s string) []ResourceFixInfo {
				return []ResourceFixInfo{imageFix(s, "pods.yaml", 1)}
			},
			wantFiles: 1, wantResource: 1,
		},
		{
			name:     "two resources in one file",
			manifest: twoPods,
			fixes: func(s string) []ResourceFixInfo {
				return []ResourceFixInfo{imageFix(s, "pods.yaml", 0), imageFix(s, "pods.yaml", 1)}
			},
			wantFiles: 1, wantResource: 2,
		},
		{
			// A scan through overlapping roots records one document twice.
			name:     "the same document referenced twice",
			manifest: twoPods,
			fixes: func(s string) []ResourceFixInfo {
				return []ResourceFixInfo{imageFix(s, "pods.yaml", 1), imageFix(s, "pods.yaml", 1)}
			},
			wantFiles: 1, wantResource: 1,
		},
		{
			// The file changes because of the second pod; the first pod's fix
			// has nothing to do, and must not be counted as part of the patch.
			name:     "a resource whose fix changes nothing, in a file that changes",
			manifest: pinned,
			fixes: func(s string) []ResourceFixInfo {
				return []ResourceFixInfo{imageFix(s, "pods.yaml", 0), imageFix(s, "pods.yaml", 1)}
			},
			wantFiles: 1, wantResource: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseDir := t.TempDir()
			source := writeManifest(t, baseDir, "pods.yaml", tt.manifest)

			result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), tt.fixes(source))

			require.NoError(t, err)
			assert.Equal(t, tt.wantFiles, result.Files)
			assert.Equal(t, tt.wantResource, result.Resources)
		})
	}
}

// TestBuildPatch_ResourceCountManyDocuments: counting by trial costs one more
// edit per document of a file that has several, so a file with a great many
// fixable documents must stay quick and count each of them.
func TestBuildPatch_ResourceCountManyDocuments(t *testing.T) {
	for _, documents := range []int{maxResourceTrials, maxResourceTrials + 100} {
		t.Run(fmt.Sprintf("%d documents", documents), func(t *testing.T) {
			testResourceCountDocuments(t, documents)
		})
	}
}

func testResourceCountDocuments(t *testing.T, documents int) {
	t.Helper()
	var manifest strings.Builder
	var fixes []ResourceFixInfo
	baseDir := t.TempDir()
	for i := 0; i < documents; i++ {
		if i > 0 {
			manifest.WriteString("---\n")
		}
		fmt.Fprintf(&manifest, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-%d\nspec:\n  containers:\n  - name: c\n    image: nginx\n", i)
	}
	source := writeManifest(t, baseDir, "many.yaml", manifest.String())
	for i := 0; i < documents; i++ {
		fix := imageFix(source, "many.yaml", i)
		fix.Resource = podResource(fmt.Sprintf("pod-%d", i))
		fix.YamlExpressions = map[string]armotypes.FixPath{
			fmt.Sprintf("select(di==%d).spec.containers[0].image |= \"nginx:1.25\"", i): {Path: "spec.containers[0].image", Value: "nginx:1.25"},
		}
		fixes = append(fixes, fix)
	}

	start := time.Now()
	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), fixes)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, 1, result.Files)
	assert.Equal(t, documents, result.Resources)
	assert.Less(t, elapsed, 20*time.Second, "building the patch took %s", elapsed)
	t.Logf("%d documents fixed in %s", documents, elapsed)
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
}

// TestCheckPatchDestination_SymlinkedParent: a patch path reached through a
// symlinked directory is judged by where it really is, so a link cannot be used
// to name a scanned manifest by another route.
func TestCheckPatchDestination_SymlinkedParent(t *testing.T) {
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pod.yaml", twoPods)
	report := writeManifest(t, baseDir, "report.json", "{}")
	fixes := []ResourceFixInfo{imageFix(source, "pod.yaml", 0)}
	h := patchHandler(baseDir, report)

	intoScanned := filepath.Join(t.TempDir(), "via-link")
	symlinkOrSkip(t, baseDir, intoScanned)
	elsewhere := t.TempDir()
	intoElsewhere := filepath.Join(t.TempDir(), "via-link")
	symlinkOrSkip(t, elsewhere, intoElsewhere)

	t.Run("a link to the scanned directory, naming a manifest, is refused", func(t *testing.T) {
		err := h.CheckPatchDestination(filepath.Join(intoScanned, "pod.yaml"), fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scanned manifest")
	})
	t.Run("a link to the scanned directory, naming the report, is refused", func(t *testing.T) {
		err := h.CheckPatchDestination(filepath.Join(intoScanned, "report.json"), fixes, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the report")
	})
	t.Run("a link to the scanned directory, naming a new file, is allowed", func(t *testing.T) {
		// Nothing is overwritten: the patch is a new file beside the manifests.
		assert.NoError(t, h.CheckPatchDestination(filepath.Join(intoScanned, "remediation.patch"), fixes, false))
	})
	t.Run("a link to another directory is allowed", func(t *testing.T) {
		assert.NoError(t, h.CheckPatchDestination(filepath.Join(intoElsewhere, "remediation.patch"), fixes, false))
	})
	t.Run("a link that leads nowhere is refused", func(t *testing.T) {
		dangling := filepath.Join(t.TempDir(), "dangling")
		symlinkOrSkip(t, filepath.Join(t.TempDir(), "gone"), dangling)

		err := h.CheckPatchDestination(filepath.Join(dangling, "remediation.patch"), fixes, true)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot write the patch")
	})
}

// TestWritePatch_SymlinkedPaths: the writer replaces the name it is given and
// never writes through a link, so a link can redirect where a patch lands but
// not what an existing file holds.
func TestWritePatch_SymlinkedPaths(t *testing.T) {
	t.Run("a symlinked parent receives the file and stays a link", func(t *testing.T) {
		real := t.TempDir()
		link := filepath.Join(t.TempDir(), "via-link")
		symlinkOrSkip(t, real, link)

		require.NoError(t, WritePatch(filepath.Join(link, "remediation.patch"), "the patch\n"))

		assert.Equal(t, "the patch\n", readText(t, filepath.Join(real, "remediation.patch")))
		info, err := os.Lstat(link)
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&os.ModeSymlink, "the link must still be a link")
		entries, err := os.ReadDir(real)
		require.NoError(t, err)
		assert.Len(t, entries, 1, "no temporary file may be left behind")
	})

	t.Run("a symlink as the destination is replaced, not written through", func(t *testing.T) {
		dir := t.TempDir()
		manifest := writeManifest(t, dir, "pod.yaml", twoPods)
		link := filepath.Join(dir, "remediation.patch")
		symlinkOrSkip(t, manifest, link)

		require.NoError(t, WritePatch(link, "the patch\n"))

		assert.Equal(t, twoPods, readText(t, manifest), "the file the link pointed at must be untouched")
		assert.Equal(t, "the patch\n", readText(t, link))
		info, err := os.Lstat(link)
		require.NoError(t, err)
		assert.Zero(t, info.Mode()&os.ModeSymlink, "the name now holds the patch itself")
	})

	t.Run("a hard link as the destination is replaced, not written through", func(t *testing.T) {
		dir := t.TempDir()
		manifest := writeManifest(t, dir, "pod.yaml", twoPods)
		link := filepath.Join(dir, "remediation.patch")
		if err := os.Link(manifest, link); err != nil {
			t.Skipf("cannot create a hard link here: %v", err)
		}

		require.NoError(t, WritePatch(link, "the patch\n"))

		assert.Equal(t, twoPods, readText(t, manifest), "the other name of the same file must be untouched")
		assert.Equal(t, "the patch\n", readText(t, link))
	})
}

// TestBuildPatch_CRLFManifest: a manifest with Windows line endings must come
// out as a patch of the one line the fixer edits, and applying it must leave
// every other line, and every ending, as it was. A fixer that rewrote the file
// with other endings would show as a patch of the whole file.
func TestBuildPatch_CRLFManifest(t *testing.T) {
	crlf := strings.ReplaceAll(twoPods, "\n", "\r\n")
	baseDir := t.TempDir()
	source := writeManifest(t, baseDir, "pods.yaml", crlf)
	fixes := []ResourceFixInfo{imageFix(source, "pods.yaml", 1)}

	result, err := patchHandler(baseDir, "").BuildPatch(context.Background(), fixes)

	require.NoError(t, err)
	require.Equal(t, 1, result.Files)
	var removed, added int
	for _, line := range strings.Split(result.Patch, "\n") {
		switch {
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			removed++
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			added++
		}
	}
	assert.Equal(t, 1, removed, "only the image line may change:\n%q", result.Patch)
	assert.Equal(t, 1, added)

	patched := readText(t, filepath.Join(applyPatchTo(t, map[string]string{"pods.yaml": crlf}, result.Patch), "pods.yaml"))
	assert.Equal(t, strings.Count(patched, "\n"), strings.Count(patched, "\r\n"), "every line must still end with CRLF")
	first, second, _ := strings.Cut(crlf, "---\r\n")
	expected := first + "---\r\n" + strings.Replace(second, "image: nginx\r\n", "image: nginx:1.25\r\n", 1)
	assert.Equal(t, expected, patched, "the second pod's image is the only difference")

	// And the same with patch -p1.
	requireTool(t, "patch")
	viaPatch := roundTrip(t, applyWithPatch, "pods.yaml", crlf, result.Patch)
	assert.Equal(t, patched, viaPatch, "patch and git must produce the same file")
}
