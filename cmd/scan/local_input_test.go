package scan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scanInputCaptureKubescape struct {
	mocks.MockIKubescape
	scanInfo          *cautils.ScanInfo
	policyIdentifiers []cautils.PolicyIdentifier
	inputContents     []string
}

func (m *scanInputCaptureKubescape) Scan(scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.scanInfo = scanInfo
	m.policyIdentifiers = policyIdentifiers
	for _, inputPattern := range scanInfo.InputPatterns {
		content, err := os.ReadFile(inputPattern)
		if err == nil {
			m.inputContents = append(m.inputContents, string(content))
		}
	}
	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	results.SetData(cautils.NewOPASessionObjMock())
	return results, nil
}

func (m *scanInputCaptureKubescape) Context() context.Context {
	return context.Background()
}

func (m *scanInputCaptureKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return m.Scan(scanInfo, policyIdentifiers)
}

// requireStagedStdinPath checks that path is the stdin manifest staged by
// prepareScanLocalInput: a file named stdin.yaml inside a kubescape-stdin-*
// directory created in the system temp dir.
func requireStagedStdinPath(t *testing.T, path string) {
	t.Helper()
	dir := filepath.Dir(path)
	assert.Equal(t, "stdin.yaml", filepath.Base(path))
	assert.True(t, strings.HasPrefix(filepath.Base(dir), "kubescape-stdin-"), "staging dir %q should be named kubescape-stdin-*", dir)
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(dir))
}

func TestPrepareScanLocalInput(t *testing.T) {
	t.Run("positional inputs populate input patterns", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}

		cleanup, err := prepareScanLocalInput(bytes.NewBufferString(""), []string{"nsa", "manifests/a.yaml", "manifests/b.yaml"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		defer cleanup()

		require.NoError(t, err)
		assert.Equal(t, []string{"manifests/a.yaml", "manifests/b.yaml"}, scanInfo.InputPatterns)
	})

	t.Run("file path fallback populates input patterns", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}

		cleanup, err := prepareScanLocalInput(bytes.NewBufferString(""), []string{"Deployment/nginx"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			FilePath:         "manifests/app.yaml",
			RejectMixedStdin: true,
		})
		defer cleanup()

		require.NoError(t, err)
		assert.Equal(t, []string{"manifests/app.yaml"}, scanInfo.InputPatterns)
	})

	t.Run("stdin input is staged as stdin.yaml in a private temp dir and cleaned up", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}
		stdin := bytes.NewBufferString("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx\n")

		cleanup, err := prepareScanLocalInput(stdin, []string{"nsa", "-"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		require.NoError(t, err)
		require.Len(t, scanInfo.InputPatterns, 1)
		requireStagedStdinPath(t, scanInfo.InputPatterns[0])

		got, err := os.ReadFile(scanInfo.InputPatterns[0])
		require.NoError(t, err)
		assert.Contains(t, string(got), "kind: Pod")

		cleanup()
		_, err = os.Stat(scanInfo.InputPatterns[0])
		assert.True(t, os.IsNotExist(err), "temporary stdin manifest should be removed by cleanup")
		_, err = os.Stat(filepath.Dir(scanInfo.InputPatterns[0]))
		assert.True(t, os.IsNotExist(err), "temporary stdin directory should be removed by cleanup")
	})

	t.Run("two stdin inputs share the file name but not the directory", func(t *testing.T) {
		var first, second cautils.ScanInfo
		opts := scanLocalInputOptions{FirstInputArg: 1, RejectMixedStdin: true}

		cleanupFirst, err := prepareScanLocalInput(bytes.NewBufferString("kind: Pod\n"), []string{"nsa", "-"}, &first, opts)
		require.NoError(t, err)
		defer cleanupFirst()
		cleanupSecond, err := prepareScanLocalInput(bytes.NewBufferString("kind: Service\n"), []string{"nsa", "-"}, &second, opts)
		require.NoError(t, err)
		defer cleanupSecond()

		require.Len(t, first.InputPatterns, 1)
		require.Len(t, second.InputPatterns, 1)
		assert.Equal(t, filepath.Base(first.InputPatterns[0]), filepath.Base(second.InputPatterns[0]))
		assert.NotEqual(t, first.InputPatterns[0], second.InputPatterns[0])

		got, err := os.ReadFile(first.InputPatterns[0])
		require.NoError(t, err)
		assert.Contains(t, string(got), "kind: Pod")
	})

	t.Run("mixed stdin and positional inputs are rejected", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}

		cleanup, err := prepareScanLocalInput(bytes.NewBufferString(""), []string{"nsa", "-", "manifests/app.yaml"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		defer cleanup()

		assert.EqualError(t, err, "usage: stdin input '-' cannot be combined with other input paths")
		assert.Empty(t, scanInfo.InputPatterns)
	})

	t.Run("mixed file path and positional inputs are rejected", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}

		cleanup, err := prepareScanLocalInput(bytes.NewBufferString(""), []string{"nsa", "manifests/app.yaml"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			FilePath:         "manifests/other.yaml",
			RejectMixedStdin: true,
		})
		defer cleanup()

		assert.EqualError(t, err, "usage: use either --file-path or positional input paths, not both")
		assert.Empty(t, scanInfo.InputPatterns)
	})
}

func TestFrameworkCmd_StdinUsesCommandInput(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	ks := &scanInputCaptureKubescape{}
	cmd := getFrameworkCmd(ks, &scanInfo)
	cmd.SetIn(strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata:\n  name: framework-stdin\n"))

	err := cmd.RunE(cmd, []string{"nsa", "-"})

	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	require.Len(t, ks.scanInfo.InputPatterns, 1)
	requireStagedStdinPath(t, ks.scanInfo.InputPatterns[0])
	assert.NoFileExists(t, ks.scanInfo.InputPatterns[0])
	require.Len(t, ks.inputContents, 1)
	assert.Contains(t, ks.inputContents[0], "framework-stdin")
	assert.Equal(t, cautils.ScanTypeFramework, ks.scanInfo.ScanType)
	require.Len(t, ks.policyIdentifiers, 1)
	assert.Equal(t, "nsa", ks.policyIdentifiers[0].Identifier)
}

func TestControlCmd_StdinUsesCommandInput(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	ks := &scanInputCaptureKubescape{}
	cmd := getControlCmd(ks, &scanInfo)
	cmd.SetIn(strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata:\n  name: control-stdin\n"))

	err := cmd.RunE(cmd, []string{"C-0058", "-"})

	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	require.Len(t, ks.scanInfo.InputPatterns, 1)
	requireStagedStdinPath(t, ks.scanInfo.InputPatterns[0])
	assert.NoFileExists(t, ks.scanInfo.InputPatterns[0])
	require.Len(t, ks.inputContents, 1)
	assert.Contains(t, ks.inputContents[0], "control-stdin")
	assert.Equal(t, cautils.ScanTypeControl, ks.scanInfo.ScanType)
	require.Len(t, ks.policyIdentifiers, 1)
	assert.Equal(t, "C-0058", ks.policyIdentifiers[0].Identifier)
}

func TestWorkloadCmd_StdinUsesCommandInput(t *testing.T) {
	scanInfo := cautils.ScanInfo{}
	ks := &scanInputCaptureKubescape{}
	cmd := getWorkloadCmd(ks, &scanInfo)
	cmd.SetIn(strings.NewReader("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\n"))

	err := cmd.RunE(cmd, []string{"Deployment/nginx", "-"})

	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	require.Len(t, ks.scanInfo.InputPatterns, 1)
	requireStagedStdinPath(t, ks.scanInfo.InputPatterns[0])
	assert.NoFileExists(t, ks.scanInfo.InputPatterns[0])
	require.Len(t, ks.inputContents, 1)
	assert.Contains(t, ks.inputContents[0], "nginx")
	assert.Equal(t, cautils.ScanTypeWorkload, ks.scanInfo.ScanType)
	assert.Equal(t, "Deployment", ks.scanInfo.ScanObject.GetKind())
	assert.Equal(t, "nginx", ks.scanInfo.ScanObject.GetName())
}

func TestScanCmd_SecurityView_StdinUsesCommandInput(t *testing.T) {
	ks := &scanInputCaptureKubescape{}
	cmd := GetScanCommand(ks)
	cmd.SetIn(strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata:\n  name: security-view-stdin\n"))
	cmd.SetArgs([]string{"--view", "security", "-"})

	err := cmd.Execute()

	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	require.Len(t, ks.scanInfo.InputPatterns, 1)
	requireStagedStdinPath(t, ks.scanInfo.InputPatterns[0])
	assert.NoFileExists(t, ks.scanInfo.InputPatterns[0])
	require.Len(t, ks.inputContents, 1)
	assert.Contains(t, ks.inputContents[0], "security-view-stdin")
	assert.Equal(t, cautils.ScanTypeRepo, ks.scanInfo.ScanType)
	require.Len(t, ks.policyIdentifiers, 2)
	assert.Equal(t, "workloadscan", ks.policyIdentifiers[0].Identifier)
	assert.Equal(t, "allcontrols", ks.policyIdentifiers[1].Identifier)
}

func TestScanCmd_SecurityView_RejectsStdinMixedWithOtherInputs(t *testing.T) {
	ks := &scanInputCaptureKubescape{}
	cmd := GetScanCommand(ks)
	cmd.SetArgs([]string{"--view", "security", "-", "manifests/app.yaml"})

	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "usage: stdin input '-' cannot be combined with other input paths")
}

func TestScanCmd_SecurityView_FilePathWithoutPositionalInputs(t *testing.T) {
	ks := &scanInputCaptureKubescape{}
	cmd := GetScanCommand(ks)
	cmd.SetArgs([]string{"--view", "security", "--file-path", "manifests/app.yaml"})

	err := cmd.Execute()
	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	assert.Equal(t, []string{"manifests/app.yaml"}, ks.scanInfo.InputPatterns)
	assert.Equal(t, cautils.ScanTypeRepo, ks.scanInfo.ScanType)
	require.Len(t, ks.policyIdentifiers, 2)
	assert.Equal(t, "workloadscan", ks.policyIdentifiers[0].Identifier)
	assert.Equal(t, "allcontrols", ks.policyIdentifiers[1].Identifier)
}

func TestScanCmd_FallbackFramework_FilePathWithoutPositionalInputs(t *testing.T) {
	ks := &scanInputCaptureKubescape{}
	cmd := GetScanCommand(ks)
	cmd.SetArgs([]string{"--view", "resource", "--file-path", "manifests/app.yaml"})

	err := cmd.Execute()
	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo)
	assert.Equal(t, []string{"manifests/app.yaml"}, ks.scanInfo.InputPatterns)
	assert.Equal(t, cautils.ScanTypeFramework, ks.scanInfo.ScanType)
}

func TestPrepareScanLocalInput_StdinSourceNameIsStable(t *testing.T) {
	scanInfo := &cautils.ScanInfo{}
	stdin := strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx\nspec:\n  containers:\n  - name: nginx\n    image: nginx\n")
	cleanup, err := prepareScanLocalInput(stdin, []string{"nsa", "-"}, scanInfo, scanLocalInputOptions{
		FirstInputArg:    1,
		RejectMixedStdin: true,
	})
	require.NoError(t, err)
	defer cleanup()

	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	_, _, _, _, err = resourcehandler.NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)

	// Reports print this source for each finding, so it must not carry the
	// random part of a temporary name.
	require.Len(t, session.ResourceSource, 1)
	for _, source := range session.ResourceSource {
		assert.Equal(t, "stdin.yaml", source.RelativePath)
	}
}

func TestPrepareScanLocalInput_StdinSizeBounds(t *testing.T) {
	t.Run("rejects oversized stdin stream and cleans up staging directory", func(t *testing.T) {
		tmpRoot := t.TempDir()
		t.Setenv("TMPDIR", tmpRoot)
		t.Setenv("TMP", tmpRoot)
		t.Setenv("TEMP", tmpRoot)
		t.Setenv(filesizelimit.MaxFileSizeEnvVar, "1024")

		scanInfo := &cautils.ScanInfo{}
		oversized := bytes.NewReader(bytes.Repeat([]byte("a"), 1025))
		cleanup, err := prepareScanLocalInput(oversized, []string{"nsa", "-"}, scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		defer cleanup()

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStdinTooLarge)
		assert.Empty(t, scanInfo.InputPatterns)

		entries, readErr := os.ReadDir(tmpRoot)
		require.NoError(t, readErr)
		assert.Empty(t, entries, "staging directory must be removed when stdin exceeds limit")
	})

	t.Run("rejects oversized regular file redirected via stdin without staging", func(t *testing.T) {
		tmpRoot := t.TempDir()
		t.Setenv("TMPDIR", tmpRoot)
		t.Setenv("TMP", tmpRoot)
		t.Setenv("TEMP", tmpRoot)
		t.Setenv(filesizelimit.MaxFileSizeEnvVar, "1024")

		srcPath := filepath.Join(t.TempDir(), "oversized.yaml")
		require.NoError(t, os.WriteFile(srcPath, bytes.Repeat([]byte("b"), 1025), 0o600))
		f, err := os.Open(srcPath)
		require.NoError(t, err)
		defer f.Close()

		scanInfo := &cautils.ScanInfo{}
		cleanup, err := prepareScanLocalInput(f, []string{"nsa", "-"}, scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		defer cleanup()

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStdinTooLarge)
		entries, readErr := os.ReadDir(tmpRoot)
		require.NoError(t, readErr)
		assert.Empty(t, entries)
	})

	t.Run("allows stdin matching exact size limit", func(t *testing.T) {
		t.Setenv(filesizelimit.MaxFileSizeEnvVar, "1024")

		payload := bytes.Repeat([]byte("c"), 1024)
		scanInfo := &cautils.ScanInfo{}
		cleanup, err := prepareScanLocalInput(bytes.NewReader(payload), []string{"nsa", "-"}, scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		require.NoError(t, err)
		defer cleanup()

		require.Len(t, scanInfo.InputPatterns, 1)
		got, err := os.ReadFile(scanInfo.InputPatterns[0])
		require.NoError(t, err)
		assert.Len(t, got, 1024)
	})

	t.Run("does not reject non-os.File reader when global os.Stdin is an oversized file", func(t *testing.T) {
		t.Setenv(filesizelimit.MaxFileSizeEnvVar, "1024")

		oversizedPath := filepath.Join(t.TempDir(), "global-stdin.yaml")
		require.NoError(t, os.WriteFile(oversizedPath, bytes.Repeat([]byte("z"), 1025), 0o600))
		f, err := os.Open(oversizedPath)
		require.NoError(t, err)
		defer f.Close()

		origStdin := os.Stdin
		os.Stdin = f
		t.Cleanup(func() { os.Stdin = origStdin })

		payload := bytes.Repeat([]byte("d"), 512)
		scanInfo := &cautils.ScanInfo{}
		cleanup, err := prepareScanLocalInput(bytes.NewReader(payload), []string{"nsa", "-"}, scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		require.NoError(t, err)
		defer cleanup()

		got, err := os.ReadFile(scanInfo.InputPatterns[0])
		require.NoError(t, err)
		assert.Len(t, got, 512)
	})
}
