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

	t.Run("stdin input is copied to system temp dir and cleaned up", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}
		stdin := bytes.NewBufferString("apiVersion: v1\nkind: Pod\nmetadata:\n  name: nginx\n")

		cleanup, err := prepareScanLocalInput(stdin, []string{"nsa", "-"}, &scanInfo, scanLocalInputOptions{
			FirstInputArg:    1,
			RejectMixedStdin: true,
		})
		require.NoError(t, err)
		require.Len(t, scanInfo.InputPatterns, 1)
		assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(scanInfo.InputPatterns[0]))

		got, err := os.ReadFile(scanInfo.InputPatterns[0])
		require.NoError(t, err)
		assert.Contains(t, string(got), "kind: Pod")

		cleanup()
		_, err = os.Stat(scanInfo.InputPatterns[0])
		assert.True(t, os.IsNotExist(err), "temporary stdin manifest should be removed by cleanup")
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
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(ks.scanInfo.InputPatterns[0]))
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
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(ks.scanInfo.InputPatterns[0]))
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
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(ks.scanInfo.InputPatterns[0]))
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
	assert.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(ks.scanInfo.InputPatterns[0]))
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
