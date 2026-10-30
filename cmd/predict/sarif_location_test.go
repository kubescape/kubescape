package predict

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSARIF_PhysicalLocation(t *testing.T) {
	// Run outside any git worktree, so the path stays relative to the
	// working directory.
	t.Chdir(t.TempDir())
	res := sampleResult()
	res.Results[0].Source = &pss.Source{File: filepath.Join("manifests", "app.yaml"), Line: 12, Column: 3}

	var buf bytes.Buffer
	require.NoError(t, writeSARIF(&buf, res))

	var report sarifReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)
	location := report.Runs[0].Results[0].Locations[0]
	require.NotNil(t, location.PhysicalLocation)
	assert.Equal(t, "manifests/app.yaml", location.PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, sarifRegion{StartLine: 12, StartColumn: 3}, location.PhysicalLocation.Region)
	assert.Equal(t, "test-ns/Deployment/failing-app/main", location.LogicalLocations[0].FullyQualifiedName)
}

func TestWriteSARIF_NoPhysicalLocationWithoutSource(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeSARIF(&buf, sampleResult()))
	assert.NotContains(t, buf.String(), "physicalLocation")
}

func TestSARIFArtifactURI(t *testing.T) {
	// Outside any git worktree, paths are relative to the working directory.
	wd, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	t.Chdir(wd)
	outside := filepath.Join(filepath.Dir(wd), "elsewhere", "pod.yaml")

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"relative path", filepath.Join("manifests", "app.yaml"), "manifests/app.yaml"},
		{"uncleaned relative path", "./manifests/../manifests/app.yaml", "manifests/app.yaml"},
		{"absolute path under the working directory", filepath.Join(wd, "manifests", "app.yaml"), "manifests/app.yaml"},
		{"absolute path outside the working directory", outside, fileURI(outside)},
		{"relative path outside the working directory", filepath.Join("..", "elsewhere", "pod.yaml"), fileURI(outside)},
		{"characters a URI must escape", filepath.Join("my manifests", "app#1.yaml"), "my%20manifests/app%231.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sarifArtifactURI(tc.path))
		})
	}
}

// TestSARIFArtifactURIInGitWorktree checks that a manifest in a git worktree
// gets a path relative to the worktree's root, which is what Code Scanning
// resolves it against, even when the command runs from a subdirectory.
func TestSARIFArtifactURIInGitWorktree(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	_, err = gitv5.PlainInit(root, false)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "deploy"), 0o750))
	t.Chdir(filepath.Join(root, "deploy"))

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"relative path in a subdirectory", "pod.yaml", "deploy/pod.yaml"},
		{"relative path in a sibling directory", filepath.Join("..", "other", "pod.yaml"), "other/pod.yaml"},
		{"absolute path", filepath.Join(root, "deploy", "pod.yaml"), "deploy/pod.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sarifArtifactURI(tc.path))
		})
	}
}

// fileURI returns the file URI of the absolute path path.
func fileURI(path string) string {
	if runtime.GOOS == "windows" {
		return "file:///" + filepath.ToSlash(path)
	}
	return "file://" + filepath.ToSlash(path)
}

// TestRunPSSSARIFLocatesLocalManifests runs the command on a manifest
// directory and checks that each finding points at its workload's file and
// line, which GitHub Code Scanning requires to accept the report.
func TestRunPSSSARIFLocatesLocalManifests(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Mkdir("manifests", 0o750))
	require.NoError(t, os.WriteFile(filepath.Join("manifests", "workloads.yaml"), []byte(stdinManifests), 0o600))

	output := filepath.Join(dir, "pss.sarif")
	err := runPSS(context.Background(), &pssFlags{
		level:  "Baseline",
		format: "sarif",
		output: output,
	}, []string{"manifests/"})
	require.ErrorContains(t, err, "PSS compliance check failed")

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	var report sarifReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Len(t, report.Runs, 1)
	require.NotEmpty(t, report.Runs[0].Results)

	// The Deployment starts on line 1, the Pod after the "---" on line 22.
	wantLines := map[string]int{"web": 1, "worker": 22}
	for _, result := range report.Runs[0].Results {
		location := result.Locations[0]
		name := location.LogicalLocations[0].Name
		require.NotNil(t, location.PhysicalLocation, name)
		assert.Equal(t, "manifests/workloads.yaml", location.PhysicalLocation.ArtifactLocation.URI, name)
		assert.Equal(t, sarifRegion{StartLine: wantLines[name], StartColumn: 1}, location.PhysicalLocation.Region, name)
	}
}

// TestRunPSSSARIFFromRepositorySubdirectory runs the command from a
// subdirectory of a git worktree and checks that the findings still point at
// the manifest's path from the worktree's root.
func TestRunPSSSARIFFromRepositorySubdirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	_, err = gitv5.PlainInit(root, false)
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(root, "deploy"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "deploy", "workloads.yaml"), []byte(stdinManifests), 0o600))
	t.Chdir(filepath.Join(root, "deploy"))

	output := filepath.Join(t.TempDir(), "pss.sarif")
	err = runPSS(context.Background(), &pssFlags{
		level:  "Baseline",
		format: "sarif",
		output: output,
	}, []string{"workloads.yaml"})
	require.ErrorContains(t, err, "PSS compliance check failed")

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	var report sarifReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Len(t, report.Runs, 1)
	require.NotEmpty(t, report.Runs[0].Results)
	for _, result := range report.Runs[0].Results {
		location := result.Locations[0]
		require.NotNil(t, location.PhysicalLocation, location.LogicalLocations[0].Name)
		assert.Equal(t, "deploy/workloads.yaml", location.PhysicalLocation.ArtifactLocation.URI)
	}
}

// TestRunPSSSARIFFromStdinHasNoPhysicalLocation checks that manifests read
// from stdin, which have no file to point at, keep only logical locations.
func TestRunPSSSARIFFromStdinHasNoPhysicalLocation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "pss.sarif")
	err := runPSS(context.Background(), &pssFlags{
		level:  "Baseline",
		format: "sarif",
		output: output,
		stdin:  strings.NewReader(stdinManifests),
	}, []string{"-"})
	require.ErrorContains(t, err, "PSS compliance check failed")

	data, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.Contains(t, string(data), "logicalLocations")
	assert.NotContains(t, string(data), "physicalLocation")
}
