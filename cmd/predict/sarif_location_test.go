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

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSARIF_PhysicalLocation(t *testing.T) {
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
	wd, err := os.Getwd()
	require.NoError(t, err)
	outside := filepath.Join(filepath.Dir(wd), "elsewhere", "pod.yaml")
	outsideURI := "file://" + filepath.ToSlash(outside)
	if runtime.GOOS == "windows" {
		outsideURI = "file:///" + filepath.ToSlash(outside)
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"relative path", filepath.Join("manifests", "app.yaml"), "manifests/app.yaml"},
		{"uncleaned relative path", "./manifests/../manifests/app.yaml", "manifests/app.yaml"},
		{"absolute path under the working directory", filepath.Join(wd, "manifests", "app.yaml"), "manifests/app.yaml"},
		{"absolute path outside the working directory", outside, outsideURI},
		{"characters a URI must escape", filepath.Join("my manifests", "app#1.yaml"), "my%20manifests/app%231.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sarifArtifactURI(tc.path))
		})
	}
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
