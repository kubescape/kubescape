package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// privilegedPodManifest mirrors testdata/privileged-pod.yaml. The report test
// writes its own copy into t.TempDir() so it can assert the absolute FilePath
// the scan records without depending on where the package is checked out.
const privilegedPodManifest = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: myapp
    image: nginx
    securityContext:
      privileged: true
`

func TestIaCScanControls_EmptyPath(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.runIaCScanControls(context.Background(), "", []string{"C-0012"})
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "path is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIaCScanControls_EmptyControlIDs(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.runIaCScanControls(context.Background(), "/some/path", []string{})
	if err == nil {
		t.Fatal("expected error for empty control IDs")
	}
	if !strings.Contains(err.Error(), "at least one control ID") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIaCScanControls_WhitespaceIDs(t *testing.T) {
	srv := &KubescapeMcpserver{}
	_, err := srv.runIaCScanControls(context.Background(), "/some/path", []string{"  ", "\t"})
	if err == nil {
		t.Fatal("expected error for whitespace-only IDs")
	}
	if !strings.Contains(err.Error(), "at least one control ID") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestIaCScanControls_InvalidPath(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}
	_, err := ksServer.runIaCScanControls(context.Background(), "/invalid/path/that/does/not/exist", []string{"C-0012"})
	if err == nil {
		t.Fatal("expected error when scanning invalid path")
	}
	if !strings.Contains(err.Error(), "no such file or directory") &&
		!strings.Contains(err.Error(), "failed to collect") &&
		!strings.Contains(err.Error(), "failed to load") {
		t.Errorf("expected a file/resource collection error, got: %v", err)
	}
}

func TestIaCScanControls_ValidPath(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}
	_, _ = ksServer.policyGetter.SetRegoObjectsWithFallback()

	respBytes, err := ksServer.runIaCScanControls(context.Background(), "testdata/privileged-pod.yaml", []string{"C-0017"})
	if err != nil {
		t.Fatalf("unexpected error scanning valid path: %v", err)
	}
	respStr := string(respBytes)
	if !strings.Contains(respStr, `"total_failed":`) {
		t.Errorf("expected scan response to include total_failed, got: %s", respStr)
	}
}

// TestIaCScanControlsReport_ReturnsPostureReport asserts the report variant
// emits the v2 PostureReport rather than the summarized scanResponse, carrying
// the three things fixhandler.NewFixHandler validates: a File scanning target,
// the absolute path of the scanned file, and the raw resources.
func TestIaCScanControlsReport_ReturnsPostureReport(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}
	_, _ = ksServer.policyGetter.SetRegoObjectsWithFallback()

	fixture := filepath.Join(t.TempDir(), "privileged-pod.yaml")
	if err := os.WriteFile(fixture, []byte(privilegedPodManifest), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	outcome, err := ksServer.runIaCScanControlsReport(context.Background(), fixture, []string{"C-0017"})
	if err != nil {
		t.Fatalf("unexpected error scanning fixture: %v", err)
	}

	var report reporthandlingv2.PostureReport
	if err := json.Unmarshal(outcome.ReportJSON, &report); err != nil {
		t.Fatalf("failed to unmarshal posture report: %v", err)
	}

	if report.Metadata.ScanMetadata.ScanningTarget != reporthandlingv2.File {
		t.Errorf("expected ScanningTarget %d (File), got %d", reporthandlingv2.File, report.Metadata.ScanMetadata.ScanningTarget)
	}

	fileCtx := report.Metadata.ContextMetadata.FileContextMetadata
	if fileCtx == nil {
		t.Fatal("expected FileContextMetadata to be set for a file-target scan")
	}
	wantPath, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatalf("failed to resolve fixture path: %v", err)
	}
	if fileCtx.FilePath != wantPath {
		t.Errorf("expected FilePath %q, got %q", wantPath, fileCtx.FilePath)
	}

	// The fixhandler resolves each result back to a raw resource to find the
	// file and document index to patch, so an empty Resources list would make
	// the report useless to it even though it parses.
	if len(report.Resources) == 0 {
		t.Error("expected the report to carry raw resources")
	}

	// ResultsHandler.ToJson adds scanCoverage alongside the PostureReport;
	// mirror it here so coverage gaps (degraded runs, controls that were never
	// evaluated) travel with the report instead of being dropped.
	var envelope struct {
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage"`
	}
	if err := json.Unmarshal(outcome.ReportJSON, &envelope); err != nil {
		t.Fatalf("failed to unmarshal report envelope: %v", err)
	}
	if envelope.ScanCoverage == nil {
		t.Error("expected the report JSON to carry scanCoverage")
	}
}
