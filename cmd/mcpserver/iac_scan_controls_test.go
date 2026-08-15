package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
)

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
