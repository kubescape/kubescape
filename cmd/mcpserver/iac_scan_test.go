package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
)

func TestIaCScan_InvalidPath(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// Test with a non-existent path. CollectResources should fail.
	_, err := ksServer.runIaCScan(context.Background(), "/invalid/path/that/does/not/exist", "nsa")

	// We expect an error specifically related to resource collection/file not found, not policy loading.
	if err == nil {
		t.Fatalf("Expected an error when scanning an invalid path")
	}
	if !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "failed to collect") && !strings.Contains(err.Error(), "failed to load") {
		t.Errorf("Expected a file/resource collection error, got: %v", err)
	}
}

func TestIaCScan_ValidPath(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// Initialize the getter so it can read from the ~/.kubescape cache
	_, err := ksServer.policyGetter.SetRegoObjectsWithFallback()
	if err != nil {
		t.Logf("Warning: SetRegoObjectsWithFallback returned error (expected if fully offline): %v", err)
	}

	// Test with a small fixture containing a privileged pod.
	respBytes, err := ksServer.runIaCScan(context.Background(), "testdata/privileged-pod.yaml", "nsa")
	if err != nil {
		t.Fatalf("Unexpected error scanning valid path: %v", err)
	}

	// Verify that the JSON response indicates failures (total_failed > 0).
	respStr := string(respBytes)
	if !strings.Contains(respStr, `"total_failed":`) || strings.Contains(respStr, `"total_failed": 0`) || strings.Contains(respStr, `"total_failed":0`) {
		t.Errorf("Expected scan to find failures in privileged-pod.yaml, got response: %v", respStr)
	}
}
