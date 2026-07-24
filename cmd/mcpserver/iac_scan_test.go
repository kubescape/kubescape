package mcpserver

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils/getter"
)

func TestIaCScan(t *testing.T) {
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}

	// Test with a non-existent path. CollectResources should fail or return empty,
	// and OPA will process 0 resources. We just want to ensure it doesn't panic.
	_, err := ksServer.runIaCScan(context.Background(), "/invalid/path/that/does/not/exist", "nsa")

	// We expect an error due to no resources or K8S connection (if the fallback somehow triggered)
	if err == nil {
		t.Errorf("Expected an error when scanning an invalid path")
	}
}
