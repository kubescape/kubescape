package mcpserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- request building (no scan) -------------------------------------------

func TestBuildWorkloadScanRequest_InvalidIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		workload string
		wantErr  string
	}{
		{name: "empty identifier", workload: ""},
		{name: "missing kind", workload: "nginx"},
		{name: "too many segments", workload: "cluster/default/Deployment/nginx"},
		{name: "empty segment", workload: "default//nginx"},
		{name: "bad api version", workload: "Deployment.vX.apps/nginx", wantErr: "is not a valid API version"},
		{name: "missing api version", workload: "Deployment.apps/nginx", wantErr: "is not a valid API version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildWorkloadScanRequest(tt.workload, "", "", "")
			require.Error(t, err)
			assert.True(t, errors.Is(err, cautils.ErrInvalidWorkloadIdentifier),
				"expected ErrInvalidWorkloadIdentifier, got %v", err)
			if tt.wantErr != "" {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildWorkloadScanRequest_ScanObject(t *testing.T) {
	tests := []struct {
		name          string
		workload      string
		namespace     string
		wantNamespace string
		wantKind      string
		wantName      string
		wantAPIVer    string
	}{
		{
			name:     "bare kind and name leaves apiVersion unset for discovery",
			workload: "Deployment/nginx",
			wantKind: "Deployment",
			wantName: "nginx",
		},
		{
			name:          "namespace from the identifier",
			workload:      "default/Deployment/nginx",
			wantNamespace: "default",
			wantKind:      "Deployment",
			wantName:      "nginx",
		},
		{
			name:          "explicit namespace wins over the identifier's",
			workload:      "a/Deployment/nginx",
			namespace:     "b",
			wantNamespace: "b",
			wantKind:      "Deployment",
			wantName:      "nginx",
		},
		{
			name:       "dotted kind resolves to a group/version apiVersion",
			workload:   "Deployment.v1.apps/nginx",
			wantKind:   "Deployment",
			wantName:   "nginx",
			wantAPIVer: "apps/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := buildWorkloadScanRequest(tt.workload, tt.namespace, "", "")
			require.NoError(t, err)
			require.NotNil(t, req.scanObject)
			assert.Equal(t, tt.wantNamespace, req.scanObject.GetNamespace())
			assert.Equal(t, tt.wantKind, req.scanObject.GetKind())
			assert.Equal(t, tt.wantName, req.scanObject.GetName())
			assert.Equal(t, tt.wantAPIVer, req.scanObject.GetApiVersion())
			assert.Equal(t, tt.wantNamespace, req.namespace)
		})
	}
}

func TestBuildWorkloadScanRequest_Frameworks(t *testing.T) {
	t.Run("defaults to the workload control set", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("Deployment/nginx", "", "", "")
		require.NoError(t, err)
		got := make([]string, 0, len(req.policyIdentifiers))
		for _, pi := range req.policyIdentifiers {
			got = append(got, pi.Identifier)
		}
		assert.Equal(t, workloadScanFrameworks, got)
	})

	t.Run("an explicit framework replaces the default", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("Deployment/nginx", "", "", "  nsa  ")
		require.NoError(t, err)
		require.Len(t, req.policyIdentifiers, 1)
		assert.Equal(t, "nsa", req.policyIdentifiers[0].Identifier)
	})
}

func TestBuildWorkloadScanRequest_HandlerSelection(t *testing.T) {
	t.Run("no path scans the live cluster", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("default/Deployment/nginx", "", "", "")
		require.NoError(t, err)
		assert.Nil(t, req.rsrcHandler, "a nil handler is what makes executeScan build a cluster client")
		assert.Empty(t, req.inputPatterns)
		assert.Equal(t, "default", req.namespace)
	})

	t.Run("a path switches to the file handler and drops the collection namespace", func(t *testing.T) {
		req, err := buildWorkloadScanRequest("default/Deployment/nginx", "", "testdata/deployment.yaml", "")
		require.NoError(t, err)
		require.NotNil(t, req.rsrcHandler)
		assert.Equal(t, []string{"testdata/deployment.yaml"}, req.inputPatterns)
		assert.Empty(t, req.namespace, "the file handler has no namespace collection filter")
		assert.Equal(t, "default", req.scanObject.GetNamespace(),
			"the namespace must survive on the scan object, which is what matches the manifests")
	})
}

// --- resolution against local manifests -----------------------------------
//
// These run the real collect-policies → collect-resources pipeline through
// FileResourceHandler, so they exercise ScanObject resolution without a
// cluster. They pass an explicit framework to keep the policy set small; the
// default set is asserted separately above.

func newWorkloadScanTestServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	ksServer := &KubescapeMcpserver{
		policyGetter: getter.NewDownloadReleasedPolicy(),
	}
	_, _ = ksServer.policyGetter.SetRegoObjectsWithFallback()
	return ksServer
}

func TestRunWorkloadScan_ResolvesFromFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "", "testdata/deployment.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
}

func TestRunWorkloadScan_NotFoundInFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	_, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/absent", "", "testdata/deployment.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "not found")
}

func TestRunWorkloadScan_AmbiguousInFile(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// Two Deployments named nginx in different namespaces: without a namespace
	// the request matches both, and reporting that beats scanning an arbitrary
	// one of them.
	_, err := ksServer.RunWorkloadScan(context.Background(), "Deployment/nginx", "", "testdata/two-workloads.yaml", "nsa")
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "more than one")
}

func TestRunWorkloadScan_NamespaceDisambiguates(t *testing.T) {
	ksServer := newWorkloadScanTestServer(t)

	// The same file that is ambiguous above resolves cleanly once the namespace
	// picks one of the two.
	respBytes, err := ksServer.RunWorkloadScan(context.Background(), "staging/Deployment/nginx", "", "testdata/two-workloads.yaml", "nsa")
	require.NoError(t, err)
	assert.Contains(t, string(respBytes), `"total_failed":`)
}

func TestRunWorkloadScan_InvalidIdentifierDoesNotScan(t *testing.T) {
	// No policy getter is configured: reaching the scan would fail differently,
	// so this also proves the identifier is rejected before any work starts.
	ksServer := &KubescapeMcpserver{}

	_, err := ksServer.RunWorkloadScan(context.Background(), "nginx", "", "testdata/deployment.yaml", "nsa")
	require.Error(t, err)
	assert.True(t, errors.Is(err, cautils.ErrInvalidWorkloadIdentifier))
}
