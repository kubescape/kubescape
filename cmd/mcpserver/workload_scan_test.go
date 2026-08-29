package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/mark3labs/mcp-go/server"
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

// --- tool dispatch --------------------------------------------------------

// stubWorkloadScan replaces the scan seam with a recorder so CallTool argument
// mapping can be asserted without running a scan, and restores it afterwards.
// It returns a pointer to the recorded arguments.
func stubWorkloadScan(t *testing.T) *struct{ workload, namespace, path, framework string } {
	t.Helper()
	got := &struct{ workload, namespace, path, framework string }{}
	orig := workloadScanFn
	t.Cleanup(func() { workloadScanFn = orig })
	workloadScanFn = func(_ *KubescapeMcpserver, _ context.Context, workload, namespace, path, framework string) ([]byte, error) {
		got.workload, got.namespace, got.path, got.framework = workload, namespace, path, framework
		return []byte(`{"total_failed":0}`), nil
	}
	return got
}

func newWorkloadToolServer(t *testing.T) *KubescapeMcpserver {
	t.Helper()
	ksServer := &KubescapeMcpserver{s: server.NewMCPServer("kubescape-test", "test")}
	require.NotPanics(t, func() { createWorkloadScanningTools(ksServer) })
	return ksServer
}

func TestCallTool_ScanWorkload_ArgumentErrors(t *testing.T) {
	tests := []struct {
		name      string
		arguments map[string]any
		wantErr   string
	}{
		{
			name:      "missing workload",
			arguments: map[string]any{},
			wantErr:   "workload argument is required",
		},
		{
			name:      "blank workload",
			arguments: map[string]any{"workload": "   "},
			wantErr:   "workload argument is required",
		},
		{
			name:      "non-string workload",
			arguments: map[string]any{"workload": 42},
			wantErr:   "workload argument must be a string",
		},
		{
			name:      "non-string namespace",
			arguments: map[string]any{"workload": "Deployment/nginx", "namespace": 7},
			wantErr:   "namespace argument must be a string",
		},
		{
			name:      "non-string path",
			arguments: map[string]any{"workload": "Deployment/nginx", "path": true},
			wantErr:   "path argument must be a string",
		},
		{
			name:      "non-string framework",
			arguments: map[string]any{"workload": "Deployment/nginx", "framework": []any{"nsa"}},
			wantErr:   "framework argument must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubWorkloadScan(t)
			ksServer := newWorkloadToolServer(t)

			res, err := ksServer.CallTool(context.Background(), "scan_workload", tt.arguments)
			require.NoError(t, err, "argument problems are reported as tool errors, not Go errors")
			require.NotNil(t, res)
			assert.True(t, res.IsError, "expected a tool error result")
			assert.Contains(t, toolResultText(t, res), tt.wantErr)
		})
	}
}

func TestCallTool_ScanWorkload_ForwardsArguments(t *testing.T) {
	tests := []struct {
		name          string
		arguments     map[string]any
		wantWorkload  string
		wantNamespace string
		wantPath      string
		wantFramework string
	}{
		{
			name:         "workload only",
			arguments:    map[string]any{"workload": "Deployment/nginx"},
			wantWorkload: "Deployment/nginx",
		},
		{
			name:          "wildcard namespace is normalized to cluster-wide",
			arguments:     map[string]any{"workload": "Deployment/nginx", "namespace": "*"},
			wantWorkload:  "Deployment/nginx",
			wantNamespace: "",
		},
		{
			name:          "all arguments forwarded and trimmed",
			arguments:     map[string]any{"workload": "  Deployment/nginx  ", "namespace": "default", "path": "  ./manifests  ", "framework": " nsa "},
			wantWorkload:  "Deployment/nginx",
			wantNamespace: "default",
			wantPath:      "./manifests",
			wantFramework: "nsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stubWorkloadScan(t)
			ksServer := newWorkloadToolServer(t)

			res, err := ksServer.CallTool(context.Background(), "scan_workload", tt.arguments)
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.False(t, res.IsError, "unexpected tool error: %s", toolResultText(t, res))

			assert.Equal(t, tt.wantWorkload, got.workload)
			assert.Equal(t, tt.wantNamespace, got.namespace)
			assert.Equal(t, tt.wantPath, got.path)
			assert.Equal(t, tt.wantFramework, got.framework)
		})
	}
}

// TestCallTool_ScanWorkload_ScanFailureIsToolError asserts a failing scan comes
// back as a tool error the agent can read, not a transport-level Go error.
func TestCallTool_ScanWorkload_ScanFailureIsToolError(t *testing.T) {
	orig := workloadScanFn
	t.Cleanup(func() { workloadScanFn = orig })
	workloadScanFn = func(_ *KubescapeMcpserver, _ context.Context, _, _, _, _ string) ([]byte, error) {
		return nil, errors.New("resource nginx was not found")
	}
	ksServer := newWorkloadToolServer(t)

	res, err := ksServer.CallTool(context.Background(), "scan_workload", map[string]any{"workload": "Deployment/nginx"})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.IsError)
	text := toolResultText(t, res)
	assert.Contains(t, text, "failed to run workload scan")
	assert.Contains(t, text, "was not found", "the underlying reason must survive to the caller")
}

func TestCreateWorkloadScanningTools_RegistersScanWorkload(t *testing.T) {
	ksServer := newWorkloadToolServer(t)

	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	require.NoError(t, err)
	raw, err := json.Marshal(ksServer.s.HandleMessage(context.Background(), message))
	require.NoError(t, err)

	var listed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Properties map[string]any `json:"properties"`
					Required   []string       `json:"required"`
				} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &listed))

	var found bool
	for _, tool := range listed.Result.Tools {
		if tool.Name != "scan_workload" {
			continue
		}
		found = true
		for _, prop := range []string{"workload", "namespace", "path", "framework"} {
			assert.Contains(t, tool.InputSchema.Properties, prop)
		}
		assert.Contains(t, tool.InputSchema.Required, "workload")
		assert.NotContains(t, tool.InputSchema.Required, "namespace",
			"namespace must stay optional so an agent can search all namespaces")
	}
	assert.True(t, found, "scan_workload was not registered")
}
