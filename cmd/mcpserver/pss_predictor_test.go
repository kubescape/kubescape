package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newPSSPredictorTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		deploymentGVR:  "DeploymentList",
		daemonSetGVR:   "DaemonSetList",
		statefulSetGVR: "StatefulSetList",
		replicaSetGVR:  "ReplicaSetList",
		jobGVR:         "JobList",
		cronJobGVR:     "CronJobList",
		podGVR:         "PodList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	createPSSPredictorTools(ksServer)
	return ksServer
}

func loadYAMLFixture(t *testing.T, relPath string) *unstructured.Unstructured {
	t.Helper()
	data, err := os.ReadFile(relPath)
	require.NoError(t, err)

	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var u unstructured.Unstructured
	err = decoder.Decode(&u)
	require.NoError(t, err)
	return &u
}

func parsePSSResult(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	require.False(t, result.IsError, "unexpected tool error: %s", toolResultText(t, result))
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &out))
	return out
}

func parsePSSToolError(t *testing.T, result *mcp.CallToolResult) ToolError {
	t.Helper()
	require.True(t, result.IsError, "expected tool error, got success: %s", toolResultText(t, result))
	var te ToolError
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &te))
	return te
}

func getSummary(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	summary, ok := result["summary"].(map[string]any)
	require.True(t, ok, "summary must be a map[string]any")
	return summary
}

func getFailingWorkloads(t *testing.T, result map[string]any) []any {
	t.Helper()
	fws, ok := result["failing_workloads"].([]any)
	require.True(t, ok, "failing_workloads must be a []any")
	return fws
}

// 1. Missing namespace returns INVALID_ARGUMENT error
func TestPredictPSSCompliance_MissingNamespaceReturnsError(t *testing.T) {
	ksServer := newPSSPredictorTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, "namespace")
}

// 2. Invalid level returns INVALID_ARGUMENT error
func TestPredictPSSCompliance_InvalidLevelReturnsError(t *testing.T) {
	ksServer := newPSSPredictorTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "invalid-level",
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeInvalidArgument, te.Code)
	assert.Contains(t, te.Message, "invalid PSS level")
}

// 3. Empty namespace returns zero counts and Restricted current_effective_level
func TestPredictPSSCompliance_EmptyNamespaceReturnsZeroCounts(t *testing.T) {
	ksServer := newPSSPredictorTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "empty-ns",
	}))
	parsed := parsePSSResult(t, result)
	assert.Equal(t, "empty-ns", parsed["namespace"])
	assert.Equal(t, "Restricted", parsed["target_level"])

	summary := getSummary(t, parsed)
	assert.Equal(t, float64(0), summary["total_workloads"])
	assert.Equal(t, float64(0), summary["passing"])
	assert.Equal(t, float64(0), summary["failing"])
	assert.Equal(t, "Restricted", summary["current_effective_level"])

	fws := getFailingWorkloads(t, parsed)
	assert.Empty(t, fws)
}

// 4. All compliant workloads report 0 failing and Restricted current_effective_level
func TestPredictPSSCompliance_AllCompliantWorkloads(t *testing.T) {
	deploy := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	ksServer := newPSSPredictorTestServer(t, deploy)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])
	assert.Equal(t, float64(0), summary["failing"])
	assert.Equal(t, "Restricted", summary["current_effective_level"])

	fws := getFailingWorkloads(t, parsed)
	assert.Empty(t, fws)
}

// 5. Mixed compliance workloads evaluated at Restricted
func TestPredictPSSCompliance_MixedCompliance(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")
	privileged := loadYAMLFixture(t, "testdata/pss/privileged-daemonset.yaml")

	ksServer := newPSSPredictorTestServer(t, compliant, baseline, privileged)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	assert.Equal(t, float64(3), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])
	assert.Equal(t, float64(2), summary["failing"])
	assert.Equal(t, "Privileged", summary["current_effective_level"])

	fws := getFailingWorkloads(t, parsed)
	require.Len(t, fws, 2)

	// Since results are sorted by Kind, then Name:
	// DaemonSet/privileged-daemonset comes before Deployment/baseline-deployment
	ds := fws[0].(map[string]any)
	assert.Equal(t, "DaemonSet", ds["kind"])
	assert.Equal(t, "privileged-daemonset", ds["name"])
	assert.Equal(t, "Privileged", ds["passes_at"])
	dsViolations := ds["violations"].([]any)
	require.NotEmpty(t, dsViolations)

	dep := fws[1].(map[string]any)
	assert.Equal(t, "Deployment", dep["kind"])
	assert.Equal(t, "baseline-deployment", dep["name"])
	assert.Equal(t, "Baseline", dep["passes_at"])
	depViolations := dep["violations"].([]any)
	require.NotEmpty(t, depViolations)
}

// 6. Target level Baseline reports only Baseline violations
func TestPredictPSSCompliance_BaselineLevelTarget(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")
	privileged := loadYAMLFixture(t, "testdata/pss/privileged-daemonset.yaml")

	ksServer := newPSSPredictorTestServer(t, compliant, baseline, privileged)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Baseline",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	// At Baseline, baseline-deployment passes! Only privileged-daemonset fails.
	assert.Equal(t, float64(3), summary["total_workloads"])
	assert.Equal(t, float64(2), summary["passing"])
	assert.Equal(t, float64(1), summary["failing"])
	assert.Equal(t, "Privileged", summary["current_effective_level"])

	fws := getFailingWorkloads(t, parsed)
	require.Len(t, fws, 1)

	ds := fws[0].(map[string]any)
	assert.Equal(t, "DaemonSet", ds["kind"])
	assert.Equal(t, "privileged-daemonset", ds["name"])
	assert.Equal(t, "Privileged", ds["passes_at"])
}

// 7. Workload name filter only evaluates the target workload
func TestPredictPSSCompliance_WorkloadNameFilter(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")

	ksServer := newPSSPredictorTestServer(t, compliant, baseline)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "baseline-deployment",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(0), summary["passing"])
	assert.Equal(t, float64(1), summary["failing"])
	assert.Equal(t, "Baseline", summary["current_effective_level"])

	fws := getFailingWorkloads(t, parsed)
	require.Len(t, fws, 1)
	assert.Equal(t, "baseline-deployment", fws[0].(map[string]any)["name"])
}

// 8. Workload name not found returns RESOURCE_NOT_FOUND error
func TestPredictPSSCompliance_WorkloadNameNotFound(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	ksServer := newPSSPredictorTestServer(t, compliant)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "non-existent-workload",
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeResourceNotFound, te.Code)
	assert.Contains(t, te.Message, "non-existent-workload")
}

// 9. Default level is Restricted when omitted
func TestPredictPSSCompliance_DefaultLevelIsRestricted(t *testing.T) {
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")
	ksServer := newPSSPredictorTestServer(t, baseline)

	// Omit level argument
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	parsed := parsePSSResult(t, result)
	assert.Equal(t, "Restricted", parsed["target_level"])

	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(0), summary["passing"])
	assert.Equal(t, float64(1), summary["failing"])
}

// 10. Multiple workload types (Deployment, DaemonSet, Pod) all correctly evaluated
func TestPredictPSSCompliance_MultipleWorkloadTypes(t *testing.T) {
	compliantDeploy := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	privilegedDS := loadYAMLFixture(t, "testdata/pss/privileged-daemonset.yaml")
	standalonePod := loadYAMLFixture(t, "testdata/pss/standalone-pod.yaml")

	ksServer := newPSSPredictorTestServer(t, compliantDeploy, privilegedDS, standalonePod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	assert.Equal(t, float64(3), summary["total_workloads"])
	assert.Equal(t, float64(2), summary["passing"]) // compliantDeploy and standalonePod pass Restricted
	assert.Equal(t, float64(1), summary["failing"]) // privilegedDS fails
}

// 11. Privileged container triggers Privileged violation under Baseline
func TestPredictPSSCompliance_PrivilegedContainerFailsBaseline(t *testing.T) {
	privilegedDS := loadYAMLFixture(t, "testdata/pss/privileged-daemonset.yaml")
	ksServer := newPSSPredictorTestServer(t, privilegedDS)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Baseline",
	}))
	parsed := parsePSSResult(t, result)
	fws := getFailingWorkloads(t, parsed)
	require.Len(t, fws, 1)

	violations := fws[0].(map[string]any)["violations"].([]any)
	checks := make(map[string]bool)
	for _, v := range violations {
		vMap := v.(map[string]any)
		checks[vMap["check"].(string)] = true
	}
	assert.True(t, checks["Privileged"], "expected check 'Privileged' in violations")
}

// 12. Current effective level computation
func TestPredictPSSCompliance_CurrentEffectiveLevelComputation(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")

	// Compliant + Baseline -> effective level is Baseline
	ksServer := newPSSPredictorTestServer(t, compliant, baseline)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Baseline",
	}))
	parsed := parsePSSResult(t, result)
	assert.Equal(t, "Baseline", getSummary(t, parsed)["current_effective_level"])
}

func dispatchToolDirect(ksServer *KubescapeMcpserver, tool string, arguments any) (*mcp.CallToolResult, error) {
	message, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": arguments,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	resp := ksServer.s.HandleMessage(context.Background(), message)
	jsonResp, ok := resp.(mcp.JSONRPCResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected message response: %T", resp)
	}
	switch res := jsonResp.Result.(type) {
	case *mcp.CallToolResult:
		return res, nil
	case mcp.CallToolResult:
		return &res, nil
	default:
		return nil, fmt.Errorf("unexpected result type: %T", jsonResp.Result)
	}
}

func extractToolResultText(result *mcp.CallToolResult) (string, error) {
	if result == nil {
		return "", errors.New("result is nil")
	}
	if len(result.Content) != 1 {
		return "", fmt.Errorf("expected 1 content element, got %d", len(result.Content))
	}
	tc, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		return "", fmt.Errorf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text, nil
}

// 13. Concurrent calls to predict_pss_compliance do not race
func TestPredictPSSCompliance_ConcurrentCalls(t *testing.T) {
	compliant := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")

	// Put compliant in "ns-1" and baseline in "ns-2"
	compliantCopy := compliant.DeepCopy()
	compliantCopy.SetNamespace("ns-1")
	baselineCopy := baseline.DeepCopy()
	baselineCopy.SetNamespace("ns-2")

	ksServer := newPSSPredictorTestServer(t, compliantCopy, baselineCopy)

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ns := "ns-1"
			expectedPassing := float64(1)
			if idx%2 == 1 {
				ns = "ns-2"
				expectedPassing = float64(0)
			}
			res, err := dispatchToolDirect(ksServer, "predict_pss_compliance", map[string]any{
				"namespace": ns,
				"level":     "Restricted",
			})
			if err != nil {
				errCh <- err
				return
			}
			if res.IsError {
				errCh <- errors.New("tool returned error in concurrent run")
				return
			}
			text, err := extractToolResultText(res)
			if err != nil {
				errCh <- err
				return
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(text), &parsed); err != nil {
				errCh <- err
				return
			}
			summary, ok := parsed["summary"].(map[string]any)
			if !ok {
				errCh <- errors.New("summary is not a map[string]any in concurrent run")
				return
			}
			if summary["passing"] != expectedPassing {
				errCh <- fmt.Errorf("expected passing %v, got %v in concurrent run", expectedPassing, summary["passing"])
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// 14. K8s client error returns ErrCodeK8sClientError
func TestPredictPSSCompliance_K8sClientErrorReturnsToolError(t *testing.T) {
	origLoadK8sConfig := loadK8sConfig
	origSetConnectedToCluster := setConnectedToCluster
	t.Cleanup(func() {
		loadK8sConfig = origLoadK8sConfig
		setConnectedToCluster = origSetConnectedToCluster
	})
	loadK8sConfig = func() error { return errors.New("no kubeconfig") }
	setConnectedToCluster = func(bool) {}

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer("test", "v1"),
	}
	createPSSPredictorTools(ksServer)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeK8sClientError, te.Code)
}

// 15. List error surfaces with classifyScanError
func TestPredictPSSCompliance_ListErrorReturnsToolError(t *testing.T) {
	ksServer := newPSSPredictorTestServer(t)

	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	dyn.PrependReactor("list", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection reset by peer")
	})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	te := parsePSSToolError(t, result)
	assert.Equal(t, ErrCodeScanFailed, te.Code)
	assert.Contains(t, te.Message, "connection reset by peer")
}

// 16. Controlled pod is deduplicated during namespace-wide scan when parent is present, but accessible via workload_name
func TestPredictPSSCompliance_ControlledPodDeduplicatedInNamespaceScan(t *testing.T) {
	childPod := loadYAMLFixture(t, "testdata/pss/child-pod.yaml")
	rs := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"metadata": map[string]any{
				"name":      "some-rs",
				"namespace": "test-pss",
				"uid":       "12345",
			},
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "child",
								"image": "nginx:latest",
							},
						},
					},
				},
			},
		},
	}
	ksServer := newPSSPredictorTestServer(t, rs, childPod)

	// Namespace-wide scan should evaluate some-rs and deduplicate child-pod
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])

	// Explicit query by workload_name should evaluate child-pod directly
	resultExplicit := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "child-pod",
	}))
	parsedExplicit := parsePSSResult(t, resultExplicit)
	summaryExplicit := getSummary(t, parsedExplicit)
	assert.Equal(t, float64(1), summaryExplicit["total_workloads"])
}

// 17. Workload name filter supports Kind/Name format (e.g. Deployment/baseline-deployment)
func TestPredictPSSCompliance_WorkloadNameWithKindPrefix(t *testing.T) {
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")
	ksServer := newPSSPredictorTestServer(t, baseline)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "Deployment/baseline-deployment",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["failing"])

	// Mismatched kind should return RESOURCE_NOT_FOUND
	resultMismatch := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "DaemonSet/baseline-deployment",
	}))
	te := parsePSSToolError(t, resultMismatch)
	assert.Equal(t, ErrCodeResourceNotFound, te.Code)
}

// 18. Decode failure records warning and does not count as passing
func TestPredictPSSCompliance_DecodeFailureDoesNotCountAsPassing(t *testing.T) {
	malformed := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "malformed-deployment",
				"namespace": "test-pss",
			},
			"spec": map[string]any{
				"template": "not-a-map",
			},
		},
	}
	ksServer := newPSSPredictorTestServer(t, malformed)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)

	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(0), summary["passing"])
	assert.Equal(t, float64(0), summary["failing"])
	assert.Equal(t, float64(1), summary["unevaluated"])
	assert.Equal(t, false, summary["current_effective_level_complete"])

	warnings, ok := parsed["decode_warnings"].([]any)
	require.True(t, ok)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0].(string), "malformed-deployment")

	fws := getFailingWorkloads(t, parsed)
	assert.Empty(t, fws)
}

// 19. Absent owner: workload with missing parent is retained as an unmatched root in namespace scans
func TestPredictPSSCompliance_AbsentOwnerRetainedInNamespaceScan(t *testing.T) {
	childPod := loadYAMLFixture(t, "testdata/pss/child-pod.yaml")
	// childPod points to some-rs (controller: true), but some-rs is absent from the scan
	ksServer := newPSSPredictorTestServer(t, childPod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])

	resultExplicit := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "child-pod",
	}))
	parsedExplicit := parsePSSResult(t, resultExplicit)
	summaryExplicit := getSummary(t, parsedExplicit)
	assert.Equal(t, float64(1), summaryExplicit["total_workloads"])
}

// 20. Operator-managed workload (controlled by a Custom Resource) is retained in namespace scans
func TestPredictPSSCompliance_OperatorOwnedWorkloadRetainedInNamespaceScan(t *testing.T) {
	privilegedDS := loadYAMLFixture(t, "testdata/pss/privileged-daemonset.yaml")
	controllerTrue := true
	privilegedDS.SetOwnerReferences([]metav1.OwnerReference{
		{
			APIVersion: "custom.operator.io/v1",
			Kind:       "OperatorResource",
			Name:       "custom-operator",
			UID:        "cr-uid-1234",
			Controller: &controllerTrue,
		},
	})

	ksServer := newPSSPredictorTestServer(t, privilegedDS)

	// Namespace scan must retain and evaluate the operator-owned DaemonSet
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["failing"])
	assert.Equal(t, "Privileged", summary["current_effective_level"])

	// Explicit selection should also evaluate it
	resultExplicit := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "DaemonSet/privileged-daemonset",
	}))
	parsedExplicit := parsePSSResult(t, resultExplicit)
	summaryExplicit := getSummary(t, parsedExplicit)
	assert.Equal(t, float64(1), summaryExplicit["total_workloads"])
	assert.Equal(t, float64(1), summaryExplicit["failing"])
	assert.Equal(t, "Privileged", summaryExplicit["current_effective_level"])
}

// 21. Custom-owned Pod (controlled by a Custom Resource) is retained in namespace scans
func TestPredictPSSCompliance_CustomOwnedPodRetainedInNamespaceScan(t *testing.T) {
	pod := loadYAMLFixture(t, "testdata/pss/standalone-pod.yaml")
	controllerTrue := true
	pod.SetOwnerReferences([]metav1.OwnerReference{
		{
			APIVersion: "sparkoperator.k8s.io/v1beta2",
			Kind:       "SparkApplication",
			Name:       "spark-pi",
			UID:        "spark-uid-5678",
			Controller: &controllerTrue,
		},
	})

	ksServer := newPSSPredictorTestServer(t, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])
}

// 22. Normal Deployment -> ReplicaSet -> Pod hierarchy deduplicates to a single evaluated workload
func TestPredictPSSCompliance_DeploymentReplicaSetPodDeduplication(t *testing.T) {
	deploy := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	deploy.SetUID("dep-uid-100")

	rs := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"metadata": map[string]any{
				"name":      "compliant-deployment-rs",
				"namespace": "test-pss",
				"uid":       "rs-uid-100",
				"ownerReferences": []any{
					map[string]any{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"name":       "compliant-deployment",
						"uid":        "dep-uid-100",
						"controller": true,
					},
				},
			},
			"spec": deploy.Object["spec"],
		},
	}

	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "compliant-deployment-pod",
				"namespace": "test-pss",
				"uid":       "pod-uid-100",
				"ownerReferences": []any{
					map[string]any{
						"apiVersion": "apps/v1",
						"kind":       "ReplicaSet",
						"name":       "compliant-deployment-rs",
						"uid":        "rs-uid-100",
						"controller": true,
					},
				},
			},
			"spec": deploy.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"],
		},
	}

	ksServer := newPSSPredictorTestServer(t, deploy, rs, pod)

	// Namespace-wide scan should evaluate only the Deployment (total: 1)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])

	// Explicit queries can still access child workloads directly
	resultRS := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "ReplicaSet/compliant-deployment-rs",
	}))
	parsedRS := parsePSSResult(t, resultRS)
	assert.Equal(t, float64(1), getSummary(t, parsedRS)["total_workloads"])

	resultPod := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "Pod/compliant-deployment-pod",
	}))
	parsedPod := parsePSSResult(t, resultPod)
	assert.Equal(t, float64(1), getSummary(t, parsedPod)["total_workloads"])
}

// 23. Operator-owned Deployment -> ReplicaSet -> Pod hierarchy retains Deployment and deduplicates children
func TestPredictPSSCompliance_OperatorDeploymentDeduplication(t *testing.T) {
	deploy := loadYAMLFixture(t, "testdata/pss/compliant-deployment.yaml")
	deploy.SetUID("op-dep-uid")
	controllerTrue := true
	deploy.SetOwnerReferences([]metav1.OwnerReference{
		{
			APIVersion: "monitoring.coreos.com/v1",
			Kind:       "Prometheus",
			Name:       "k8s",
			UID:        "prom-uid",
			Controller: &controllerTrue,
		},
	})

	rs := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"metadata": map[string]any{
				"name":      "op-deployment-rs",
				"namespace": "test-pss",
				"uid":       "op-rs-uid",
				"ownerReferences": []any{
					map[string]any{
						"apiVersion": "apps/v1",
						"kind":       "Deployment",
						"name":       "compliant-deployment",
						"uid":        "op-dep-uid",
						"controller": true,
					},
				},
			},
			"spec": deploy.Object["spec"],
		},
	}

	pod := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      "op-deployment-pod",
				"namespace": "test-pss",
				"uid":       "op-pod-uid",
				"ownerReferences": []any{
					map[string]any{
						"apiVersion": "apps/v1",
						"kind":       "ReplicaSet",
						"name":       "op-deployment-rs",
						"uid":        "op-rs-uid",
						"controller": true,
					},
				},
			},
			"spec": deploy.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"],
		},
	}

	ksServer := newPSSPredictorTestServer(t, deploy, rs, pod)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
		"level":     "Restricted",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])
}

// 24. Kind-qualified workload listing ignores unrelated GVR list errors (e.g. Forbidden on DaemonSets)
func TestPredictPSSCompliance_KindQualifiedWorkloadIgnoresUnrelatedListErrors(t *testing.T) {
	baseline := loadYAMLFixture(t, "testdata/pss/baseline-deployment.yaml")
	ksServer := newPSSPredictorTestServer(t, baseline)

	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	dyn.PrependReactor("list", "daemonsets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "daemonsets"}, "", errors.New("forbidden"))
	})

	// Kind-qualified request for Deployment should only list Deployments and succeed despite DaemonSets being Forbidden
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace":     "test-pss",
		"workload_name": "Deployment/baseline-deployment",
	}))
	parsed := parsePSSResult(t, result)
	summary := getSummary(t, parsed)
	assert.Equal(t, float64(1), summary["total_workloads"])

	// Namespace-wide scan attempts to list DaemonSets and returns RBAC_DENIED
	resultAll := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "predict_pss_compliance", map[string]any{
		"namespace": "test-pss",
	}))
	te := parsePSSToolError(t, resultAll)
	assert.Equal(t, ErrCodeRBACDenied, te.Code)
}
