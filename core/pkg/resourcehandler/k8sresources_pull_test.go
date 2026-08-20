package resourcehandler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/hostsensor"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

type mockDynamicClient struct {
	dynamic.Interface
	listFunc func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockDynamicClient) Resource(resource schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &mockNamespaceableResourceClient{listFunc: m.listFunc}
}

type mockNamespaceableResourceClient struct {
	dynamic.NamespaceableResourceInterface
	listFunc func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
}

func (m *mockNamespaceableResourceClient) Namespace(s string) dynamic.ResourceInterface {
	return m
}

func (m *mockNamespaceableResourceClient) List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return m.listFunc(ctx, opts)
}

func TestPullResources_PartialFailureSurface(t *testing.T) {
	mockErr := errors.New("simulated API failure")
	mockClient := &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if opts.FieldSelector == "metadata.name=fail" {
				return nil, mockErr
			}
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{
					{
						Object: map[string]any{
							"apiVersion": "v1",
							"kind":       "Pod",
							"metadata": map[string]any{
								"name":      "test-pod",
								"namespace": "default",
							},
						},
					},
				},
			}, nil
		},
	}

	k8sApi := &k8sinterface.KubernetesApi{
		DynamicClient: mockClient,
	}

	handler := &K8sResourceHandler{
		k8s: k8sApi,
	}

	queryableResources := QueryableResources{
		"//v1/configmaps/metadata.name=ok": QueryableResource{
			GroupVersionResourceTriplet: "//v1/configmaps",
			FieldSelectors:              "metadata.name=ok",
		},
		"//v1/configmaps/metadata.name=fail": QueryableResource{
			GroupVersionResourceTriplet: "//v1/configmaps",
			FieldSelectors:              "metadata.name=fail",
		},
	}

	k8sResourcesMap, allResources, failedQueries := handler.pullResources(context.Background(), queryableResources, &EmptySelector{})

	// Verify that the successful selector populated the shared raw-GVR bucket.
	assert.Len(t, allResources, 1)
	assert.Len(t, k8sResourcesMap["//v1/configmaps"], 1)

	// Verify that the failed selector is retained under its selector-qualified key.
	assert.Len(t, failedQueries, 1)
	fq, ok := failedQueries["//v1/configmaps/metadata.name=fail"]
	assert.True(t, ok, "expected failed query key to include the field selector")
	assert.Equal(t, "//v1/configmaps", fq.gvr)
	assert.ErrorContains(t, fq.err, "simulated API failure")
}

func TestGetResources_SurfacesMissingGVRFailuresInInfoMap(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			if opts.FieldSelector != "" {
				return nil, errors.New("simulated API failure")
			}
			return &unstructured.UnstructuredList{
				Items: []unstructured.Unstructured{{
					Object: map[string]any{
						"apiVersion": "v1",
						"kind":       "Namespace",
						"metadata": map[string]any{
							"name": "default",
						},
					},
				}},
			}, nil
		},
	}

	rule := mockRule("rule-a", nil, "")
	rule.Match = append(rule.Match, mockMatch(6), mockMatch(4))
	control := mockControl("control-1", nil)
	control.Rules = append(control.Rules, rule)
	framework := mockFramework("test", nil)
	framework.Controls = append(framework.Controls, control)

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	assert.NoError(t, err)

	info, ok := sessionObj.InfoMap["core/v1/secrets"]
	assert.True(t, ok, "expected missing secrets GVR to be surfaced in InfoMap")
	assert.Contains(t, info.InnerInfo, "simulated API failure")
}

func TestGetResources_FailsWhenAllQueriesFail(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return nil, errors.New("simulated API failure")
		},
	}

	rule := mockRule("rule-a", nil, "")
	rule.Match = append(rule.Match, mockMatch(4))
	control := mockControl("control-1", nil)
	control.Rules = append(control.Rules, rule)
	framework := mockFramework("test", nil)
	framework.Controls = append(framework.Controls, control)

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	assert.ErrorContains(t, err, "failed to pull any Kubernetes resources")
	assert.ErrorContains(t, err, "simulated API failure")
}

// TestGetResources_ScanAbortedOnContextCancellation verifies that when the
// scan context is cancelled (e.g. by a --scan-timeout expiry), GetResources
// returns a "scan aborted" error that explicitly wraps the context error.
// This gives users a clear, actionable message instead of a confusing
// "failed to pull any Kubernetes resources" message.
func TestGetResources_ScanAbortedOnContextCancellation(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()

	// List function blocks until its context is done, simulating a slow API.
	hangForever := make(chan struct{})
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			select {
			case <-hangForever:
				return &unstructured.UnstructuredList{}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	rule := mockRule("rule-a", nil, "")
	rule.Match = append(rule.Match, mockMatch(4))
	control := mockControl("control-1", nil)
	control.Rules = append(control.Rules, rule)
	framework := mockFramework("test", nil)
	framework.Controls = append(framework.Controls, control)

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, _, _, err := handler.GetResources(ctx, sessionObj, scanInfo)
	require.Error(t, err)
	assert.ErrorContains(t, err, "scan aborted",
		"timeout error should say 'scan aborted', not 'failed to pull any Kubernetes resources'")
	assert.True(t,
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"error should wrap the context error so callers can use errors.Is(err, context.DeadlineExceeded)")
}

type stubHostSensor struct {
	infoMap map[string]apis.StatusInfo
}

func (s *stubHostSensor) Init(_ context.Context) error { return nil }
func (s *stubHostSensor) TearDown() error              { return nil }
func (s *stubHostSensor) CollectResources(_ context.Context) ([]hostsensor.HostSensorDataEnvelope, map[string]apis.StatusInfo, error) {
	return nil, s.infoMap, nil
}

// TestGetResources_HostSensorInfoMapMerged is a regression test for the bug
// where the host-sensor infoMap replaced sessionObj.InfoMap wholesale instead
// of being merged into it, silently discarding GVR pull-failure entries that
// recordFailedQueryStatuses had written earlier.
func TestGetResources_HostSensorInfoMapMerged(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	handler.hostSensorHandler = &stubHostSensor{
		infoMap: map[string]apis.StatusInfo{
			"KubeletInfo": {InnerStatus: apis.StatusSkipped, InnerInfo: "node-1: connection refused"},
		},
	}

	rule := mockRule("host-sensor-rule", nil, "")
	rule.Match = []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"KubeletInfo"},
	}}
	control := mockControl("host-control", nil)
	control.Rules = []reporthandling.PolicyRule{rule}
	framework := mockFramework("host-framework", nil)
	framework.Controls = []reporthandling.Control{control}

	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	sessionObj.Policies = append(sessionObj.Policies, *framework)

	const preSeededGVR = "/v1/networkpolicies"
	sessionObj.InfoMap[preSeededGVR] = apis.StatusInfo{
		InnerInfo:   "networkpolicies is forbidden",
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusNotEvaluated,
	}

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	_, ok := sessionObj.InfoMap[preSeededGVR]
	assert.True(t, ok, "GVR pull-failure entry must survive host-sensor collection; host infoMap must be merged, not replace sessionObj.InfoMap")

	_, ok = sessionObj.InfoMap["KubeletInfo"]
	assert.True(t, ok, "host-sensor infoMap entries must be present in sessionObj.InfoMap after merge")
}
