package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	mappedHostGVR    = "hostdata.kubescape.cloud/v1beta0/KubeletInfo"
	unrelatedHostGVR = "hostdata.kubescape.cloud/v1beta0/KubeProxyInfo"
)

// hostFilterFramework selects only a KubeletInfo-dependent control, so a
// KubeProxyInfo conversion gap is unrelated to the scan.
func hostFilterFramework() *reporthandling.Framework {
	rule := mockRule("kubelet-rule", nil, "")
	rule.Match = []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{""},
		APIVersions: []string{"v1"},
		Resources:   []string{"KubeletInfo"},
	}}
	control := mockControl("kubelet-control", nil)
	control.Rules = []reporthandling.PolicyRule{rule}
	framework := mockFramework("host-filter-framework", nil)
	framework.Controls = []reporthandling.Control{control}
	return framework
}

// TestGetResources_HostPartialUnrelatedToSelectedControlsNotPenalized is the
// eager-path regression for the scope defect: CollectResources queries every
// host resource, but only gaps for GVRs a selected control depends on may
// reach PartialGVRFailures and the coverage penalty. An unrelated unreadable
// host CRD must not fail --fail-coverage-below when every requested control
// was fully evaluated.
func TestGetResources_HostPartialUnrelatedToSelectedControlsNotPenalized(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	handler.hostSensorHandler = &stubHostSensor{
		partials: []cautils.PartialGVRPull{
			{GVR: mappedHostGVR, Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
			{GVR: unrelatedHostGVR, Selector: "conversion", Error: "node-agent reported 2 KubeProxyInfo but only 1 could be read"},
		},
	}

	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *hostFilterFramework())

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	require.Contains(t, sessionObj.ResourceToControlsMap, mappedHostGVR,
		"precondition: the selected control must map the KubeletInfo GVR")
	require.NotContains(t, sessionObj.ResourceToControlsMap, unrelatedHostGVR,
		"precondition: no selected control may map the KubeProxyInfo GVR")
	require.Len(t, sessionObj.PartialGVRFailures, 1,
		"only the mapped host gap may reach the session; the unrelated gap keeps its warning but no penalty")
	assert.Equal(t, mappedHostGVR, sessionObj.PartialGVRFailures[0].GVR)

	coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
	require.Len(t, coverage.PartialGVRPulls, 1)
	assert.Equal(t, mappedHostGVR, coverage.PartialGVRPulls[0].GVR)
}

// TestGetResources_HostPartialOnlyUnrelatedKeepsFullCoverage covers the gate
// scenario directly: the scan selects only a KubeletInfo-dependent control
// with complete KubeletInfo, and the only gap is an unrelated KubeProxyInfo
// conversion. Coverage must stay at 100 so --fail-coverage-below=100 passes.
func TestGetResources_HostPartialOnlyUnrelatedKeepsFullCoverage(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(_ context.Context, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	handler.hostSensorHandler = &stubHostSensor{
		partials: []cautils.PartialGVRPull{
			{GVR: unrelatedHostGVR, Selector: "conversion", Error: "node-agent reported 2 KubeProxyInfo but only 1 could be read"},
		},
	}

	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *hostFilterFramework())

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	assert.Empty(t, sessionObj.PartialGVRFailures,
		"an unrelated host gap must not reach the session")

	coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil)
	assert.Empty(t, coverage.PartialGVRPulls)
	coverage.ComputeCoverageScore(1)
	assert.Equal(t, float32(100), coverage.CoverageScore)
	assert.False(t, coverage.Degraded)
}

// TestCollectAndStreamBatches_HostPartialUnrelatedToSelectedControlsNotPenalized
// is the streaming-path mirror: the same filter must apply when host
// collection runs inside collectAndStreamBatches.
func TestCollectAndStreamBatches_HostPartialUnrelatedToSelectedControlsNotPenalized(t *testing.T) {
	ctx := context.Background()
	handler := getResourceHandlerMock()
	handler.hostSensorHandler = &stubHostSensor{
		partials: []cautils.PartialGVRPull{
			{GVR: mappedHostGVR, Selector: "conversion", Error: "node-agent reported 2 KubeletInfo but only 1 could be read"},
			{GVR: unrelatedHostGVR, Selector: "conversion", Error: "node-agent reported 2 KubeProxyInfo but only 1 could be read"},
		},
	}
	scanInfo, session := streamingTestSession(ctx)
	session.Metadata.ScanMetadata.HostScanner = true
	framework := hostFilterFramework()
	session.Policies = append(session.Policies, *framework)
	// Map by the control's real ID (whatever the mock carries) so the
	// fixture stays consistent with the effective-control predicate, which
	// reads Policies — not just the map.
	session.ResourceToControlsMap = map[string][]string{mappedHostGVR: {framework.Controls[0].ControlID}}
	batches := make(chan *cautils.ResourceBatch, 1)

	err := handler.collectAndStreamBatches(
		ctx,
		QueryableResources{},
		&EmptySelector{},
		session,
		scanInfo,
		cautils.ExternalResources{mappedHostGVR: nil, unrelatedHostGVR: nil},
		batches,
		nil,
	)

	require.NoError(t, err)
	require.Len(t, session.PartialGVRFailures, 1,
		"only the mapped host gap may reach the session; the unrelated gap keeps its warning but no penalty")
	assert.Equal(t, mappedHostGVR, session.PartialGVRFailures[0].GVR)

	coverage := cautils.BuildScanCoverage(session.InfoMap, session.ResourceToControlsMap, nil, session.PartialGVRFailures, nil, nil)
	require.Len(t, coverage.PartialGVRPulls, 1)
	assert.Equal(t, mappedHostGVR, coverage.PartialGVRPulls[0].GVR)
}
