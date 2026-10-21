package resourcehandler

import (
	"context"
	"slices"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// perResourceDynamicClient answers each LIST by the resource it is for.
type perResourceDynamicClient struct {
	dynamic.Interface
	list func(gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error)
}

func (c *perResourceDynamicClient) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	return &mockNamespaceableResourceClient{listFunc: func(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
		return c.list(gvr)
	}}
}

// TestDynamicMatchHostWildcardWithEnabledCollector runs the review case of
// #4258 through the real host collector: host scanning is enabled, but node-agent
// reports no OsReleaseFile and every other host LIST is forbidden. The
// collector returns a failure status for each kind it reads and no top-level
// error, so the caller copies those statuses as they are. Control B reads host
// data with ["KubeletInfo", "*"]; every dependency recorded for it must have
// one of those statuses, otherwise B counts as evaluated with no input.
func TestDynamicMatchHostWildcardWithEnabledCollector(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}
	handler.hostSensorHandler = hostsensorutils.NewHostSensorHandlerWithClient(&perResourceDynamicClient{
		list: func(gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
			if gvr.Resource == "osreleasefiles" {
				return &unstructured.UnstructuredList{}, nil
			}
			return nil, apierrors.NewForbidden(gvr.GroupResource(), "", nil)
		},
	}, 1)

	framework := reporthandling.Framework{Controls: []reporthandling.Control{
		dynamicMatchOnControl("C-B", []string{"hostdata.kubescape.cloud"}, []string{"v1beta0"}, []string{"KubeletInfo", "*"}),
		{ControlID: "C-PODS", Rules: []reporthandling.PolicyRule{{Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}}}}},
	}}
	scanInfo := &cautils.ScanInfo{}
	scanInfo.HostSensorEnabled.SetBool(true)
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, framework)

	_, _, _, _, _ = handler.GetResources(context.Background(), sessionObj, scanInfo)

	var dependencies []string
	for gvr, controls := range sessionObj.ResourceToControlsMap {
		if slices.Contains(controls, "C-B") {
			dependencies = append(dependencies, gvr)
			assert.Contains(t, sessionObj.InfoMap, gvr, "dependency without a collection status")
		}
	}
	assert.Len(t, dependencies, len(hostsensorutils.CollectedResources()))
	assert.NotContains(t, dependencies, "hostdata.kubescape.cloud/v1beta0/KubeletConfiguration")
	assert.NotContains(t, dependencies, "hostdata.kubescape.cloud/v1beta0/KubeletCommandLine")

	coverage := cautils.BuildScanCoverage(sessionObj.InfoMap, sessionObj.ResourceToControlsMap, nil, sessionObj.PartialGVRFailures, nil, nil,
		map[string]struct{}{"C-B": {}, "C-PODS": {}})
	coverage.ComputeCoverageScore(2)

	require.Len(t, coverage.NotEvaluatedControls, 1)
	assert.Equal(t, "C-B", coverage.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, 1, coverage.EvaluatedControls)
	assert.Zero(t, coverage.SilentFailedGVRCount)
	assert.InDelta(t, 50.0, coverage.CoverageScore, 0.01)
}
