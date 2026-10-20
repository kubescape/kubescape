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

// listedGVRsSession returns a session whose framework lists Pods without a
// field selector and HTTPRoutes only with one.
func listedGVRsSession() (*K8sResourceHandler, *cautils.OPASessionObj, *cautils.ScanInfo) {
	k8sinterface.InitializeMapResourcesMock()
	handler := getResourceHandlerMock()
	handler.k8s.DiscoveryClient = clusterWithGatewayAPIDiscovery()
	handler.k8s.DynamicClient = &mockDynamicClient{
		listFunc: func(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error) {
			return &unstructured.UnstructuredList{}, nil
		},
	}

	rule := mockRule("rule-a", []reporthandling.RuleMatchObjects{
		{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"}},
		{APIGroups: []string{"gateway.networking.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"HTTPRoute"}, FieldSelector: []string{"metadata.name=route1"}},
	}, "")
	framework := mockFramework("test", []reporthandling.Control{mockControl("control-1", []reporthandling.PolicyRule{rule})})

	scanInfo := &cautils.ScanInfo{}
	sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	sessionObj.Policies = append(sessionObj.Policies, *framework)
	return handler, sessionObj, scanInfo
}

var wantListedGVRs = map[string]bool{
	"/v1/pods": true,
	"gateway.networking.k8s.io/v1/httproutes": false,
}

func TestGetResources_RecordsListedGVRs(t *testing.T) {
	handler, sessionObj, scanInfo := listedGVRsSession()

	_, _, _, _, err := handler.GetResources(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)

	assert.Equal(t, wantListedGVRs, sessionObj.ListedGVRs)
}

func TestStreamResourcesBatches_RecordsListedGVRs(t *testing.T) {
	handler, sessionObj, scanInfo := listedGVRsSession()

	batchChan, errChan, _, err := handler.StreamResourcesBatches(context.Background(), sessionObj, scanInfo)
	require.NoError(t, err)
	for range batchChan {
	}
	require.NoError(t, <-errChan)

	assert.Equal(t, wantListedGVRs, sessionObj.ListedGVRs)
}
