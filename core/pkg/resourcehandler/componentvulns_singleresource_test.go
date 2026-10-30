package resourcehandler

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Both public collection paths skip component vulnerabilities for a
// single-workload scan without listing nodes or loading the DB.
func TestSingleResourceScanSkipsComponentVulnerabilities(t *testing.T) {
	for name, collect := range map[string]func(*K8sResourceHandler, *cautils.OPASessionObj, *cautils.ScanInfo){
		"GetResources": func(h *K8sResourceHandler, s *cautils.OPASessionObj, si *cautils.ScanInfo) {
			_, _, _, _, _ = h.GetResources(context.Background(), s, si)
		},
		"StreamResourcesBatches": func(h *K8sResourceHandler, s *cautils.OPASessionObj, si *cautils.ScanInfo) {
			batches, errs, _, err := h.StreamResourcesBatches(context.Background(), s, si)
			if err != nil {
				return
			}
			for range batches {
			}
			for range errs {
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			k8sinterface.InitializeMapResourcesMock()
			handler := getResourceHandlerMock()
			handler.k8s.DynamicClient = &mockDynamicClient{
				listFunc: func(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error) {
					return &unstructured.UnstructuredList{}, nil
				},
			}
			handler.componentVulnSources = func(context.Context, *cautils.ScanInfo) (componentVulnSources, error) {
				t.Fatal("vulnerability database loaded for a single workload scan")
				return componentVulnSources{}, nil
			}

			// A deleted scan object is resolved from the object itself, so
			// the scan stays single-workload without a cluster lookup.
			scanInfo := &cautils.ScanInfo{ScanObject: scanObject("apps/v1", "Deployment", "default", "web"), IsDeletedScanObject: true}
			sessionObj := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
			sessionObj.Policies = []reporthandling.Framework{{Controls: []reporthandling.Control{componentVulnControl("C-RUNTIME", "ContainerRuntimeVulnerabilities")}}}

			collect(handler, sessionObj, scanInfo)

			require.NotNil(t, sessionObj.SingleResourceScan)

			require.Contains(t, sessionObj.InfoMap, runtimeVulnsGVR)
			assert.Equal(t, apis.StatusSkipped, sessionObj.InfoMap[runtimeVulnsGVR].InnerStatus)
			assert.Empty(t, sessionObj.PartialGVRFailures)
		})
	}
}
