package opaprocessor

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery/fake"
)

const (
	c0302Control   = "C-0302-danglinggatewaybackend.json"
	c0302ServiceNS = "backend"
)

// gatewayDiscovery serves the mock discovery list plus the Gateway API route
// resources. Partitioning decides whether a kind is namespaced from the
// discovery mapping, and HTTPRoute is a CRD that the built-in mock lacks:
// without it the route would be treated as cluster-scoped and land in the
// resident batch instead of its own namespace's batch.
type gatewayDiscovery struct {
	fake.FakeDiscovery
}

func (gatewayDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	list, err := k8sinterface.GetResourceListMock()
	if err != nil {
		return nil, err
	}
	return append(list, &metav1.APIResourceList{
		GroupVersion: "gateway.networking.k8s.io/v1",
		APIResources: []metav1.APIResource{{Name: "httproutes", Kind: "HTTPRoute", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
	}), nil
}

// registerGatewayResources installs the discovery mapping for the test and
// restores the shared mock mapping afterwards.
func registerGatewayResources(t *testing.T) {
	t.Helper()
	k8sinterface.InitializeMapResources(&gatewayDiscovery{})
	t.Cleanup(k8sinterface.InitializeMapResourcesMock)
}

// c0302Fixture holds an HTTPRoute in "apps" whose backendRef names namespace
// "backend", plus (optionally) the Service it points at in that namespace.
func c0302Fixture(t *testing.T, serviceExists bool) (cautils.K8SResources, map[string]workloadinterface.IMetadata) {
	t.Helper()
	raw := []string{
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"apps"}}`,
		`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"backend"}}`,
		`{"apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute","metadata":{"name":"web","namespace":"apps"},"spec":{"parentRefs":[{"name":"gw"}],"rules":[{"backendRefs":[{"name":"api","namespace":"backend","port":80}]}]}}`,
	}
	if serviceExists {
		raw = append(raw, `{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"backend"},"spec":{"ports":[{"port":80}],"selector":{"app":"api"}}}`)
	}

	k8sResources := make(cautils.K8SResources)
	allResources := make(map[string]workloadinterface.IMetadata, len(raw))
	for _, item := range raw {
		object := make(map[string]any)
		require.NoError(t, json.Unmarshal([]byte(item), &object))
		workload := workloadinterface.NewWorkloadObj(object)
		allResources[workload.GetID()] = workload

		var groupResource string
		switch workload.GetKind() {
		case "Namespace":
			groupResource = "/v1/namespaces"
		case "Service":
			groupResource = "/v1/services"
		case "HTTPRoute":
			groupResource = "gateway.networking.k8s.io/v1/httproutes"
		}
		k8sResources[groupResource] = append(k8sResources[groupResource], workload.GetID())
	}
	for groupResource := range k8sResources {
		sort.Strings(k8sResources[groupResource])
	}
	return k8sResources, allResources
}

func c0302Frameworks(t *testing.T) []reporthandling.Framework {
	t.Helper()
	control := loadLibraryControl(t, c0302Control)
	require.NotEmpty(t, control.Rules, "C-0302 must carry its Rego rule")
	return []reporthandling.Framework{{Controls: []reporthandling.Control{control}}}
}

func c0302RouteFailed(t *testing.T, opap *OPAProcessor) bool {
	t.Helper()
	var routeID string
	for id := range opap.ResourcesResult {
		if strings.Contains(id, "HTTPRoute") {
			routeID = id
		}
	}
	require.NotEmpty(t, routeID, "HTTPRoute must be reported; got %v", keysOf(opap.ResourcesResult))
	result := opap.ResourcesResult[routeID]
	for _, control := range result.AssociatedControls {
		if control.GetID() == "C-0302" {
			return control.GetStatus(nil).IsFailed()
		}
	}
	t.Fatalf("C-0302 has no result for %s", routeID)
	return false
}

func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func c0302Eager(t *testing.T, serviceExists bool) bool {
	t.Helper()
	frameworks := c0302Frameworks(t)
	policies := convertFrameworksToPolicies(frameworks, nil, reporthandling.ScopeCluster)

	k8sResources, allResources := c0302Fixture(t, serviceExists)
	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.K8SResources = k8sResources
	sessionObj.AllResources = allResources
	sessionObj.Policies = frameworks

	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	require.NoError(t, opap.Process(context.Background(), policies, nil))
	return c0302RouteFailed(t, opap)
}

func c0302Streaming(t *testing.T, serviceExists bool) bool {
	t.Helper()
	// A threshold of 1 forces every namespace into its own batch.
	t.Setenv("LARGE_CLUSTER_SIZE", "1")
	registerGatewayResources(t)

	frameworks := c0302Frameworks(t)
	k8sResources, allResources := c0302Fixture(t, serviceExists)

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.Policies = frameworks
	sessionObj.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{}
	opap := NewOPAProcessor(sessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	resident, batches := cautils.PartitionResources(len(allResources), k8sResources, nil, allResources, 1)

	// The test only proves anything if the route and its Service never share a
	// batch: each namespace must be evaluated in isolation.
	batchOf := func(kind string) string {
		for _, batch := range batches {
			for _, obj := range batch.AllResources {
				if obj.GetKind() == kind {
					return batch.Scope
				}
			}
		}
		return ""
	}
	require.Equal(t, "apps", batchOf("HTTPRoute"))
	if serviceExists {
		require.Equal(t, c0302ServiceNS, batchOf("Service"))
	}

	batchChan := make(chan *cautils.ResourceBatch, len(batches)+1)
	errChan := make(chan error, 1)
	close(errChan)
	batchChan <- resident
	for _, batch := range batches {
		batchChan <- batch
	}
	close(batchChan)

	require.NoError(t, opap.ProcessWithStreaming(context.Background(), batchChan, errChan, cautils.NewProgressHandler(""), len(batches)))
	return c0302RouteFailed(t, opap)
}

// TestC0302_CrossNamespaceBackendEagerStreamingParity runs the real C-0302
// control from the pinned regolibrary through Process and ProcessWithStreaming.
// The rule joins an HTTPRoute with a Service named by backendRef.namespace, so
// it only resolves when both are visible in one input; without the
// whole-cluster deferral, streaming evaluates the route in the "apps" batch
// where the "backend" Service is absent and reports a false positive.
func TestC0302_CrossNamespaceBackendEagerStreamingParity(t *testing.T) {
	tests := []struct {
		name          string
		serviceExists bool
		wantFailed    bool
	}{
		{name: "cross-namespace service exists", serviceExists: true, wantFailed: false},
		{name: "cross-namespace service missing", serviceExists: false, wantFailed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("eager", func(t *testing.T) {
				require.Equal(t, tt.wantFailed, c0302Eager(t, tt.serviceExists))
			})
			t.Run("streaming", func(t *testing.T) {
				require.Equal(t, tt.wantFailed, c0302Streaming(t, tt.serviceExists))
			})
		})
	}
}
