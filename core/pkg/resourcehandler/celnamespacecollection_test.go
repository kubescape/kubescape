package resourcehandler

import (
	"context"
	"sync"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func celNamespaceTestFramework() reporthandling.Framework {
	rule := mockCELRule("cel-deployment", []reporthandling.RuleMatchObjects{mockMatch(2)})
	return *mockFramework("cel-test", []reporthandling.Control{mockControl("cel-control", []reporthandling.PolicyRule{rule})})
}

// namespaceContextReactor models the important distinction: the workload
// matches app=web, while its Namespace has no such label. A regular scan query
// therefore sees no Namespace; a support lookup with no label selector does.
func namespaceContextReactor(t *testing.T, namespaceLabels *[]string, mu *sync.Mutex) k8stesting.ReactionFunc {
	t.Helper()
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		require.True(t, ok)
		labels := listAction.GetListRestrictions().Labels.String()
		switch action.GetResource().Resource {
		case "namespaces":
			mu.Lock()
			*namespaceLabels = append(*namespaceLabels, labels)
			mu.Unlock()
			if labels != "" {
				return true, &unstructured.UnstructuredList{}, nil
			}
			return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: map[string]any{
				"apiVersion": "v1", "kind": "Namespace",
				"metadata": map[string]any{"name": "team-a", "labels": map[string]any{"tier": "prod"}},
			}}}}, nil
		case "deployments":
			if labels != "" && labels != "app=web" {
				return true, &unstructured.UnstructuredList{}, nil
			}
			return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{Object: map[string]any{
				"apiVersion": "apps/v1", "kind": "Deployment",
				"metadata": map[string]any{"name": "web", "namespace": "team-a", "labels": map[string]any{"app": "web"}},
			}}}}, nil
		default:
			return true, &unstructured.UnstructuredList{}, nil
		}
	}
}

func TestGetResourcesCollectsNamespaceContextOutsideWorkloadFilters(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	for _, tt := range []struct {
		name         string
		label        string
		includeKinds string
	}{
		{name: "workload label selector", label: "app=web"},
		{name: "workload kind filter", includeKinds: "Deployment"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var namespaceLabels []string
			handler := newHandlerWithReactor(t, namespaceContextReactor(t, &namespaceLabels, &mu))
			scanInfo := &cautils.ScanInfo{LabelSelector: tt.label, IncludeKinds: tt.includeKinds}
			session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
			session.Policies = []reporthandling.Framework{celNamespaceTestFramework()}

			resources, allResources, _, _, err := handler.GetResources(context.Background(), session, scanInfo)
			require.NoError(t, err)
			assert.NotEmpty(t, resources["apps/v1/deployments"], "the requested workload stays a scan target")
			assert.Empty(t, resources["/v1/namespaces"], "support context is not another scan target")
			assert.Len(t, allResources, 1, "support context is not a report resource")
			var foundNamespace bool
			for _, resource := range session.CELNamespaceContext {
				if resource.GetKind() == "Namespace" && resource.GetName() == "team-a" {
					foundNamespace = true
					assert.Equal(t, "prod", resource.GetObject()["metadata"].(map[string]any)["labels"].(map[string]any)["tier"])
				}
			}
			assert.True(t, foundNamespace, "the processor must receive Namespace labels for namespaceObject")
			assert.Contains(t, namespaceLabels, "", "support collection must bypass the workload label selector")
		})
	}
}

func TestStreamingCollectionCarriesSupplementalNamespaceContext(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	ctx := context.Background()
	var mu sync.Mutex
	var namespaceLabels []string
	handler := newHandlerWithReactor(t, namespaceContextReactor(t, &namespaceLabels, &mu))
	scanInfo, session := streamingTestSession(ctx)
	scanInfo.LabelSelector = "app=web"
	session.Policies = []reporthandling.Framework{celNamespaceTestFramework()}
	queryable, _ := getQueryableResourceMapFromPolicies(session.Policies, nil, reporthandling.ScopeCluster, defaultResourceResolver)
	batches := make(chan *cautils.ResourceBatch, 3)

	err := handler.collectAndStreamBatches(ctx, queryable, &EmptySelector{}, session, scanInfo,
		cautils.ExternalResources{}, batches, defaultResourceResolver)
	require.NoError(t, err)
	require.NotEmpty(t, batches)
	resident := <-batches
	assert.Contains(t, namespaceLabels, "")
	assert.Empty(t, resident.K8SResources["/v1/namespaces"], "Namespace context must not become a policy target")
	var foundNamespace bool
	assert.Empty(t, resident.AllResources, "the resident report catalog must not contain support-only Namespaces")
	for _, resource := range resident.CELNamespaceContext {
		if resource.GetKind() == "Namespace" && resource.GetName() == "team-a" {
			foundNamespace = true
		}
	}
	assert.True(t, foundNamespace, "the first batch must carry Namespace context before workload evaluation")
}

func TestCollectResourcesRejectsEmptyLabelFilteredCELScan(t *testing.T) {
	k8sinterface.InitializeMapResourcesMock()
	var mu sync.Mutex
	var namespaceLabels []string
	handler := newHandlerWithReactor(t, namespaceContextReactor(t, &namespaceLabels, &mu))
	scanInfo := &cautils.ScanInfo{LabelSelector: "app=missing"}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	session.Policies = []reporthandling.Framework{celNamespaceTestFramework()}

	err := CollectResources(context.Background(), handler, session, scanInfo)
	require.ErrorContains(t, err, "no resources found to scan")
	assert.Empty(t, session.AllResources)
	assert.NotEmpty(t, session.CELNamespaceContext, "Namespace context was available but is not a scan target")
}

func TestSupplementalNamespaceContextRequiresCELAndNarrowing(t *testing.T) {
	celPolicies := []reporthandling.Framework{celNamespaceTestFramework()}
	regoPolicies := []reporthandling.Framework{*mockFramework("rego-test", []reporthandling.Control{
		mockControl("rego-control", []reporthandling.PolicyRule{mockRule("rego-deployment", []reporthandling.RuleMatchObjects{mockMatch(2)}, "")}),
	})}
	assert.False(t, needsSupplementalCELNamespaces(&cautils.ScanInfo{}, celPolicies))
	assert.True(t, needsSupplementalCELNamespaces(&cautils.ScanInfo{LabelSelector: "app=web"}, celPolicies))
	assert.True(t, needsSupplementalCELNamespaces(&cautils.ScanInfo{IncludeKinds: "Deployment"}, celPolicies))
	assert.False(t, needsSupplementalCELNamespaces(&cautils.ScanInfo{LabelSelector: "app=web"}, regoPolicies))
	assert.False(t, needsSupplementalCELNamespaces(&cautils.ScanInfo{LabelSelector: "app=web"}, nil))
}
