package vapreconcile

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCoverageResolvesImmutableNamespaceName(t *testing.T) {
	const nameLabel = "kubernetes.io/metadata.name"
	for _, tc := range []struct {
		name       string
		selector   map[string]any
		namespaces map[string]map[string]string
		covered    bool
	}{
		{name: "name-only selector without namespace inventory", selector: matchLabels(nameLabel, "prod"), covered: true},
		{name: "another namespace", selector: matchLabels(nameLabel, "dev")},
		{name: "namespace manifest omits automatic label", selector: matchLabels(nameLabel, "prod"), namespaces: map[string]map[string]string{"prod": {"team": "payments"}}, covered: true},
		{name: "immutable name overrides conflicting input", selector: matchLabels(nameLabel, "prod"), namespaces: map[string]map[string]string{"prod": {nameLabel: "dev"}}, covered: true},
		{name: "unknown custom labels stay unknown", selector: matchLabels(nameLabel, "prod", "team", "payments")},
		{name: "known custom labels match", selector: matchLabels(nameLabel, "prod", "team", "payments"), namespaces: map[string]map[string]string{"prod": {"team": "payments"}}, covered: true},
		{name: "known custom labels mismatch", selector: matchLabels(nameLabel, "prod", "team", "payments"), namespaces: map[string]map[string]string{"prod": {"team": "other"}}},
		{name: "name exists", selector: map[string]any{"matchExpressions": []any{map[string]any{"key": nameLabel, "operator": "Exists"}}}, covered: true},
		{name: "name cannot be absent", selector: map[string]any{"matchExpressions": []any{map[string]any{"key": nameLabel, "operator": "DoesNotExist"}}}},
		{name: "name in set", selector: map[string]any{"matchExpressions": []any{map[string]any{"key": nameLabel, "operator": "In", "values": []any{"prod", "staging"}}}}, covered: true},
		{name: "name not in excluded set", selector: map[string]any{"matchExpressions": []any{map[string]any{"key": nameLabel, "operator": "NotIn", "values": []any{"dev"}}}}, covered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := []unstructured.Unstructured{makeVAP("policy", "C-0001")}
			bindings := []unstructured.Unstructured{makeVAPBScoped("binding", "policy", tc.selector, nil)}
			failing := map[string][]ResourceInfo{"C-0001": {{ResourceID: "pod", APIVersion: "v1", Kind: "Pod", Namespace: "prod"}}}
			coverage := BuildCoverage(policies, bindings, failing, tc.namespaces)["C-0001"]
			require.True(t, coverage.Bound)
			require.Equal(t, tc.covered, coverage.FullyCovered())
			require.Equal(t, tc.covered, coverage.Resources[0].Covered)
			if !tc.covered {
				require.NotEmpty(t, coverage.Resources[0].Reason)
			}
			if tc.name == "immutable name overrides conflicting input" {
				require.Equal(t, "dev", tc.namespaces["prod"][nameLabel], "coverage must not mutate collected labels")
			}
		})
	}
}

func TestCoverageInfersNameForNamespaceObject(t *testing.T) {
	for _, name := range []string{"prod", "dev"} {
		policies := []unstructured.Unstructured{makeVAP("policy", "C-0001")}
		bindings := []unstructured.Unstructured{makeVAPBScoped("binding", "policy", matchLabels("kubernetes.io/metadata.name", "prod"), nil)}
		resource := ResourceInfo{ResourceID: "namespace", APIVersion: "v1", Kind: "Namespace", Name: name}
		coverage := BuildCoverage(policies, bindings, map[string][]ResourceInfo{"C-0001": {resource}}, nil)["C-0001"]
		require.Equal(t, name == "prod", coverage.Resources[0].Covered)
	}
}

func TestCollectedCoverageResourcesKeepNamespaceObjectName(t *testing.T) {
	resource := workloadinterface.NewWorkloadObj(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "prod"}})
	resourceID := resource.GetID()
	failed := resourcesresults.ResourceAssociatedControl{ControlID: "C-0001", ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Status: apis.StatusFailed}}}
	byControl := CollectFailingResourcesByControl(nil, map[string]resourcesresults.Result{resourceID: {AssociatedControls: []resourcesresults.ResourceAssociatedControl{failed}}}, map[string]workloadinterface.IMetadata{resourceID: resource})
	require.Len(t, byControl["C-0001"], 1)
	require.Equal(t, "prod", byControl["C-0001"][0].Name)
	coverage := BuildCoverage([]unstructured.Unstructured{makeVAP("policy", "C-0001")}, []unstructured.Unstructured{makeVAPBScoped("binding", "policy", matchLabels("kubernetes.io/metadata.name", "prod"), nil)}, byControl, nil)
	require.True(t, coverage["C-0001"].FullyCovered())
}
