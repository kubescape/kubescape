package resourcehandler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func agentRuntimeMatches() []reporthandling.RuleMatchObjects {
	return []reporthandling.RuleMatchObjects{
		{
			APIGroups:   []string{"agents.x-k8s.io"},
			APIVersions: []string{"v1alpha1", "v1beta1"},
			Resources:   []string{"Sandbox"},
		},
		{
			APIGroups:   []string{"extensions.agents.x-k8s.io"},
			APIVersions: []string{"v1alpha1", "v1beta1"},
			Resources:   []string{"SandboxTemplate"},
		},
		{
			APIGroups:   []string{"ate.dev"},
			APIVersions: []string{"v1alpha1"},
			Resources:   []string{"ActorTemplate", "WorkerPool"},
		},
	}
}

func agentRuntimeFramework() reporthandling.Framework {
	rule := mockRule("agent-runtime-crds", agentRuntimeMatches(), "")
	control := mockControl("agent-runtime-control", []reporthandling.PolicyRule{rule})
	return *mockFramework("agent-runtime", []reporthandling.Control{control})
}

func TestResolveResourceGroupsAgentRuntimeCRDs(t *testing.T) {
	tests := []struct {
		group    string
		version  string
		resource string
		want     string
	}{
		{group: "agents.x-k8s.io", version: "v1alpha1", resource: "Sandbox", want: "agents.x-k8s.io/v1alpha1/sandboxes"},
		{group: "agents.x-k8s.io", version: "v1beta1", resource: "Sandbox", want: "agents.x-k8s.io/v1beta1/sandboxes"},
		{group: "extensions.agents.x-k8s.io", version: "v1alpha1", resource: "SandboxTemplate", want: "extensions.agents.x-k8s.io/v1alpha1/sandboxtemplates"},
		{group: "extensions.agents.x-k8s.io", version: "v1beta1", resource: "SandboxTemplate", want: "extensions.agents.x-k8s.io/v1beta1/sandboxtemplates"},
		{group: "ate.dev", version: "v1alpha1", resource: "ActorTemplate", want: "ate.dev/v1alpha1/actortemplates"},
		{group: "ate.dev", version: "v1alpha1", resource: "WorkerPool", want: "ate.dev/v1alpha1/workerpools"},
		{group: "ate.dev", version: "v1alpha1", resource: "actortemplates", want: "ate.dev/v1alpha1/actortemplates"},
	}

	for _, test := range tests {
		t.Run(test.resource+"_"+test.version, func(t *testing.T) {
			assert.Equal(t, []string{test.want}, resolveResourceGroups(test.group, test.version, test.resource))
		})
	}
}

func TestAgentRuntimeCRDResourceToControlKeysMatchQueries(t *testing.T) {
	framework := agentRuntimeFramework()
	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{framework},
		nil,
		reporthandling.ScopeCluster,
	)
	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls)

	for query := range queryable {
		assert.Containsf(t, resourceToControls, query,
			"resource collection failures for %s must map back to the affected control", query)
	}
}

func TestFileResourceHandlerCollectsAgentRuntimeCRDs(t *testing.T) {
	manifest := `apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: alpha-sandbox
  namespace: agents
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: hardened-template
  namespace: agents
---
apiVersion: ate.dev/v1alpha1
kind: ActorTemplate
metadata:
  name: code-runner
  namespace: agents
---
apiVersion: ate.dev/v1alpha1
kind: WorkerPool
metadata:
  name: shared-workers
  namespace: agents
`
	manifestPath := filepath.Join(t.TempDir(), "agent-runtime.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo)
	session.Policies = []reporthandling.Framework{agentRuntimeFramework()}

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 4)

	expected := map[string]string{
		"agents.x-k8s.io/v1alpha1/sandboxes":                  "Sandbox",
		"extensions.agents.x-k8s.io/v1beta1/sandboxtemplates": "SandboxTemplate",
		"ate.dev/v1alpha1/actortemplates":                     "ActorTemplate",
		"ate.dev/v1alpha1/workerpools":                        "WorkerPool",
	}
	for resourceGroup, kind := range expected {
		require.Lenf(t, resources[resourceGroup], 1, "expected one %s under %s", kind, resourceGroup)
		assert.Equal(t, kind, allResources[resources[resourceGroup][0]].GetKind())
	}
}

func TestK8sResourceHandlerCollectsAgentRuntimeCRDs(t *testing.T) {
	objects := map[schema.GroupVersionResource]*unstructured.Unstructured{
		{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}:                   unstructuredResource("agents.x-k8s.io/v1beta1", "Sandbox", "agents", "live-sandbox"),
		{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxtemplates"}: unstructuredResource("extensions.agents.x-k8s.io/v1beta1", "SandboxTemplate", "agents", "live-template"),
		{Group: "ate.dev", Version: "v1alpha1", Resource: "actortemplates"}:                     unstructuredResource("ate.dev/v1alpha1", "ActorTemplate", "agents", "live-actor-template"),
		{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"}:                        unstructuredResource("ate.dev/v1alpha1", "WorkerPool", "agents", "live-worker-pool"),
	}
	listKinds := map[schema.GroupVersionResource]string{
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"}:                   "SandboxList",
		{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}:                    "SandboxList",
		{Group: "extensions.agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxtemplates"}: "SandboxTemplateList",
		{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxtemplates"}:  "SandboxTemplateList",
		{Group: "ate.dev", Version: "v1alpha1", Resource: "actortemplates"}:                      "ActorTemplateList",
		{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"}:                         "WorkerPoolList",
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object, ok := objects[action.GetResource()]
		if !ok {
			return true, &unstructured.UnstructuredList{}, nil
		}
		return true, &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*object}}, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{DynamicClient: dynamicClient}}

	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{agentRuntimeFramework()},
		nil,
		reporthandling.ScopeCluster,
	)
	resources, allResources, failures := handler.pullResources(context.Background(), queryable, &EmptySelector{})

	assert.Empty(t, failures)
	require.Len(t, allResources, 4)
	assert.Len(t, resources["agents.x-k8s.io/v1beta1/sandboxes"], 1)
	assert.Len(t, resources["extensions.agents.x-k8s.io/v1beta1/sandboxtemplates"], 1)
	assert.Len(t, resources["ate.dev/v1alpha1/actortemplates"], 1)
	assert.Len(t, resources["ate.dev/v1alpha1/workerpools"], 1)
}
