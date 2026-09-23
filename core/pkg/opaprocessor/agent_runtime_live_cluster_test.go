package opaprocessor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAgentRuntimeLiveClusterCollectionReachesPolicyEvaluation(t *testing.T) {
	ctx := context.Background()
	const sandboxUID = "11111111-1111-1111-1111-111111111111"

	sandboxAlpha := schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"}
	sandboxBeta := schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}
	actorTemplate := schema.GroupVersionResource{Group: "ate.dev", Version: "v1alpha1", Resource: "actortemplates"}
	workerPool := schema.GroupVersionResource{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"}
	vap := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}
	vapBinding := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicybindings"}

	listKinds := map[schema.GroupVersionResource]string{
		sandboxAlpha:  "SandboxList",
		sandboxBeta:   "SandboxList",
		actorTemplate: "ActorTemplateList",
		workerPool:    "WorkerPoolList",
		vap:           "ValidatingAdmissionPolicyList",
		vapBinding:    "ValidatingAdmissionPolicyBindingList",
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		gvr := action.GetResource()
		if gvr == vap || gvr == vapBinding {
			return true, &unstructured.UnstructuredList{}, nil
		}

		switch gvr {
		case sandboxAlpha:
			return true, agentRuntimeList(agentRuntimeObject("agents.x-k8s.io/v1alpha1", "Sandbox", "shared-sandbox", sandboxUID)), nil
		case sandboxBeta:
			return true, agentRuntimeList(agentRuntimeObject("agents.x-k8s.io/v1beta1", "Sandbox", "shared-sandbox", sandboxUID)), nil
		case actorTemplate:
			return true, agentRuntimeList(agentRuntimeObject("ate.dev/v1alpha1", "ActorTemplate", "code-runner", "22222222-2222-2222-2222-222222222222")), nil
		case workerPool:
			return true, nil, apierrors.NewForbidden(
				schema.GroupResource{Group: workerPool.Group, Resource: workerPool.Resource},
				"", errors.New("worker pools are not permitted"),
			)
		default:
			return true, nil, fmt.Errorf("unexpected live-cluster list request for %s", gvr)
		}
	})

	resourceLists := []*metav1.APIResourceList{
		{GroupVersion: "agents.x-k8s.io/v1alpha1", APIResources: []metav1.APIResource{{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}},
		{GroupVersion: "agents.x-k8s.io/v1beta1", APIResources: []metav1.APIResource{{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}},
		{GroupVersion: "ate.dev/v1alpha1", APIResources: []metav1.APIResource{
			{Name: "actortemplates", Kind: "ActorTemplate", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
			{Name: "workerpools", Kind: "WorkerPool", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
		}},
	}
	discoveryClient := &agentRuntimePartialDiscovery{
		FakeDiscovery: &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}, FakedServerVersion: &version.Info{GitVersion: "v1.34.0"}},
		resources:     resourceLists,
	}
	k8s := &k8sinterface.KubernetesApi{
		KubernetesClient: kubernetesfake.NewClientset(),
		DynamicClient:    dynamicClient,
		DiscoveryClient:  discoveryClient,
		Context:          ctx,
	}
	handler := resourcehandler.NewK8sResourceHandler(ctx, k8s, nil, nil, "test-cluster")

	framework := agentRuntimeLiveFramework()
	scanInfo := &cautils.ScanInfo{IncludeNamespaces: "agents"}
	session := cautils.NewOPASessionObj(ctx, []reporthandling.Framework{framework}, nil, scanInfo, nil)
	session.Metadata.ContextMetadata.ClusterContextMetadata = &reporthandlingv2.ClusterMetadata{ContextName: "test-cluster"}

	require.NoError(t, resourcehandler.CollectResources(ctx, handler, session, scanInfo))
	require.Len(t, session.AllResources, 2, "the Sandbox served at two versions must be collected once")
	assert.Contains(t, session.AllResources, "agents.x-k8s.io/v1beta1/agents/Sandbox/shared-sandbox")
	assert.Contains(t, session.AllResources, "ate.dev/v1alpha1/agents/ActorTemplate/code-runner")
	assert.NotContains(t, session.AllResources, "agents.x-k8s.io/v1alpha1/agents/Sandbox/shared-sandbox")

	require.Len(t, session.ScanCoverage.FailedGVRPulls, 1)
	assert.Equal(t, "ate.dev/v1alpha1/workerpools", session.ScanCoverage.FailedGVRPulls[0].GVR)
	assert.Contains(t, session.ScanCoverage.FailedGVRPulls[0].Error, "worker pools are not permitted")
	require.Len(t, session.ScanCoverage.PartialGVRPulls, 1)
	assert.Equal(t, "discovery:extensions.agents.x-k8s.io/v1beta1", session.ScanCoverage.PartialGVRPulls[0].GVR)
	assertAgentRuntimeListRequests(t, dynamicClient.Actions(), sandboxAlpha, sandboxBeta, actorTemplate, workerPool)

	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test-cluster", "", "agents", false, nil)
	require.NoError(t, processor.ProcessRulesListener(ctx, cautils.NewProgressHandler("")))

	require.Len(t, session.ResourcesResult, 2)
	assert.Contains(t, session.ResourcesResult, "agents.x-k8s.io/v1beta1/agents/Sandbox/shared-sandbox")
	assert.Contains(t, session.ResourcesResult, "ate.dev/v1alpha1/agents/ActorTemplate/code-runner")
	sandboxSummary := session.Report.SummaryDetails.Controls["C-LIVE-SANDBOX"]
	workerPoolSummary := session.Report.SummaryDetails.Controls["C-LIVE-WORKERPOOL"]
	templateSummary := session.Report.SummaryDetails.Controls["C-LIVE-TEMPLATE"]
	actorSummary := session.Report.SummaryDetails.Controls["C-LIVE-ACTOR"]
	assert.Equal(t, apis.StatusFailed, sandboxSummary.GetStatus().Status())
	assert.Equal(t, apis.StatusSkipped, workerPoolSummary.GetStatus().Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, workerPoolSummary.GetSubStatus())
	assert.Equal(t, apis.StatusSkipped, templateSummary.GetStatus().Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, templateSummary.GetSubStatus())
	assert.Equal(t, apis.StatusFailed, actorSummary.GetStatus().Status())
	require.Len(t, session.ScanCoverage.NotEvaluatedControls, 2)
}

type agentRuntimePartialDiscovery struct {
	*discoveryfake.FakeDiscovery
	resources []*metav1.APIResourceList
}

func (d *agentRuntimePartialDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, d.resources, &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
		{Group: "extensions.agents.x-k8s.io", Version: "v1beta1"}: errors.New("SandboxTemplate CRD is unavailable"),
	}}
}

func agentRuntimeLiveFramework() reporthandling.Framework {
	controls := []reporthandling.Control{
		agentRuntimeLiveControl("C-LIVE-SANDBOX", "live-sandbox", []string{"agents.x-k8s.io"}, []string{"v1alpha1", "v1beta1"}, []string{"Sandbox"}),
		agentRuntimeLiveControl("C-LIVE-TEMPLATE", "live-template", []string{"extensions.agents.x-k8s.io"}, []string{"v1beta1"}, []string{"SandboxTemplate"}),
		agentRuntimeLiveControl("C-LIVE-ACTOR", "live-actor", []string{"ate.dev"}, []string{"v1alpha1"}, []string{"ActorTemplate"}),
		agentRuntimeLiveControl("C-LIVE-WORKERPOOL", "live-workerpool", []string{"ate.dev"}, []string{"v1alpha1"}, []string{"WorkerPool"}),
	}
	framework := reporthandling.Framework{Controls: controls}
	framework.Name = "Agent Runtime live cluster"
	return framework
}

func agentRuntimeLiveControl(controlID, ruleName string, groups, versions, kinds []string) reporthandling.Control {
	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: groups, APIVersions: versions, Resources: kinds,
		}},
		Rule: `package armo_builtins

import rego.v1

deny contains message if {
	resource := input[_]
	message := {
		"alertMessage": "Agent Runtime resource reached policy evaluation",
		"packagename": "armo_builtins",
		"failedPaths": ["metadata.name"],
		"reviewPaths": ["metadata.name"],
		"fixPaths": [],
		"alertScore": 5,
		"alertObject": {"k8sApiObjects": [resource]}
	}
}`,
	}
	rule.Name = ruleName
	control := reporthandling.Control{ControlID: controlID, BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = ruleName
	return control
}

func agentRuntimeObject(apiVersion, kind, name, uid string) *unstructured.Unstructured {
	resource := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"name":      name,
			"namespace": "agents",
		},
	}}
	resource.SetUID(types.UID(uid))
	return resource
}

func agentRuntimeList(objects ...*unstructured.Unstructured) *unstructured.UnstructuredList {
	list := &unstructured.UnstructuredList{}
	for _, object := range objects {
		list.Items = append(list.Items, *object)
	}
	return list
}

func assertAgentRuntimeListRequests(t *testing.T, actions []k8stesting.Action, expected ...schema.GroupVersionResource) {
	t.Helper()
	actual := make(map[schema.GroupVersionResource]int)
	for _, action := range actions {
		if action.GetVerb() == "list" && action.GetResource().Group != "admissionregistration.k8s.io" {
			assert.Equal(t, "agents", action.GetNamespace(), "Agent Runtime CRDs must be listed through the requested namespace")
			actual[action.GetResource()]++
		}
	}
	require.Len(t, actual, len(expected), "an unavailable SandboxTemplate CRD must not produce a list request")
	for _, gvr := range expected {
		assert.Equalf(t, 1, actual[gvr], "expected one list request for %s", gvr)
	}
}
