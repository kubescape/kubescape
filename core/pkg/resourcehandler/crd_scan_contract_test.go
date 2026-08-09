package resourcehandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
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

func agentRuntimeDiscovery() *discoveryfake.FakeDiscovery {
	discovery := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "agents.x-k8s.io/v1alpha1",
			APIResources: []metav1.APIResource{{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "agents.x-k8s.io/v1beta1",
			APIResources: []metav1.APIResource{{Name: "sandboxes", Kind: "Sandbox", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "extensions.agents.x-k8s.io/v1alpha1",
			APIResources: []metav1.APIResource{{Name: "sandboxtemplates", Kind: "SandboxTemplate", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "extensions.agents.x-k8s.io/v1beta1",
			APIResources: []metav1.APIResource{{Name: "sandboxtemplates", Kind: "SandboxTemplate", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
		{
			GroupVersion: "ate.dev/v1alpha1",
			APIResources: []metav1.APIResource{
				{Name: "actortemplates", Kind: "ActorTemplate", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
				{Name: "workerpools", Kind: "WorkerPool", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}},
			},
		},
		{
			GroupVersion: "monitoring.coreos.com/v1",
			APIResources: []metav1.APIResource{{Name: "prometheuses", Kind: "Prometheus", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}},
		},
	}
	return discovery
}

func TestDiscoveryResolverUsesDeclaredPluralAndScope(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(agentRuntimeDiscovery())
	require.Empty(t, failures)

	tests := []struct {
		group    string
		version  string
		resource string
		want     string
	}{
		{group: "agents.x-k8s.io", version: "v1alpha1", resource: "Sandbox", want: "agents.x-k8s.io/v1alpha1/sandboxes"},
		{group: "agents.x-k8s.io", version: "v1beta1", resource: "sandboxes", want: "agents.x-k8s.io/v1beta1/sandboxes"},
		{group: "extensions.agents.x-k8s.io", version: "v1beta1", resource: "SandboxTemplate", want: "extensions.agents.x-k8s.io/v1beta1/sandboxtemplates"},
		{group: "ate.dev", version: "v1alpha1", resource: "ActorTemplate", want: "ate.dev/v1alpha1/actortemplates"},
		{group: "ate.dev", version: "v1alpha1", resource: "WorkerPool", want: "ate.dev/v1alpha1/workerpools"},
		{group: "monitoring.coreos.com", version: "v1", resource: "Prometheus", want: "monitoring.coreos.com/v1/prometheuses"},
	}

	for _, test := range tests {
		t.Run(test.resource+"_"+test.version, func(t *testing.T) {
			resolved := resolver(test.group, test.version, test.resource)
			require.Len(t, resolved, 1)
			assert.Equal(t, test.want, resolved[0].groupVersionResourceTriplet)
			require.NotNil(t, resolved[0].namespaced)
			assert.True(t, *resolved[0].namespaced)
		})
	}
}

func TestDefaultResolverNormalizesOfflineIdentityWithoutGuessingWildcards(t *testing.T) {
	exact := defaultResourceResolver("ate.dev", "v1alpha1", "ActorTemplate")
	require.Len(t, exact, 1)
	assert.Equal(t, "ate.dev/v1alpha1/actortemplate", exact[0].groupVersionResourceTriplet)

	assert.Empty(t, defaultResourceResolver("ate.dev", "*", "ActorTemplate"))
	assert.Empty(t, defaultResourceResolver("*", "v1alpha1", "ActorTemplate"))
	assert.Empty(t, defaultResourceResolver("", "v1", "UnknownCoreKind"))
	assert.Empty(t, defaultResourceResolver("ate.dev", "", "ActorTemplate"))
}

func TestDiscoveryResolverReportsPartialDiscoveryFailures(t *testing.T) {
	discoveryClient := agentRuntimeDiscovery()
	discoveryClient.PrependReactor("get", "resource", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
			{Group: "custom.metrics.k8s.io", Version: "v1beta2"}: errors.New("provider unavailable"),
			{Group: "metrics.k8s.io", Version: "v1beta1"}:        errors.New("metrics server unavailable"),
		}}
	})

	resolver, failures := newDiscoveryResourceResolver(discoveryClient)
	require.Len(t, failures, 2)
	assert.Equal(t, "discovery:custom.metrics.k8s.io/v1beta2", failures[0].GVR)
	assert.Equal(t, "discovery", failures[0].Selector)
	assert.Contains(t, failures[0].Error, "provider unavailable")
	assert.Equal(t, "discovery:metrics.k8s.io/v1beta1", failures[1].GVR)

	// Partial discovery results remain usable for groups that did respond.
	resolved := resolver("agents.x-k8s.io", "v1alpha1", "Sandbox")
	require.Len(t, resolved, 1)
	assert.Equal(t, "agents.x-k8s.io/v1alpha1/sandboxes", resolved[0].groupVersionResourceTriplet)

	coverage := cautils.BuildScanCoverage(nil, nil, nil, failures, nil)
	coverage.ComputeCoverageScore(1)
	assert.Len(t, coverage.PartialGVRPulls, 2)
	assert.True(t, coverage.Degraded)
	assert.Less(t, coverage.CoverageScore, float32(100))
}

func TestDiscoveryResolverReportsUntypedDiscoveryFailure(t *testing.T) {
	discoveryClient := &discoveryfake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discoveryClient.PrependReactor("get", "resource", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("discovery endpoint unavailable")
	})

	_, failures := newDiscoveryResourceResolver(discoveryClient)

	require.Len(t, failures, 1)
	assert.Equal(t, "discovery:*", failures[0].GVR)
	assert.Equal(t, "discovery", failures[0].Selector)
	assert.Contains(t, failures[0].Error, "discovery endpoint unavailable")
}

func TestDiscoveredScopeAppliesIncludeAndExcludeSelectors(t *testing.T) {
	resolver, failures := newDiscoveryResourceResolver(agentRuntimeDiscovery())
	require.Empty(t, failures)
	resolved := resolver("agents.x-k8s.io", "v1beta1", "Sandbox")
	require.Len(t, resolved, 1)
	require.NotNil(t, resolved[0].namespaced)

	gvr := &schema.GroupVersionResource{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"}
	assert.Equal(t,
		[]string{"metadata.namespace==agents"},
		NewIncludeSelector("agents").GetNamespacesSelectors(gvr, resolved[0].namespaced),
	)
	assert.Equal(t,
		[]string{"metadata.namespace!=kube-system"},
		NewExcludeSelector("kube-system").GetNamespacesSelectors(gvr, resolved[0].namespaced),
	)
}

func TestOfflineResolverUsesKindScopeWhenNamespaceIsOmitted(t *testing.T) {
	tests := []struct {
		apiVersion     string
		group          string
		version        string
		kind           string
		resource       string
		wantNamespaced bool
		wantSelector   string
	}{
		{apiVersion: "v1", version: "v1", kind: "Pod", resource: "pods", wantNamespaced: true, wantSelector: "metadata.namespace!=kube-system"},
		{apiVersion: "apps/v1", group: "apps", version: "v1", kind: "Deployment", resource: "deployments", wantNamespaced: true, wantSelector: "metadata.namespace!=kube-system"},
		{apiVersion: "rbac.authorization.k8s.io/v1", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole", resource: "clusterroles", wantNamespaced: false, wantSelector: ""},
	}

	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			workload := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": test.apiVersion,
				"kind":       test.kind,
				"metadata":   map[string]any{"name": "without-namespace"},
			})
			mapped := map[string][]workloadinterface.IMetadata{
				k8sinterface.JoinResourceTriplets(test.group, test.version, test.resource): {workload},
			}
			resolver := newOfflineManifestResourceResolver(mapped)

			resolved := resolver(test.group, test.version, test.kind)
			require.Len(t, resolved, 1)
			require.NotNil(t, resolved[0].namespaced)
			assert.Equal(t, test.wantNamespaced, *resolved[0].namespaced)

			gvr := &schema.GroupVersionResource{Group: test.group, Version: test.version, Resource: test.resource}
			assert.Equal(t,
				[]string{test.wantSelector},
				NewExcludeSelector("kube-system").GetNamespacesSelectors(gvr, resolved[0].namespaced),
			)
		})
	}
}

func TestAgentRuntimeCRDResourceToControlKeysMatchQueries(t *testing.T) {
	framework := agentRuntimeFramework()
	resolver, failures := newDiscoveryResourceResolver(agentRuntimeDiscovery())
	require.Empty(t, failures)
	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{framework},
		nil,
		reporthandling.ScopeCluster,
		resolver,
	)
	resourceToControls := map[string][]string{}
	setComplexKSResourceMap([]reporthandling.Framework{framework}, resourceToControls, resolver)

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
	session := cautils.NewOPASessionObj(context.Background(), nil, nil, scanInfo, nil)
	session.Policies = []reporthandling.Framework{agentRuntimeFramework()}

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 4)

	// Offline there is no authoritative REST discovery. Policies naming the
	// Kind use the lowercase, manifest-derived singular comparison key.
	expected := map[string]string{
		"agents.x-k8s.io/v1alpha1/sandbox":                   "Sandbox",
		"extensions.agents.x-k8s.io/v1beta1/sandboxtemplate": "SandboxTemplate",
		"ate.dev/v1alpha1/actortemplate":                     "ActorTemplate",
		"ate.dev/v1alpha1/workerpool":                        "WorkerPool",
	}
	for resourceGroup, kind := range expected {
		require.Lenf(t, resources[resourceGroup], 1, "expected one %s under %s", kind, resourceGroup)
		assert.Equal(t, kind, allResources[resources[resourceGroup][0]].GetKind())
	}
}

func TestFileResourceHandlerMatchesCustomResourcesByKindOrPlural(t *testing.T) {
	manifest := `apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: alpha-sandbox
  namespace: agents
`
	manifestPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	for _, policyResource := range []string{"Sandbox", "sandbox", "sandboxs", "sandboxes", "SANDBOXES"} {
		t.Run(policyResource, func(t *testing.T) {
			match := reporthandling.RuleMatchObjects{
				APIGroups:   []string{"agents.x-k8s.io"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{policyResource},
			}
			framework := *mockFramework("offline-custom-resource", []reporthandling.Control{
				mockControl("offline-custom-resource", []reporthandling.PolicyRule{mockRule("offline-custom-resource", []reporthandling.RuleMatchObjects{match}, "")}),
			})
			scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
			session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

			resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
			require.NoError(t, err)
			require.Len(t, allResources, 1)

			resolved := defaultResourceResolver("agents.x-k8s.io", "v1alpha1", policyResource)
			require.Len(t, resolved, 1)
			assert.Len(t, resources[resolved[0].groupVersionResourceTriplet], 1)
		})
	}
}

func TestFileResourceHandlerMatchesGatewayPlural(t *testing.T) {
	manifest := `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public-gateway
  namespace: gateway-system
`
	manifestPath := filepath.Join(t.TempDir(), "gateway.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"gateway.networking.k8s.io"},
		APIVersions: []string{"v1"},
		Resources:   []string{"gateways"},
	}
	framework := *mockFramework("offline-gateway", []reporthandling.Control{
		mockControl("offline-gateway", []reporthandling.PolicyRule{
			mockRule("offline-gateway", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 1)
	assert.Len(t, resources["gateway.networking.k8s.io/v1/gateways"], 1)
}

func TestFileSingleResourceScanMatchesPluralPolicy(t *testing.T) {
	manifest := `apiVersion: agents.x-k8s.io/v1alpha1
kind: Sandbox
metadata:
  name: alpha-sandbox
  namespace: agents
`
	manifestPath := filepath.Join(t.TempDir(), "sandbox.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"agents.x-k8s.io"},
		APIVersions: []string{"v1alpha1"},
		Resources:   []string{"sandboxes"},
	}
	framework := *mockFramework("offline-single-resource", []reporthandling.Control{
		mockControl("offline-single-resource", []reporthandling.PolicyRule{
			mockRule("offline-single-resource", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})
	scanInfo := &cautils.ScanInfo{
		InputPatterns: []string{manifestPath},
		ScanObject:    scanObject("agents.x-k8s.io/v1alpha1", "Sandbox", "agents", "alpha-sandbox"),
	}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 1)
	require.Len(t, resources["agents.x-k8s.io/v1alpha1/sandboxes"], 1)
	assert.Contains(t, allResources, resources["agents.x-k8s.io/v1alpha1/sandboxes"][0])
}

func TestK8sResourceHandlerUsesDiscoveredGVRsAndNamespaceScope(t *testing.T) {
	expectedGVRs := []schema.GroupVersionResource{
		{Group: "agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxes"},
		{Group: "agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxes"},
		{Group: "extensions.agents.x-k8s.io", Version: "v1alpha1", Resource: "sandboxtemplates"},
		{Group: "extensions.agents.x-k8s.io", Version: "v1beta1", Resource: "sandboxtemplates"},
		{Group: "ate.dev", Version: "v1alpha1", Resource: "actortemplates"},
		{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"},
	}
	objects := map[schema.GroupVersionResource]*unstructured.Unstructured{
		expectedGVRs[0]: nil,
		expectedGVRs[1]: unstructuredResource("agents.x-k8s.io/v1beta1", "Sandbox", "agents", "live-sandbox"),
		expectedGVRs[2]: nil,
		expectedGVRs[3]: unstructuredResource("extensions.agents.x-k8s.io/v1beta1", "SandboxTemplate", "agents", "live-template"),
		expectedGVRs[4]: unstructuredResource("ate.dev/v1alpha1", "ActorTemplate", "agents", "live-actor-template"),
		expectedGVRs[5]: unstructuredResource("ate.dev/v1alpha1", "WorkerPool", "agents", "live-worker-pool"),
	}
	listKinds := map[schema.GroupVersionResource]string{}
	for _, gvr := range expectedGVRs {
		listKinds[gvr] = "CustomResourceList"
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	dynamicClient.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		gvr := action.GetResource()
		object, ok := objects[gvr]
		if !ok {
			return true, nil, fmt.Errorf("unexpected resource query: %s", gvr.String())
		}
		list := &unstructured.UnstructuredList{}
		if object != nil {
			list.Items = []unstructured.Unstructured{*object}
		}
		return true, list, nil
	})
	handler := &K8sResourceHandler{k8s: &k8sinterface.KubernetesApi{
		DynamicClient:   dynamicClient,
		DiscoveryClient: agentRuntimeDiscovery(),
	}}
	resolver, discoveryFailures := newDiscoveryResourceResolver(handler.k8s.DiscoveryClient)
	require.Empty(t, discoveryFailures)
	queryable, _ := getQueryableResourceMapFromPolicies(
		[]reporthandling.Framework{agentRuntimeFramework()},
		nil,
		reporthandling.ScopeCluster,
		resolver,
	)
	resources, allResources, failures := handler.pullResources(context.Background(), queryable, NewIncludeSelector("agents"))

	assert.Empty(t, failures)
	require.Len(t, allResources, 4)

	var actualQueries []string
	seenSelectors := map[schema.GroupVersionResource]string{}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "list" {
			gvr := action.GetResource()
			actualQueries = append(actualQueries, gvr.String())
			listAction, ok := action.(k8stesting.ListAction)
			require.True(t, ok)
			seenSelectors[gvr] = listAction.GetListRestrictions().Fields.String()
		}
	}
	var expectedQueries []string
	for _, gvr := range expectedGVRs {
		expectedQueries = append(expectedQueries, gvr.String())
	}
	sort.Strings(actualQueries)
	sort.Strings(expectedQueries)
	assert.Equal(t, expectedQueries, actualQueries)
	for _, gvr := range expectedGVRs {
		assert.Equal(t, "metadata.namespace=agents", seenSelectors[gvr])
		assert.Contains(t, resources, k8sinterface.GroupVersionResourceToString(&gvr))
	}
}

func TestFileResourceHandlerUsesManifestAPIVersionsForBuiltIns(t *testing.T) {
	manifest := `apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
  namespace: default
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
  namespace: default
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: web
  namespace: default
`
	manifestPath := filepath.Join(t.TempDir(), "current-builtins.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	matches := []reporthandling.RuleMatchObjects{
		{APIGroups: []string{"autoscaling"}, APIVersions: []string{"v2"}, Resources: []string{"HorizontalPodAutoscaler"}},
		{APIGroups: []string{"policy"}, APIVersions: []string{"v1"}, Resources: []string{"PodDisruptionBudget"}},
		{APIGroups: []string{"discovery.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"EndpointSlice"}},
	}
	framework := *mockFramework("current-builtins", []reporthandling.Control{
		mockControl("current-builtins", []reporthandling.PolicyRule{mockRule("current-builtins", matches, "")}),
	})
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 3)

	expected := map[string]string{
		"autoscaling/v2/horizontalpodautoscaler": "HorizontalPodAutoscaler",
		"policy/v1/poddisruptionbudget":          "PodDisruptionBudget",
		"discovery.k8s.io/v1/endpointslice":      "EndpointSlice",
	}
	for resourceGroup, kind := range expected {
		require.Lenf(t, resources[resourceGroup], 1, "expected one %s under %s", kind, resourceGroup)
		assert.Equal(t, kind, allResources[resources[resourceGroup][0]].GetKind())
	}
}

func TestAddWorkloadsToResourcesMapUsesManifestGroupVersionForBuiltIns(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		kind       string
		want       string
	}{
		{name: "current HPA", apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler", want: "autoscaling/v2/horizontalpodautoscalers"},
		{name: "current PDB", apiVersion: "policy/v1", kind: "PodDisruptionBudget", want: "policy/v1/poddisruptionbudgets"},
		{name: "current EndpointSlice", apiVersion: "discovery.k8s.io/v1", kind: "EndpointSlice", want: "discovery.k8s.io/v1/endpointslices"},
		{name: "legacy Deployment", apiVersion: "extensions/v1beta1", kind: "Deployment", want: "extensions/v1beta1/deployments"},
		{name: "legacy Role", apiVersion: "rbac.authorization.k8s.io/v1beta1", kind: "Role", want: "rbac.authorization.k8s.io/v1beta1/roles"},
		{name: "legacy CronJob", apiVersion: "batch/v1beta1", kind: "CronJob", want: "batch/v1beta1/cronjobs"},
		{name: "legacy HPA", apiVersion: "autoscaling/v2beta2", kind: "HorizontalPodAutoscaler", want: "autoscaling/v2beta2/horizontalpodautoscalers"},
		{name: "legacy Ingress", apiVersion: "networking.k8s.io/v1beta1", kind: "Ingress", want: "networking.k8s.io/v1beta1/ingresses"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workload := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": test.apiVersion,
				"kind":       test.kind,
				"metadata": map[string]any{
					"name":      "legacy-resource",
					"namespace": "default",
				},
			})
			mapped := map[string][]workloadinterface.IMetadata{}

			addWorkloadsToResourcesMap(mapped, []workloadinterface.IMetadata{workload})

			require.Len(t, mapped[test.want], 1)
			assert.Same(t, workload, mapped[test.want][0])
		})
	}
}

func TestAddWorkloadsToResourcesMapKeepsCustomKindCollisions(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "serving.knative.dev/v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "hello",
			"namespace": "default",
		},
	})
	mapped := map[string][]workloadinterface.IMetadata{}

	addWorkloadsToResourcesMap(mapped, []workloadinterface.IMetadata{workload})

	assert.Len(t, mapped["serving.knative.dev/v1/service"], 1)
	assert.Len(t, mapped["serving.knative.dev/v1/services"], 1)
}

func TestOfflineManifestResourceAliases(t *testing.T) {
	tests := []struct {
		kind string
		want []string
	}{
		{kind: "Gateway", want: []string{"gateway", "gateways"}},
		{kind: "Proxy", want: []string{"proxy", "proxys", "proxies"}},
		{kind: "Policy", want: []string{"policy", "policys", "policies"}},
		{kind: "Sandbox", want: []string{"sandbox", "sandboxs", "sandboxes"}},
		{kind: "HTTPRoute", want: []string{"httproute", "httproutes"}},
		{kind: "Ingress", want: []string{"ingress", "ingresses"}},
		{kind: "Elasticsearch", want: []string{"elasticsearch", "elasticsearchs", "elasticsearches"}},
	}

	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			assert.Equal(t, test.want, offlineManifestResourceAliases(test.kind))
		})
	}
}

func TestFileResourceHandlerBuildsWildcardMatchesFromManifestCatalog(t *testing.T) {
	manifest := `apiVersion: autoscaling/v99
kind: HorizontalPodAutoscaler
metadata:
  name: future-hpa
  namespace: default
---
apiVersion: future.example.io/v7
kind: Widget
metadata:
  name: future-widget
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: core-pod
  namespace: default
`
	manifestPath := filepath.Join(t.TempDir(), "future-resources.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0o600))

	match := reporthandling.RuleMatchObjects{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"HorizontalPodAutoscaler", "Widget", "Pod"},
	}
	framework := *mockFramework("future-resources", []reporthandling.Control{
		mockControl("future-resources", []reporthandling.PolicyRule{
			mockRule("future-resources", []reporthandling.RuleMatchObjects{match}, ""),
		}),
	})
	scanInfo := &cautils.ScanInfo{InputPatterns: []string{manifestPath}}
	session := cautils.NewOPASessionObj(context.Background(), []reporthandling.Framework{framework}, nil, scanInfo, nil)

	resources, allResources, _, _, err := NewFileResourceHandler().GetResources(context.Background(), session, scanInfo)
	require.NoError(t, err)
	require.Len(t, allResources, 3)
	assert.Len(t, resources["autoscaling/v99/horizontalpodautoscaler"], 1)
	assert.Len(t, resources["future.example.io/v7/widget"], 1)
	assert.Len(t, resources["/v1/pod"], 1)
}

func TestAddSingleResourceToResourceMapsIndexesOfflineAliases(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "agents.x-k8s.io/v1alpha1",
		"kind":       "Sandbox",
		"metadata": map[string]any{
			"name":      "alpha-sandbox",
			"namespace": "agents",
		},
	})
	resources := cautils.K8SResources{}
	allResources := map[string]workloadinterface.IMetadata{}

	addSingleResourceToResourceMaps(resources, allResources, workload, defaultResourceResolver)

	for _, resource := range []string{"sandbox", "sandboxs", "sandboxes"} {
		assert.Equal(t, []string{workload.GetID()}, resources["agents.x-k8s.io/v1alpha1/"+resource])
	}
	assert.Same(t, workload, allResources[workload.GetID()])
}

func TestAddSingleResourceToResourceMapsGuardsUnresolvedIdentity(t *testing.T) {
	workload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "ate.dev/v1alpha1",
		"kind":       "",
		"metadata":   map[string]any{"name": "malformed"},
	})
	resources := cautils.K8SResources{}
	allResources := map[string]workloadinterface.IMetadata{}

	assert.NotPanics(t, func() {
		addSingleResourceToResourceMaps(resources, allResources, workload, defaultResourceResolver)
	})
	assert.Empty(t, resources)
	assert.Empty(t, allResources)
}
