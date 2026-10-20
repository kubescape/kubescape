package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const grantWlid = "wlid://cluster-test/namespace-prod/deployment-web"

func testReferenceGrant(apiVersion, namespace, name, fromNamespace, fromKind string, toName any) *unstructured.Unstructured {
	to := map[string]any{"group": "", "kind": "Service"}
	if toName != nil {
		to["name"] = toName
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       "ReferenceGrant",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"from": []any{map[string]any{"group": "gateway.networking.k8s.io", "kind": fromKind, "namespace": fromNamespace}},
			"to":   []any{to},
		},
	}}
}

// crossNamespaceRoute is a route in "edge" whose backendRef reaches prod/web-svc.
func crossNamespaceRoute() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "route", "namespace": "edge"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "web-svc", "namespace": "prod"}}}},
		},
	}}
}

func grantTestGateway() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]any{"name": "gw", "namespace": "edge"},
		"spec":       map[string]any{"listeners": []any{map[string]any{"name": "http"}}},
	}}
}

func notServed(gvrs ...schema.GroupVersionResource) k8stesting.ReactionFunc {
	return func(a k8stesting.Action) (bool, runtime.Object, error) {
		for _, gvr := range gvrs {
			if a.GetResource() == gvr {
				return true, nil, apierrors.NewNotFound(gvr.GroupResource(), "")
			}
		}
		return false, nil, nil
	}
}

type grantOutcome int

const (
	outcomeAuthorized grantOutcome = iota
	outcomeDenied
	outcomeUnknown
)

// grantScenario prepares the cluster's dynamic client: grants to create (as
// the v1 object each carries), and optional reactors simulating an
// unavailable ReferenceGrant API.
type grantScenario struct {
	name    string
	grants  []*unstructured.Unstructured
	prepare func(dyn *dynamicfake.FakeDynamicClient)
	want    grantOutcome
}

func grantScenarios() []grantScenario {
	allowAll := testReferenceGrant("gateway.networking.k8s.io/v1", "prod", "g", "edge", "HTTPRoute", nil)
	return []grantScenario{
		{name: "matching v1 grant", grants: []*unstructured.Unstructured{allowAll}, want: outcomeAuthorized},
		{name: "matching named grant", grants: []*unstructured.Unstructured{testReferenceGrant("gateway.networking.k8s.io/v1", "prod", "g", "edge", "HTTPRoute", "web-svc")}, want: outcomeAuthorized},
		{name: "served empty list is no grants", want: outcomeDenied},
		{name: "wrong target name", grants: []*unstructured.Unstructured{testReferenceGrant("gateway.networking.k8s.io/v1", "prod", "g", "edge", "HTTPRoute", "other")}, want: outcomeDenied},
		{name: "wrong source namespace", grants: []*unstructured.Unstructured{testReferenceGrant("gateway.networking.k8s.io/v1", "prod", "g", "elsewhere", "HTTPRoute", nil)}, want: outcomeDenied},
		{name: "wrong source kind", grants: []*unstructured.Unstructured{testReferenceGrant("gateway.networking.k8s.io/v1", "prod", "g", "edge", "GRPCRoute", nil)}, want: outcomeDenied},
		{name: "grant in the wrong namespace", grants: []*unstructured.Unstructured{testReferenceGrant("gateway.networking.k8s.io/v1", "edge", "g", "edge", "HTTPRoute", nil)}, want: outcomeDenied},
		{
			name:   "v1beta1-only cluster",
			grants: nil,
			prepare: func(dyn *dynamicfake.FakeDynamicClient) {
				dyn.PrependReactor("list", "referencegrants", notServed(referenceGrantGVR))
				_, err := dyn.Resource(referenceGrantGVRv1beta1).Namespace("prod").Create(context.Background(),
					testReferenceGrant("gateway.networking.k8s.io/v1beta1", "prod", "g", "edge", "HTTPRoute", nil), metav1.CreateOptions{})
				if err != nil {
					panic(err)
				}
			},
			want: outcomeAuthorized,
		},
		{
			name: "API not served",
			prepare: func(dyn *dynamicfake.FakeDynamicClient) {
				dyn.PrependReactor("list", "referencegrants", notServed(referenceGrantGVR, referenceGrantGVRv1beta1))
			},
			want: outcomeUnknown,
		},
		{
			name: "RBAC denial",
			prepare: func(dyn *dynamicfake.FakeDynamicClient) {
				dyn.PrependReactor("list", "referencegrants", forbidden(referenceGrantGVR))
			},
			want: outcomeUnknown,
		},
		{
			name: "other collection failure",
			prepare: func(dyn *dynamicfake.FakeDynamicClient) {
				dyn.PrependReactor("list", "referencegrants", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("connection refused")
				})
			},
			want: outcomeUnknown,
		},
		{
			name: "v1 forbidden does not fall through to an empty v1beta1",
			prepare: func(dyn *dynamicfake.FakeDynamicClient) {
				dyn.PrependReactor("list", "referencegrants", func(a k8stesting.Action) (bool, runtime.Object, error) {
					if a.GetResource() == referenceGrantGVR {
						return true, nil, apierrors.NewForbidden(referenceGrantGVR.GroupResource(), "", nil)
					}
					return false, nil, nil
				})
			},
			want: outcomeUnknown,
		},
		{
			name: "malformed grant cannot be ruled out",
			grants: []*unstructured.Unstructured{{Object: map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1",
				"kind":       "ReferenceGrant",
				"metadata":   map[string]any{"name": "bad", "namespace": "prod"},
				"spec":       map[string]any{"from": []any{}, "to": []any{}},
			}}},
			want: outcomeUnknown,
		},
	}
}

func (sc grantScenario) apply(t *testing.T, ksServer *KubescapeMcpserver) {
	t.Helper()
	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	_, err := dyn.Resource(gatewayGVR).Namespace("edge").Create(context.Background(), grantTestGateway(), metav1.CreateOptions{})
	require.NoError(t, err)
	for _, g := range sc.grants {
		_, err := dyn.Resource(referenceGrantGVR).Namespace(g.GetNamespace()).Create(context.Background(), g.DeepCopy(), metav1.CreateOptions{})
		require.NoError(t, err)
	}
	if sc.prepare != nil {
		sc.prepare(dyn)
	}
}

func TestAnalyzeServiceExposure_ReferenceGrantOutcomes(t *testing.T) {
	for _, sc := range grantScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			svc := unstructuredServiceWithSelector("prod", "web-svc", "ClusterIP", map[string]any{"app": "web"})
			ksServer := newServiceExposureTestServer(t, svc, crossNamespaceRoute())
			sc.apply(t, ksServer)

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{"namespace": "prod", "service_name": "web-svc"}))
			require.False(t, result.IsError, "a ReferenceGrant collection problem must not fail the tool")

			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			services := parsed["services"].(map[string]any)
			paths := findingPaths(t, services, "web-svc")
			unclear := findingIsUnclear(t, services, "web-svc")
			_, unavailable := parsed["reference_grants_unavailable"]

			switch sc.want {
			case outcomeAuthorized:
				require.Len(t, paths, 1)
				require.Equal(t, "HTTPRoute", paths[0].(map[string]any)["kind"])
				require.Equal(t, "edge/route", paths[0].(map[string]any)["source"])
				require.False(t, unclear)
				require.False(t, unavailable)
			case outcomeDenied:
				require.Empty(t, paths, "an unauthorized cross-namespace reference is not an exposure path")
				require.False(t, unclear, "grants were collected: the answer is a definite no")
				require.False(t, unavailable)
			case outcomeUnknown:
				require.Empty(t, paths)
				require.True(t, unclear, "missing authorization data must not become a definitive not-exposed result")
				require.True(t, unavailable)
			}
		})
	}
}

func TestAnalyzeVulnerabilityExposure_ReferenceGrantOutcomes(t *testing.T) {
	for _, sc := range grantScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			deploy := unstructuredDeployment("prod", "web", map[string]any{"app": "web"})
			svc := unstructuredServiceWithSelector("prod", "web-svc", "ClusterIP", map[string]any{"app": "web"})
			manifest := vulnerabilityManifest("prod", "web-manifest", grantWlid, criticalMatch("CVE-2024-1"))
			ksServer := newVulnExposureTestServer(t, []runtime.Object{deploy, svc, crossNamespaceRoute()}, manifest)
			sc.apply(t, ksServer)

			result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_vulnerability_exposure", map[string]any{}))
			require.False(t, result.IsError)

			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			findings := parsed["findings"].([]any)
			require.Len(t, findings, 1)
			exposed, _ := findings[0].(map[string]any)["external_exposure"].([]any)

			grantWarning := false
			warnings, _ := parsed["warnings"].([]any)
			for _, w := range warnings {
				if ws, ok := w.(string); ok && containsAll(ws, "ReferenceGrant", "unknown") {
					grantWarning = true
				}
			}

			switch sc.want {
			case outcomeAuthorized:
				require.Len(t, exposed, 1)
				require.Equal(t, "HTTPRoute", exposed[0].(map[string]any)["kind"])
				require.False(t, grantWarning)
			case outcomeDenied:
				require.Empty(t, exposed)
				require.False(t, grantWarning)
			case outcomeUnknown:
				require.Empty(t, exposed)
				require.True(t, grantWarning, "warnings must say authorization is unknown: %v", warnings)
			}
		})
	}
}

// multiBackendRoute is a route in "edge" whose backendRefs reach each named
// Service in prod.
func multiBackendRoute(services ...string) *unstructured.Unstructured {
	refs := make([]any, 0, len(services))
	for _, s := range services {
		refs = append(refs, map[string]any{"name": s, "namespace": "prod"})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "route", "namespace": "edge"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"rules":      []any{map[string]any{"backendRefs": refs}},
		},
	}}
}

// A workload fronted by several unclear Services must produce one warning, and
// distinct workloads must each still produce their own.
func TestAnalyzeVulnerabilityExposure_UnclearWarningsDeduplicatedPerWorkload(t *testing.T) {
	web := unstructuredDeployment("prod", "web", map[string]any{"app": "web"})
	api := unstructuredDeployment("prod", "api", map[string]any{"app": "api"})
	objs := []runtime.Object{
		web, api,
		unstructuredServiceWithSelector("prod", "web-svc", "ClusterIP", map[string]any{"app": "web"}),
		unstructuredServiceWithSelector("prod", "web-svc-2", "ClusterIP", map[string]any{"app": "web"}),
		unstructuredServiceWithSelector("prod", "api-svc", "ClusterIP", map[string]any{"app": "api"}),
		multiBackendRoute("web-svc", "web-svc-2", "api-svc"),
	}
	ksServer := newVulnExposureTestServer(t, objs,
		vulnerabilityManifest("prod", "web-manifest", grantWlid, criticalMatch("CVE-2024-1")),
		vulnerabilityManifest("prod", "api-manifest", "wlid://cluster-test/namespace-prod/deployment-api", criticalMatch("CVE-2024-2")))
	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	_, err := dyn.Resource(gatewayGVR).Namespace("edge").Create(context.Background(), grantTestGateway(), metav1.CreateOptions{})
	require.NoError(t, err)
	dyn.PrependReactor("list", "referencegrants", forbidden(referenceGrantGVR))

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_vulnerability_exposure", map[string]any{}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	warnings, _ := parsed["warnings"].([]any)
	counts := map[string]int{}
	for _, w := range warnings {
		ws, _ := w.(string)
		if !containsAll(ws, "ReferenceGrant", "unknown") {
			continue
		}
		switch {
		case containsAll(ws, "(web)"):
			counts["web"]++
		case containsAll(ws, "(api)"):
			counts["api"]++
		}
	}
	require.Equal(t, map[string]int{"web": 1, "api": 1}, counts, "warnings: %v", warnings)
}
