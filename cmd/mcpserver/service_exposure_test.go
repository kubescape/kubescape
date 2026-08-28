package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// newServiceExposureTestServer always registers the Gateway API GVRs' list
// kinds: NewSimpleDynamicClientWithCustomListKinds panics on List against
// any GVR it was not given a list kind for, which is a testing-harness
// requirement, not a stand-in for how a real cluster without the Gateway
// API CRDs installed actually behaves (a real List there returns a NotFound
// error). TestAnalyzeServiceExposure_MissingGatewayAPIIsNotFatal simulates
// that real behavior with a reactor instead of omitting the registration.
func newServiceExposureTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		serviceGVR:   "ServiceList",
		ingressGVR:   "IngressList",
		namespaceGVR: "NamespaceList",
		httpRouteGVR: "HTTPRouteList",
		gatewayGVR:   "GatewayList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	createServiceExposureTools(ksServer)
	return ksServer
}

func unstructuredService(namespace, name, serviceType string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       map[string]any{"type": serviceType},
	}}
}

func unstructuredIngress(namespace, name, backendServiceName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": backendServiceName}},
		},
	}}
}

func TestAnalyzeServiceExposure_LoadBalancerServiceIsExposed(t *testing.T) {
	svc := unstructuredService("prod", "app", "LoadBalancer")
	ksServer := newServiceExposureTestServer(t, svc)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	services := parsed["services"].(map[string]any)
	paths := services["app"].([]any)
	require.Len(t, paths, 1)
	require.Equal(t, "LoadBalancer", paths[0].(map[string]any)["kind"])
}

func TestAnalyzeServiceExposure_ClusterIPWithNoIngressIsNotExposed(t *testing.T) {
	svc := unstructuredService("prod", "app", "ClusterIP")
	ksServer := newServiceExposureTestServer(t, svc)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	services := parsed["services"].(map[string]any)
	require.Empty(t, services["app"])
}

func TestAnalyzeServiceExposure_IngressExposesClusterIPService(t *testing.T) {
	svc := unstructuredService("prod", "app", "ClusterIP")
	ing := unstructuredIngress("prod", "web", "app")
	ksServer := newServiceExposureTestServer(t, svc, ing)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	services := parsed["services"].(map[string]any)
	paths := services["app"].([]any)
	require.Len(t, paths, 1)
	entry := paths[0].(map[string]any)
	require.Equal(t, "Ingress", entry["kind"])
	require.Equal(t, "prod/web", entry["source"])
}

func TestAnalyzeServiceExposure_OmittedServiceNameReportsEveryServiceInNamespace(t *testing.T) {
	svc1 := unstructuredService("prod", "app-one", "ClusterIP")
	svc2 := unstructuredService("prod", "app-two", "LoadBalancer")
	ksServer := newServiceExposureTestServer(t, svc1, svc2)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace": "prod",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	services := parsed["services"].(map[string]any)
	require.Len(t, services, 2)
	require.Empty(t, services["app-one"])
	require.Len(t, services["app-two"].([]any), 1)
}

func TestAnalyzeServiceExposure_MissingNamespaceReturnsError(t *testing.T) {
	ksServer := newServiceExposureTestServer(t)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{}))
	require.True(t, result.IsError)
}

func TestAnalyzeServiceExposure_MissingGatewayAPIIsNotFatal(t *testing.T) {
	svc := unstructuredService("prod", "app", "ClusterIP")
	ksServer := newServiceExposureTestServer(t, svc)

	// Simulate a real cluster without the Gateway API CRDs installed: List
	// against either GVR returns NotFound, not the panic
	// NewSimpleDynamicClientWithCustomListKinds produces for a genuinely
	// unregistered GVR (a testing-harness artifact, not real behavior).
	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	notFound := func(gvr schema.GroupVersionResource) k8stesting.ReactionFunc {
		return func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewNotFound(gvr.GroupResource(), "")
		}
	}
	dyn.PrependReactor("list", httpRouteGVR.Resource, notFound(httpRouteGVR))
	dyn.PrependReactor("list", gatewayGVR.Resource, notFound(gatewayGVR))

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.False(t, result.IsError, "a cluster without the Gateway API installed must not fail the whole tool")
}

func TestAnalyzeServiceExposure_UnexpectedGatewayAPIListErrorIsFatal(t *testing.T) {
	svc := unstructuredService("prod", "app", "ClusterIP")
	ksServer := newServiceExposureTestServer(t, svc)

	dyn := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	dyn.PrependReactor("list", httpRouteGVR.Resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.True(t, result.IsError, "a genuine list failure (not a missing-API shape) must surface as a tool error, not be silently swallowed")
}

func TestAnalyzeServiceExposure_HTTPRouteThroughGatewayExposesService(t *testing.T) {
	svc := unstructuredService("prod", "app", "ClusterIP")
	route := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "route", "namespace": "prod"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app"}}}},
		},
	}}
	gw := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]any{"name": "gw", "namespace": "prod"},
		"spec":       map[string]any{"listeners": []any{map[string]any{"name": "http"}}},
	}}
	ksServer := newServiceExposureTestServer(t, svc, route)

	// NewSimpleDynamicClientWithCustomListKinds' constructor buckets initial
	// objects by guessing their resource from Kind via
	// meta.UnsafeGuessKindToResource, which applies an unconditional "y" ->
	// "ies" rule with no vowel check -- it guesses "Gateway" as "gatewaies",
	// not the real Gateway API plural "gateways" this test (and the real
	// production GVR) uses, so a Gateway object passed through the
	// constructor is silently bucketed under the wrong resource and never
	// found by a List against gatewayGVR. Adding it via an explicit Create
	// against the real GVR sidesteps the guess entirely.
	dyn := ksServer.k8sClient.DynamicClient
	_, err := dyn.Resource(gatewayGVR).Namespace("prod").Create(context.Background(), gw, metav1.CreateOptions{})
	require.NoError(t, err)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_service_exposure", map[string]any{
		"namespace":    "prod",
		"service_name": "app",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	services := parsed["services"].(map[string]any)
	paths := services["app"].([]any)
	require.Len(t, paths, 1)
	require.Equal(t, "HTTPRoute", paths[0].(map[string]any)["kind"])
}
