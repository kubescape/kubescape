package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func newReachabilityTestServer(objects ...runtime.Object) *KubescapeMcpserver {
	listKinds := map[schema.GroupVersionResource]string{
		networkPolicyGVR: "NetworkPolicyList",
		namespaceGVR:     "NamespaceList",
		podGVR:           "PodList",
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
	createNetworkReachabilityTools(ksServer)
	return ksServer
}

func unstructuredPod(namespace, name string, labels map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
	}
	if labels != nil {
		obj["metadata"].(map[string]any)["labels"] = labels
	}
	return &unstructured.Unstructured{Object: obj}
}

func unstructuredNetworkPolicy(namespace, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": spec,
	}}
}

func TestAnalyzeNetworkReachability_DefaultDenyBlocksUnrelatedSource(t *testing.T) {
	deny := unstructuredNetworkPolicy("prod", "deny-all", map[string]any{
		"podSelector": map[string]any{},
		"policyTypes": []any{"Ingress"},
	})
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(deny, server, client)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))

	require.Equal(t, "denied", parsed["verdict"])
	ingress := parsed["ingress"].(map[string]any)
	require.Equal(t, "denied", ingress["verdict"])
}

func TestAnalyzeNetworkReachability_AllowsSelectedPeer(t *testing.T) {
	allow := unstructuredNetworkPolicy("prod", "allow-client", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
		"policyTypes": []any{"Ingress"},
		"ingress": []any{
			map[string]any{
				"from": []any{
					map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app": "client"}}},
				},
			},
		},
	})
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(allow, server, client)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, "allowed", parsed["verdict"])
	ingress := parsed["ingress"].(map[string]any)
	require.Equal(t, "prod/allow-client", ingress["matched_policy"])
}

func TestAnalyzeNetworkReachability_MissingArgumentsReturnError(t *testing.T) {
	ksServer := newReachabilityTestServer()

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace": "prod",
		"source_pod":       "client",
		// destination_namespace/destination_pod deliberately omitted
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeNetworkReachability_PortRespected(t *testing.T) {
	allowPort80 := unstructuredNetworkPolicy("prod", "allow-port-80", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
		"policyTypes": []any{"Ingress"},
		"ingress": []any{
			map[string]any{
				"ports": []any{
					map[string]any{"protocol": "TCP", "port": int64(80)},
				},
			},
		},
	})
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(allowPort80, server, client)

	allowed := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(80),
	}))
	var allowedParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, allowed)), &allowedParsed))
	require.Equal(t, "allowed", allowedParsed["verdict"])

	denied := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(443),
	}))
	var deniedParsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, denied)), &deniedParsed))
	require.Equal(t, "denied", deniedParsed["verdict"])
}

func TestAnalyzeNetworkReachability_NoPoliciesAllowsByDefault(t *testing.T) {
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(server, client)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, "allowed", parsed["verdict"])
}

func TestAnalyzeNetworkReachability_LowercaseProtocolIsNormalized(t *testing.T) {
	allowPort80 := unstructuredNetworkPolicy("prod", "allow-port-80", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
		"policyTypes": []any{"Ingress"},
		"ingress": []any{
			map[string]any{
				"ports": []any{
					map[string]any{"protocol": "TCP", "port": int64(80)},
				},
			},
		},
	})
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(allowPort80, server, client)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(80),
		"protocol":              "tcp",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, "allowed", parsed["verdict"], "a lowercase protocol must be normalized, not silently fail every port match")
}

func TestAnalyzeNetworkReachability_InvalidProtocolReturnsError(t *testing.T) {
	ksServer := newReachabilityTestServer()

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(80),
		"protocol":              "ICMP",
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeNetworkReachability_PortAboveRangeReturnsError(t *testing.T) {
	ksServer := newReachabilityTestServer()

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(70000),
	}))
	require.True(t, result.IsError)
}

func TestAnalyzeNetworkReachability_MalformedPodSelectorDowngradesVerdictToUnknown(t *testing.T) {
	bad := unstructuredNetworkPolicy("prod", "broken", map[string]any{
		"podSelector": map[string]any{
			"matchExpressions": []any{
				map[string]any{"key": "x", "operator": "NotARealOperator"},
			},
		},
		"policyTypes": []any{"Ingress"},
	})
	server := unstructuredPod("prod", "server", map[string]any{"app": "server"})
	client := unstructuredPod("prod", "client", map[string]any{"app": "client"})

	ksServer := newReachabilityTestServer(bad, server, client)

	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
	}))
	require.False(t, result.IsError)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	require.Equal(t, "unknown", parsed["verdict"], "a dropped, unparseable policy must downgrade the verdict, not silently report a confident allowed")
	require.NotEmpty(t, parsed["decode_warnings"])
}
