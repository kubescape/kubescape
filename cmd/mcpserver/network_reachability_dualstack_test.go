package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// dualStackPod is a Pod as a dual-stack cluster reports it: status.podIP
// holds the primary address and status.podIPs one address per IP family.
func dualStackPod(namespace, name string, ips ...string) *unstructured.Unstructured {
	pod := unstructuredPod(namespace, name, map[string]any{"app": name})
	podIPs := make([]any, len(ips))
	for i, ip := range ips {
		podIPs[i] = map[string]any{"ip": ip}
	}
	pod.Object["status"] = map[string]any{"podIP": ips[0], "podIPs": podIPs}
	return pod
}

func ipBlockPolicy(name, app, direction, peersKey, cidr string) *unstructured.Unstructured {
	rules := []any{map[string]any{peersKey: []any{map[string]any{"ipBlock": map[string]any{"cidr": cidr}}}}}
	spec := map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": app}},
		"policyTypes": []any{direction},
	}
	if direction == "Egress" {
		spec["egress"] = rules
	} else {
		spec["ingress"] = rules
	}
	return unstructuredNetworkPolicy("prod", name, spec)
}

func analyzeClientToServer(t *testing.T, objects ...*unstructured.Unstructured) map[string]any {
	t.Helper()
	runtimeObjects := make([]runtime.Object, len(objects))
	for i, obj := range objects {
		runtimeObjects[i] = obj
	}
	ksServer := newReachabilityTestServer(runtimeObjects...)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_network_reachability", map[string]any{
		"source_namespace":      "prod",
		"source_pod":            "client",
		"destination_namespace": "prod",
		"destination_pod":       "server",
		"port":                  float64(8080),
	}))
	require.False(t, result.IsError)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
	return parsed
}

// An ipBlock in the pods' secondary IP family admits the connection over
// that family, although status.podIP only carries the primary address.
func TestAnalyzeNetworkReachability_DualStackIPBlockInSecondaryFamily(t *testing.T) {
	tests := []struct {
		name           string
		client, server *unstructured.Unstructured
		cidr           string
	}{
		{
			name:   "IPv4-primary pods, IPv6 ipBlock",
			client: dualStackPod("prod", "client", "10.244.1.2", "fd00:10:244:1::2"),
			server: dualStackPod("prod", "server", "10.244.2.2", "fd00:10:244:2::2"),
			cidr:   "fd00:10:244::/56",
		},
		{
			name:   "IPv6-primary pods, IPv4 ipBlock",
			client: dualStackPod("prod", "client", "fd00:10:244:1::2", "10.244.1.2"),
			server: dualStackPod("prod", "server", "fd00:10:244:2::2", "10.244.2.2"),
			cidr:   "10.244.0.0/16",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := analyzeClientToServer(t, tt.client, tt.server,
				ipBlockPolicy("server-ingress", "server", "Ingress", "from", tt.cidr))
			require.Equal(t, "allowed", parsed["verdict"])
			require.Equal(t, "prod/server-ingress", parsed["ingress"].(map[string]any)["matched_policy"])
		})
	}
}

// Egress that admits only IPv4 and ingress that admits only IPv6 leave no IP
// family a connection could use at both ends.
func TestAnalyzeNetworkReachability_DualStackFamilyMismatchIsDenied(t *testing.T) {
	parsed := analyzeClientToServer(t,
		dualStackPod("prod", "client", "10.244.1.2", "fd00:10:244:1::2"),
		dualStackPod("prod", "server", "10.244.2.2", "fd00:10:244:2::2"),
		ipBlockPolicy("client-egress", "client", "Egress", "to", "10.244.0.0/16"),
		ipBlockPolicy("server-ingress", "server", "Ingress", "from", "fd00:10:244::/56"))
	require.Equal(t, "denied", parsed["verdict"])
}

// A pod that reports only status.podIP is evaluated exactly as before.
func TestAnalyzeNetworkReachability_SingleStackIPBlockUnchanged(t *testing.T) {
	singleStackPod := func(name, ip string) *unstructured.Unstructured {
		pod := unstructuredPod("prod", name, map[string]any{"app": name})
		pod.Object["status"] = map[string]any{"podIP": ip}
		return pod
	}
	for cidr, want := range map[string]string{"10.244.0.0/16": "allowed", "fd00:10:244::/56": "denied"} {
		parsed := analyzeClientToServer(t, singleStackPod("client", "10.244.1.2"), singleStackPod("server", "10.244.2.2"),
			ipBlockPolicy("server-ingress", "server", "Ingress", "from", cidr))
		require.Equal(t, want, parsed["verdict"], cidr)
	}
}

// Pods whose reported addresses share no IP family cannot connect, with or
// without a policy; a pod that reports no address at all is not such a case.
func TestAnalyzeNetworkReachability_NoCommonIPFamilyIsDenied(t *testing.T) {
	parsed := analyzeClientToServer(t,
		dualStackPod("prod", "client", "10.244.1.2"),
		dualStackPod("prod", "server", "fd00:10:244:2::2"))
	require.Equal(t, "denied", parsed["verdict"])
	for _, direction := range []string{"egress", "ingress"} {
		require.Contains(t, parsed[direction].(map[string]any)["reason"], "no IP family in common")
	}

	parsed = analyzeClientToServer(t,
		dualStackPod("prod", "client", "10.244.1.2"),
		unstructuredPod("prod", "server", map[string]any{"app": "server"}))
	require.Equal(t, "allowed", parsed["verdict"])
}

func TestUnstructuredPodIPs(t *testing.T) {
	require.Equal(t, []string{"10.244.1.2", "fd00:10:244:1::2"},
		unstructuredPodIPs(dualStackPod("prod", "client", "10.244.1.2", "fd00:10:244:1::2").Object))
	require.Nil(t, unstructuredPodIPs(unstructuredPod("prod", "pending", nil).Object))
	require.Nil(t, unstructuredPodIPs(map[string]any{"status": map[string]any{"podIPs": "10.244.1.2"}}))
	require.Equal(t, []string{"10.244.1.2"}, unstructuredPodIPs(map[string]any{"status": map[string]any{
		"podIPs": []any{"fd00::1", map[string]any{"ip": ""}, map[string]any{"ip": 7}, map[string]any{"ip": "10.244.1.2"}},
	}}))
}
