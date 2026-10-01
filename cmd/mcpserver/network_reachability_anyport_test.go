package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeNetworkReachability_AnyPort(t *testing.T) {
	for _, tc := range []struct {
		name, ingressProtocol, want string
		ingressPort                 any
	}{
		{"disjoint ports", "TCP", "denied", int64(443)},
		{"disjoint protocols", "UDP", "denied", int64(80)},
		{"shared port", "TCP", "allowed", int64(80)},
		{"named port", "TCP", "unknown", "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := unstructuredNetworkPolicy("ns", "client-egress", map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{"app": "client"}},
				"policyTypes": []any{"Egress"},
				"egress":      []any{map[string]any{"ports": []any{map[string]any{"protocol": "TCP", "port": int64(80)}}}},
			})
			in := unstructuredNetworkPolicy("ns", "server-ingress", map[string]any{
				"podSelector": map[string]any{"matchLabels": map[string]any{"app": "server"}},
				"policyTypes": []any{"Ingress"},
				"ingress":     []any{map[string]any{"ports": []any{map[string]any{"protocol": tc.ingressProtocol, "port": tc.ingressPort}}}},
			})
			ks := newReachabilityTestServer(out, in,
				unstructuredPod("ns", "client", map[string]any{"app": "client"}),
				unstructuredPod("ns", "server", map[string]any{"app": "server"}))
			for _, query := range []struct {
				port     float64
				protocol string
			}{{}, {protocol: "UDP"}, {port: 80}, {port: 443}} {
				args := map[string]any{
					"source_namespace": "ns", "source_pod": "client",
					"destination_namespace": "ns", "destination_pod": "server",
				}
				if query.port != 0 {
					args["port"] = query.port
				} else if query.protocol != "" {
					// Preserve the existing contract: protocol is ignored when
					// port is omitted, so a TCP overlap is still considered.
					args["protocol"] = query.protocol
				}
				result := registeredToolResult(t, dispatchRegisteredTool(t, ks, "analyze_network_reachability", args))
				require.False(t, result.IsError)
				var parsed struct {
					Verdict string `json:"verdict"`
					Egress  struct {
						Verdict       string `json:"verdict"`
						Reason        string `json:"reason"`
						MatchedPolicy string `json:"matched_policy"`
					} `json:"egress"`
					Ingress struct {
						Verdict       string `json:"verdict"`
						Reason        string `json:"reason"`
						MatchedPolicy string `json:"matched_policy"`
					} `json:"ingress"`
				}
				require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
				want := tc.want
				if query.port == 443 {
					want = "denied"
				}
				require.Equal(t, want, parsed.Verdict, "query=%+v", query)
				if query.port == 0 {
					require.Equal(t, "allowed", parsed.Egress.Verdict)
					require.Equal(t, "ns/client-egress", parsed.Egress.MatchedPolicy)
					if want == "unknown" {
						require.Equal(t, "unknown", parsed.Ingress.Verdict)
						require.Empty(t, parsed.Ingress.MatchedPolicy)
					} else {
						require.Equal(t, "allowed", parsed.Ingress.Verdict)
						require.Equal(t, "ns/server-ingress", parsed.Ingress.MatchedPolicy)
					}
					if want == "denied" {
						require.Contains(t, parsed.Egress.Reason, "no common port/protocol")
						require.Contains(t, parsed.Ingress.Reason, "no common port/protocol")
					} else {
						require.Contains(t, parsed.Egress.Reason, "80/TCP")
						require.Contains(t, parsed.Ingress.Reason, "80/TCP")
					}
				}
			}
		})
	}
}
