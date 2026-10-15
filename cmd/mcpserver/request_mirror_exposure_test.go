package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestVulnerabilityExposureIncludesRequestMirror(t *testing.T) {
	for _, tc := range []struct {
		name         string
		percent      int64
		wantExposure bool
		onBackend    bool
		parentPort   int64
	}{
		{name: "active mirror", percent: 1, wantExposure: true},
		{name: "disabled mirror", percent: 0},
		{name: "backend mirror with valid parent", percent: 1, wantExposure: true, onBackend: true, parentPort: 80},
		{name: "backend mirror with mismatched parent port", percent: 1, onBackend: true, parentPort: 90},
		{name: "backend mirror with uncollected parent", percent: 1, wantExposure: true, onBackend: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deploy := unstructuredDeployment("prod", "shadow", map[string]any{"app": "shadow"})
			service := unstructuredServiceWithSelector("prod", "shadow-svc", "ClusterIP", map[string]any{"app": "shadow"})
			// No direct backend or public Service type exposes this workload. The
			// only outside-in path is the copy sent by RequestMirror.
			route := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1",
				"kind":       "HTTPRoute",
				"metadata":   map[string]any{"namespace": "prod", "name": "public-api"},
				"spec": map[string]any{
					"parentRefs": []any{map[string]any{"name": "public"}},
					"hostnames":  []any{"api.example.com"},
					"rules": []any{map[string]any{
						"backendRefs": []any{map[string]any{"name": "primary", "port": int64(80)}},
						"filters": []any{map[string]any{
							"type": "RequestMirror",
							"requestMirror": map[string]any{
								"backendRef": map[string]any{"name": "shadow-svc", "port": int64(80)},
								"percent":    tc.percent,
							},
						}},
					}},
				},
			}}
			if tc.onBackend {
				rule := route.Object["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)
				backend := rule["backendRefs"].([]any)[0].(map[string]any)
				backend["filters"] = rule["filters"]
				delete(rule, "filters")
			}

			gateway := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1",
				"kind":       "Gateway",
				"metadata":   map[string]any{"namespace": "prod", "name": "public"},
				"spec": map[string]any{"listeners": []any{map[string]any{
					"name": "http", "port": int64(80), "protocol": "HTTP",
				}}},
			}}
			manifest := vulnerabilityManifest("prod", "shadow-vulns",
				"wlid://cluster-test/namespace-prod/deployment-shadow", criticalMatch("CVE-2026-12345"))
			objects := []runtime.Object{deploy, service, route, gateway}
			if tc.parentPort != 0 {
				primary := unstructuredServiceWithSelector("prod", "primary", "ClusterIP", map[string]any{"app": "primary"})
				primary.Object["spec"].(map[string]any)["ports"] = []any{map[string]any{"port": tc.parentPort}}
				objects = append(objects, primary)
			}
			tool := newVulnExposureTestServer(t, objects, manifest)
			result := registeredToolResult(t, dispatchRegisteredTool(t, tool, "analyze_vulnerability_exposure", map[string]any{}))
			require.False(t, result.IsError)
			var parsed map[string]any
			require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &parsed))
			findings, ok := parsed["findings"].([]any)
			require.True(t, ok)
			require.Len(t, findings, 1)
			finding := findings[0].(map[string]any)
			require.Equal(t, "CVE-2026-12345", finding["cve_id"])
			paths, _ := finding["external_exposure"].([]any)
			if tc.wantExposure {
				require.Len(t, paths, 1)
				path := paths[0].(map[string]any)
				require.Equal(t, "HTTPRoute", path["kind"])
				require.Equal(t, "api.example.com", path["host"])
			} else {
				require.Empty(t, paths)
			}
		})
	}
}
