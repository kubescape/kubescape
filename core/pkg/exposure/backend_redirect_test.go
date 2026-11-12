package exposure

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestServiceExposure_BackendRedirectDoesNotForwardToService(t *testing.T) {
	for _, namespace := range []string{"app", "backends"} {
		t.Run(namespace, func(t *testing.T) {
			route, err := decodeGatewayRoute("HTTPRoute", map[string]any{
				"metadata": map[string]any{"name": "redirect", "namespace": "app"},
				"spec": map[string]any{
					"parentRefs": []any{map[string]any{"name": "gateway"}},
					"rules": []any{map[string]any{"backendRefs": []any{map[string]any{
						"name": "private", "namespace": namespace, "port": 80,
						"filters": []any{map[string]any{"type": "RequestRedirect", "requestRedirect": map[string]any{"hostname": "public.example.com", "statusCode": 302}}},
					}}}},
				},
			})
			require.NoError(t, err)
			service := svc(namespace, "private", corev1.ServiceTypeClusterIP)
			service.Spec.Ports = []corev1.ServicePort{{Port: 80}}
			idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, []gateway{{Namespace: "app", Name: "gateway", Listeners: []listener{{Name: "http", Protocol: "HTTP", Port: 80}}}}, nil)
			paths, unclear := idx.ServiceExposure(ref(namespace, "private"))
			require.Empty(t, paths, "the gateway responds with a redirect instead of forwarding to the Service")
			require.False(t, unclear, "a redirect-only backend needs no ReferenceGrant decision to rule out forwarding")
		})
	}
}

func TestBackendRedirectPreservesOtherExposurePaths(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		otherBackend, otherRule, mirror, nodePort bool
	}{
		{name: "another forwarding backend", otherBackend: true},
		{name: "another forwarding rule", otherRule: true},
		{name: "rule-level mirror to same service", mirror: true},
		{name: "direct NodePort", nodePort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := map[string]any{"name": "private", "port": 80, "filters": []any{map[string]any{"type": "RequestRedirect", "requestRedirect": map[string]any{"hostname": "public.example.com"}}}}
			refs := []any{backend}
			if tc.otherBackend {
				refs = append(refs, map[string]any{"name": "private", "port": 80})
			}
			rule := map[string]any{"backendRefs": refs}
			if tc.mirror {
				rule["filters"] = []any{mirrorFilter(map[string]any{"name": "private", "port": 80}, nil)}
			}
			rules := []any{rule}
			if tc.otherRule {
				rules = append(rules, map[string]any{"backendRefs": []any{map[string]any{"name": "private", "port": 80}}})
			}
			route, err := decodeGatewayRoute("HTTPRoute", map[string]any{
				"metadata": map[string]any{"name": "web", "namespace": "app"},
				"spec":     map[string]any{"parentRefs": []any{map[string]any{"name": "gateway"}}, "rules": rules},
			})
			require.NoError(t, err)
			service := svc("app", "private", corev1.ServiceTypeClusterIP)
			service.Spec.Ports = []corev1.ServicePort{{Port: 80}}
			if tc.nodePort {
				service.Spec.Type = corev1.ServiceTypeNodePort
			}
			idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("app", "private"))
			require.False(t, unclear)
			require.Len(t, paths, 1, "only the redirect forwarding path should be removed")
			if tc.nodePort {
				require.Equal(t, ExposureNodePort, paths[0].Kind)
			} else {
				require.Equal(t, ExposureHTTPRoute, paths[0].Kind)
			}
		})
	}
}

func TestBackendRedirectDoesNotSuppressUnrelatedFilters(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		filter     map[string]any
		want       bool
	}{
		{name: "HTTP URL rewrite still forwards", kind: "HTTPRoute", filter: map[string]any{"type": "URLRewrite", "urlRewrite": map[string]any{"hostname": "upstream.example.com"}}, want: true},
		{name: "HTTP header modifier still forwards", kind: "HTTPRoute", filter: map[string]any{"type": "RequestHeaderModifier", "requestHeaderModifier": map[string]any{"add": []any{map[string]any{"name": "x-test", "value": "yes"}}}}, want: true},
		{name: "incomplete redirect retains conservative path", kind: "HTTPRoute", filter: map[string]any{"type": "RequestRedirect"}, want: true},
		{name: "unrelated discriminator retains path", kind: "HTTPRoute", filter: map[string]any{"type": "ExtensionRef", "requestRedirect": map[string]any{}}, want: true},
		{name: "empty redirect configuration", kind: "HTTPRoute", filter: map[string]any{"type": "RequestRedirect", "requestRedirect": map[string]any{}}},
		{name: "GRPC header modifier still forwards", kind: "GRPCRoute", filter: map[string]any{"type": "RequestHeaderModifier", "requestHeaderModifier": map[string]any{}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route, err := decodeGatewayRoute(tc.kind, map[string]any{
				"metadata": map[string]any{"name": "web", "namespace": "app"},
				"spec":     map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "private", "port": 80, "filters": []any{tc.filter}}}}}},
			})
			require.NoError(t, err)
			service := svc("app", "private", corev1.ServiceTypeClusterIP)
			service.Spec.Ports = []corev1.ServicePort{{Port: 80}}
			idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("app", "private"))
			require.False(t, unclear)
			require.Equal(t, tc.want, len(paths) > 0)
		})
	}
}
