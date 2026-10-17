package exposure

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func mirrorRoute(t *testing.T, kind string, filter map[string]any, onBackend bool, weight int) gatewayRoute {
	t.Helper()
	backend := map[string]any{"name": "primary", "port": 80, "weight": weight}
	rule := map[string]any{"backendRefs": []any{backend}}
	if onBackend {
		backend["filters"] = []any{filter}
	} else {
		rule["filters"] = []any{filter}
	}
	route, err := decodeGatewayRoute(kind, map[string]any{
		"metadata": map[string]any{"name": "web", "namespace": "app"},
		"spec":     map[string]any{"parentRefs": []any{map[string]any{"name": "public"}}, "hostnames": []any{"api.example.com"}, "rules": []any{rule}},
	})
	require.NoError(t, err)
	return route
}

func mirrorFilter(backend map[string]any, sampling map[string]any) map[string]any {
	mirror := map[string]any{"backendRef": backend}
	for k, v := range sampling {
		mirror[k] = v
	}
	return map[string]any{"type": "RequestMirror", "requestMirror": mirror}
}

func TestRequestMirrorExposesShadowBackend(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, onBackend := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/rule", true: "/backend"}[onBackend], func(t *testing.T) {
				route := mirrorRoute(t, kind, mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), onBackend, 1)
				service := svc("app", "shadow", corev1.ServiceTypeClusterIP)
				service.Spec.Ports = []corev1.ServicePort{{Port: 80}}
				gw := gateway{Namespace: "app", Name: "public", Listeners: []listener{{Protocol: "HTTP", Port: 80, Hostname: "*.example.com"}}}
				idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
				paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
				require.False(t, unclear)
				require.Len(t, paths, 1, "a copy of an external request still reaches the shadow service")
				require.Equal(t, routeExposureKind(kind), paths[0].Kind)
				require.Equal(t, "api.example.com", paths[0].Host)
				require.Equal(t, "app/web", paths[0].Source)
			})
		}
	}
}

func TestRequestMirrorSampling(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sampling map[string]any
		exposed  bool
	}{
		{name: "default all requests", exposed: true},
		{name: "one percent", sampling: map[string]any{"percent": 1}, exposed: true},
		{name: "all requests", sampling: map[string]any{"percent": 100}, exposed: true},
		{name: "zero percent", sampling: map[string]any{"percent": 0}},
		{name: "positive fraction", sampling: map[string]any{"fraction": map[string]any{"numerator": 1, "denominator": 10000}}, exposed: true},
		{name: "default denominator", sampling: map[string]any{"fraction": map[string]any{"numerator": 1}}, exposed: true},
		{name: "zero fraction", sampling: map[string]any{"fraction": map[string]any{"numerator": 0, "denominator": 100}}},
	} {
		for _, onBackend := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/rule", true: "/backend"}[onBackend], func(t *testing.T) {
				r := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "port": 80}, tc.sampling), onBackend, 1)
				idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{r}, nil, nil)
				paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
				require.False(t, unclear)
				require.Equal(t, tc.exposed, len(paths) > 0)
			})
		}
	}
}

func TestRequestMirrorReferenceValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend map[string]any
		want    bool
	}{
		{name: "default service", backend: map[string]any{"name": "shadow", "port": 80}, want: true},
		{name: "explicit core service", backend: map[string]any{"name": "shadow", "port": 80, "group": "", "kind": "Service"}, want: true},
		{name: "other kind", backend: map[string]any{"name": "shadow", "port": 80, "kind": "ServiceImport"}},
		{name: "other group", backend: map[string]any{"name": "shadow", "port": 80, "group": "example.io"}},
		{name: "wrong service port", backend: map[string]any{"name": "shadow", "port": 90}},
		{name: "wrong service name", backend: map[string]any{"name": "other", "port": 80}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mirrorRoute(t, "HTTPRoute", mirrorFilter(tc.backend, nil), false, 1)
			service := svc("app", "shadow", corev1.ServiceTypeClusterIP)
			service.Spec.Ports = []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt32(8080)}}
			idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{r}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
			require.False(t, unclear)
			require.Equal(t, tc.want, len(paths) > 0)
		})
	}
}

func TestRequestMirrorCrossNamespaceIsUncertain(t *testing.T) {
	for _, sampling := range []map[string]any{nil, {"percent": 0}} {
		r := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "namespace": "other", "port": 80}, sampling), false, 1)
		idx := NewIndex([]corev1.Service{svc("other", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{r}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("other", "shadow"))
		require.Empty(t, paths)
		require.Equal(t, sampling == nil, unclear, "no ReferenceGrants were supplied, so an active cross-namespace mirror cannot be declared safe")
	}
}

func TestBackendMirrorRequiresActiveParent(t *testing.T) {
	for _, onBackend := range []bool{false, true} {
		r := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), onBackend, 0)
		idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{r}, nil, nil)
		paths, _ := idx.ServiceExposure(ref("app", "shadow"))
		require.Equal(t, !onBackend, len(paths) > 0, "rule filters apply independently of the weight of an individual backend")
	}
}

func TestMirrorDecoderPreservesOrdinaryBackends(t *testing.T) {
	r := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), false, 1)
	idx := NewIndex([]corev1.Service{svc("app", "primary", corev1.ServiceTypeClusterIP), svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{r}, nil, nil)
	for _, name := range []string{"primary", "shadow"} {
		paths, unclear := idx.ServiceExposure(ref("app", name))
		require.False(t, unclear)
		require.Len(t, paths, 1)
	}
}

func TestRequestMirrorThroughResourceAdapter(t *testing.T) {
	raw := map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "web", "namespace": "app"},
		"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "rules": []any{map[string]any{
			"filters": []any{mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil)},
		}}},
	}
	resource := workloadinterface.NewWorkloadObj(raw)
	routes, gateways, errs := FromUnstructuredGatewayAPI(map[string]workloadinterface.IMetadata{resource.GetID(): resource})
	require.Empty(t, errs)
	require.Len(t, routes, 1)
	idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, routes, gateways, nil)
	paths, _ := idx.ServiceExposure(ref("app", "shadow"))
	require.Len(t, paths, 1)
}

func TestRequestMirrorRespectsGatewayAdmission(t *testing.T) {
	for _, tc := range []struct {
		name             string
		protocol         string
		listenerHost     string
		gatewayNamespace string
		includeParent    bool
		want             bool
	}{
		{name: "admitted hostname", protocol: "HTTPS", listenerHost: "*.example.com", gatewayNamespace: "app", includeParent: true, want: true},
		{name: "hostname outside listener", protocol: "HTTP", listenerHost: "internal.example.org", gatewayNamespace: "app", includeParent: true},
		{name: "transport listener cannot accept HTTP route", protocol: "TCP", gatewayNamespace: "app", includeParent: true},
		{name: "no parent reference", protocol: "HTTP", gatewayNamespace: "app"},
		{name: "default namespace restriction", protocol: "HTTP", gatewayNamespace: "edge", includeParent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := mirrorRoute(t, "HTTPRoute", mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil), false, 1)
			if tc.includeParent {
				route.ParentRefs[0].Namespace = &tc.gatewayNamespace
			} else {
				route.ParentRefs = nil
			}
			g := gateway{Namespace: tc.gatewayNamespace, Name: "public", Listeners: []listener{{Protocol: tc.protocol, Port: 80, Hostname: tc.listenerHost}}}
			idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{g}, nil)
			paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
			require.False(t, unclear)
			require.Equal(t, tc.want, len(paths) > 0)
		})
	}
}

func TestRequestMirrorRepeatedReferencesHaveOneRoutePath(t *testing.T) {
	filter := mirrorFilter(map[string]any{"name": "shadow", "port": 80}, nil)
	route, err := decodeGatewayRoute("HTTPRoute", map[string]any{
		"metadata": map[string]any{"name": "web", "namespace": "app"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "public"}},
			"rules": []any{
				map[string]any{"filters": []any{filter, filter}, "backendRefs": []any{
					map[string]any{"name": "shadow", "port": 80, "filters": []any{filter}},
				}},
				map[string]any{"filters": []any{filter}},
			},
		},
	})
	require.NoError(t, err)
	idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
	require.False(t, unclear)
	require.Len(t, paths, 1, "the exposure identity remains route plus hostname, not the number of references")
}

func TestRequestMirrorIgnoresOtherFilterTypes(t *testing.T) {
	for _, filter := range []map[string]any{
		{"type": "RequestHeaderModifier"},
		{"type": "RequestMirror"},
		{"type": "ResponseHeaderModifier", "requestMirror": map[string]any{"backendRef": map[string]any{"name": "shadow", "port": 80}}},
	} {
		route := mirrorRoute(t, "HTTPRoute", filter, false, 1)
		idx := NewIndex([]corev1.Service{svc("app", "shadow", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("app", "shadow"))
		require.Empty(t, paths)
		require.False(t, unclear)
	}
}

func TestRequestMirrorMalformedPortProducesAdapterWarning(t *testing.T) {
	object := map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "invalid-mirror", "namespace": "app"},
		"spec": map[string]any{"rules": []any{map[string]any{
			"filters": []any{mirrorFilter(map[string]any{"name": "shadow", "port": "eighty"}, nil)},
		}}},
	}
	resource := workloadinterface.NewWorkloadObj(object)
	routes, _, errs := FromUnstructuredGatewayAPI(map[string]workloadinterface.IMetadata{resource.GetID(): resource})
	require.Empty(t, routes)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "invalid-mirror")
	require.Contains(t, errs[0].Error(), "port")
}
