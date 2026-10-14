package exposure

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestBackendPort_MissingServicePortIsNotExposure(t *testing.T) {
	service := svc("ns", "app", corev1.ServiceTypeClusterIP)
	service.Spec.Ports = []corev1.ServicePort{{Name: "http", Port: 80}}
	route, err := decodeGatewayRoute("HTTPRoute", map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": "ns"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": 8080}}}},
		},
	})
	require.NoError(t, err)
	idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths, "a missing Service port cannot forward traffic to this backend")
	require.False(t, unclear)
}

func backendPortService() corev1.Service {
	service := svc("ns", "app", corev1.ServiceTypeClusterIP)
	service.Spec.Ports = []corev1.ServicePort{
		{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080), NodePort: 30080},
		{Name: "https", Port: 443, TargetPort: intstr.FromString("tls"), Protocol: corev1.ProtocolTCP},
		{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP},
	}
	return service
}

func backendPortRoute(t *testing.T, kind, namespace string, backends []any) gatewayRoute {
	t.Helper()
	route, err := decodeGatewayRoute(kind, map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": namespace},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"rules":      []any{map[string]any{"backendRefs": backends}},
		},
	})
	require.NoError(t, err)
	return route
}

func TestBackendPort_GatewayReferencesUseServiceNotTargetOrNodePorts(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, tc := range []struct {
			name string
			port any
			want bool
		}{
			{"service http", 80, true},
			{"service https", 443, true},
			{"container target", 8080, false},
			{"node port", 30080, false},
			{"UDP service port", 53, false},
			{"unlisted port", 8443, false},
			{"zero", 0, false},
			{"negative", -1, false},
			{"out of range", 65536, false},
			{"omitted", nil, false},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				backend := map[string]any{"name": "app"}
				if tc.port != nil {
					backend["port"] = tc.port
				}
				route := backendPortRoute(t, kind, "ns", []any{backend})
				idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
				paths, unclear := idx.ServiceExposure(ref("ns", "app"))
				require.Equal(t, tc.want, len(paths) > 0)
				require.False(t, unclear)
				if tc.want {
					require.Len(t, paths, 1)
					require.Equal(t, routeExposureKind(kind), paths[0].Kind)
					require.Equal(t, "ns/route", paths[0].Source)
				}
			})
		}
	}
}

func TestBackendPort_CrossNamespaceUncertaintyRequiresExistingServicePort(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, port := range []int32{80, 443, 53, 8080, 30080} {
			route := backendPortRoute(t, kind, "other", []any{map[string]any{"name": "app", "namespace": "ns", "port": port}})
			idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("ns", "app"))
			require.Empty(t, paths)
			require.Equal(t, port == 80 || port == 443, unclear, "kind=%s port=%d", kind, port)
		}
	}
}

func TestBackendPort_IngressNamedAndNumericReferences(t *testing.T) {
	for _, tc := range []struct {
		name string
		port networkingv1.ServiceBackendPort
		want bool
	}{
		{"numeric http", networkingv1.ServiceBackendPort{Number: 80}, true},
		{"numeric https", networkingv1.ServiceBackendPort{Number: 443}, true},
		{"named http", networkingv1.ServiceBackendPort{Name: "http"}, true},
		{"named https", networkingv1.ServiceBackendPort{Name: "https"}, true},
		{"named target", networkingv1.ServiceBackendPort{Name: "tls"}, false},
		{"wrong case", networkingv1.ServiceBackendPort{Name: "HTTP"}, false},
		{"missing name", networkingv1.ServiceBackendPort{Name: "admin"}, false},
		{"target number", networkingv1.ServiceBackendPort{Number: 8080}, false},
		{"node number", networkingv1.ServiceBackendPort{Number: 30080}, false},
		{"UDP name", networkingv1.ServiceBackendPort{Name: "dns"}, false},
		{"UDP number", networkingv1.ServiceBackendPort{Number: 53}, false},
		{"empty", networkingv1.ServiceBackendPort{}, false},
	} {
		for _, defaultBackend := range []bool{false, true} {
			t.Run(tc.name+"/default="+map[bool]string{false: "no", true: "yes"}[defaultBackend], func(t *testing.T) {
				backend := networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app", Port: tc.port}}
				ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ingress"}}
				if defaultBackend {
					ing.Spec.DefaultBackend = &backend
				} else {
					ing.Spec.Rules = []networkingv1.IngressRule{{Host: "app.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{Backend: backend}},
					}}}}
				}
				idx := NewIndex([]corev1.Service{backendPortService()}, []networkingv1.Ingress{ing}, nil, nil, nil)
				paths, unclear := idx.ServiceExposure(ref("ns", "app"))
				require.Equal(t, tc.want, len(paths) > 0)
				require.False(t, unclear)
				if tc.want {
					require.Equal(t, ExposureIngress, paths[0].Kind)
					require.Equal(t, "ns/ingress", paths[0].Source)
				}
			})
		}
	}
}

func TestBackendPort_InvalidBackendDoesNotHideLaterValidBackend(t *testing.T) {
	for _, namespace := range []string{"ns", "other"} {
		route := backendPortRoute(t, "HTTPRoute", namespace, []any{
			map[string]any{"name": "app", "namespace": "ns", "port": 8080},
			map[string]any{"name": "app", "namespace": "ns", "port": 443},
		})
		idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("ns", "app"))
		if namespace == "ns" {
			require.Len(t, paths, 1)
			require.False(t, unclear)
		} else {
			require.Empty(t, paths)
			require.True(t, unclear)
		}
	}
}

func TestBackendPort_ZeroWeightAndNonServiceBackendsRemainExcluded(t *testing.T) {
	for _, backend := range []map[string]any{
		{"name": "app", "port": 80, "weight": 0},
		{"name": "app", "port": 80, "kind": "ServiceImport"},
		{"name": "app", "port": 80, "group": "custom.example"},
	} {
		for _, namespace := range []string{"ns", "other"} {
			backend["namespace"] = "ns"
			route := backendPortRoute(t, "HTTPRoute", namespace, []any{backend})
			idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
			paths, unclear := idx.ServiceExposure(ref("ns", "app"))
			require.Empty(t, paths)
			require.False(t, unclear)
		}
	}
}

func TestBackendPort_IndependentServiceExposureIsPreserved(t *testing.T) {
	for _, serviceType := range []corev1.ServiceType{corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeClusterIP} {
		service := backendPortService()
		service.Spec.Type = serviceType
		if serviceType == corev1.ServiceTypeClusterIP {
			service.Spec.ExternalIPs = []string{"203.0.113.5"}
		}
		route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "app", "port": 8080}})
		idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("ns", "app"))
		require.Len(t, paths, 1)
		require.NotEqual(t, ExposureHTTPRoute, paths[0].Kind)
		require.False(t, unclear)
	}
}

func TestBackendPort_UnknownServicePortsRetainConservativeBehavior(t *testing.T) {
	for _, namespace := range []string{"ns", "other"} {
		service := svc("ns", "app", corev1.ServiceTypeClusterIP)
		route := backendPortRoute(t, "GRPCRoute", namespace, []any{map[string]any{"name": "app", "namespace": "ns", "port": 9090}})
		idx := NewIndex([]corev1.Service{service}, nil, []gatewayRoute{route}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("ns", "app"))
		require.Equal(t, namespace == "ns", len(paths) > 0)
		require.Equal(t, namespace != "ns", unclear)
	}
	require.True(t, serviceBackendPortMatches(nil, "", 80))
}

func TestBackendPort_DecodePreservesPortIndependentlyOfWeight(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		route := backendPortRoute(t, kind, "ns", []any{
			map[string]any{"name": "app", "port": 80, "weight": 0},
			map[string]any{"name": "app", "port": 443, "weight": 2},
			map[string]any{"name": "app"},
		})
		require.Equal(t, int32(80), *route.Rules[0].BackendRefs[0].Port)
		require.Zero(t, *route.Rules[0].BackendRefs[0].Weight)
		require.Equal(t, int32(443), *route.Rules[0].BackendRefs[1].Port)
		require.Equal(t, int32(2), *route.Rules[0].BackendRefs[1].Weight)
		require.Nil(t, route.Rules[0].BackendRefs[2].Port)
	}
}

func TestBackendPort_UnstructuredPipelineRejectsTargetPortOnlyRoute(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, port := range []int{80, 8080} {
			service := unstructuredResource(map[string]any{
				"apiVersion": "v1", "kind": "Service",
				"metadata": map[string]any{"name": "app", "namespace": "ns"},
				"spec":     map[string]any{"ports": []any{map[string]any{"name": "http", "port": 80, "targetPort": 8080}}},
			})
			route := unstructuredResource(map[string]any{
				"apiVersion": "gateway.networking.k8s.io/v1", "kind": kind,
				"metadata": map[string]any{"name": "route", "namespace": "ns"},
				"spec": map[string]any{
					"parentRefs": []any{map[string]any{"name": "gw"}},
					"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": port}}}},
				},
			})
			resources := map[string]workloadinterface.IMetadata{service.GetID(): service, route.GetID(): route}
			services, ingresses, namespaces, errs := FromResources(resources)
			require.Empty(t, errs)
			routes, gateways, errs := FromUnstructuredGatewayAPI(resources)
			require.Empty(t, errs)
			idx := NewIndex(services, ingresses, routes, gateways, namespaces)
			paths, unclear := idx.ServiceExposure(ref("ns", "app"))
			require.Equal(t, port == 80, len(paths) > 0)
			require.False(t, unclear)
		}
	}
}

func TestBackendPort_ProtocolSpecificPortsDoNotShadowTCPPort(t *testing.T) {
	service := backendPortService()
	service.Spec.Ports = []corev1.ServicePort{
		{Name: "udp", Port: 80, Protocol: corev1.ProtocolUDP},
		{Name: "sctp", Port: 80, Protocol: corev1.ProtocolSCTP},
		{Name: "tcp", Port: 80, Protocol: corev1.ProtocolTCP},
	}
	require.True(t, serviceBackendPortMatches(&service, "", 80))
	require.True(t, serviceBackendPortMatches(&service, "tcp", 0))
	require.False(t, serviceBackendPortMatches(&service, "udp", 0))
	require.False(t, serviceBackendPortMatches(&service, "sctp", 0))
}

func TestBackendPort_DifferentServiceCannotLendItsPort(t *testing.T) {
	app := backendPortService()
	other := svc("ns", "other", corev1.ServiceTypeClusterIP)
	other.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
	route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "app", "port": 8080}})
	idx := NewIndex([]corev1.Service{app, other}, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
	paths, unclear = idx.ServiceExposure(ref("ns", "other"))
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestBackendPort_MissingServiceStillHasNoExposure(t *testing.T) {
	route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "missing", "port": 80}})
	idx := NewIndex(nil, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "missing"))
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestBackendPort_ListenerAdmissionIsStillRequired(t *testing.T) {
	route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "app", "port": 80}})
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "http", Protocol: "HTTP", Port: 80, Hostname: "public.example"}}}
	route.Hostnames = []string{"private.example"}
	idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
	route.Hostnames = []string{"public.example"}
	idx = NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
	paths, unclear = idx.ServiceExposure(ref("ns", "app"))
	require.Len(t, paths, 1)
	require.Equal(t, "public.example", paths[0].Host)
	require.False(t, unclear)
}

func TestBackendPort_ParentListenerPortAndBackendPortAreIndependent(t *testing.T) {
	route := backendPortRoute(t, "GRPCRoute", "ns", []any{map[string]any{"name": "app", "port": 443}})
	listenerPort := int32(8443)
	route.ParentRefs[0].Port = &listenerPort
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "tls", Protocol: "HTTPS", Port: 8443}}}
	idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Len(t, paths, 1)
	require.False(t, unclear)
	backendPort := int32(8443)
	route.Rules[0].BackendRefs[0].Port = &backendPort
	idx = NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
	paths, unclear = idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestBackendPort_SameNamedServiceInAnotherNamespaceCannotSupplyPort(t *testing.T) {
	app := backendPortService()
	other := svc("other", "app", corev1.ServiceTypeClusterIP)
	other.Spec.Ports = []corev1.ServicePort{{Port: 8080}}
	route := backendPortRoute(t, "HTTPRoute", "other", []any{map[string]any{"name": "app", "namespace": "ns", "port": 8080}})
	idx := NewIndex([]corev1.Service{app, other}, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
	paths, unclear = idx.ServiceExposure(ref("other", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestBackendPort_IngressPathsKeepValidHostOnly(t *testing.T) {
	ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "ns"}}
	for _, port := range []int32{8080, 443} {
		host := "invalid.example"
		if port == 443 {
			host = "valid.example"
		}
		ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: host, IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
			Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app", Port: networkingv1.ServiceBackendPort{Number: port}}}}},
		}}})
	}
	idx := NewIndex([]corev1.Service{backendPortService()}, []networkingv1.Ingress{ing}, nil, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Len(t, paths, 1)
	require.Equal(t, "valid.example", paths[0].Host)
	require.False(t, unclear)
}

func TestBackendPort_ServicePortRangeBoundaries(t *testing.T) {
	service := backendPortService()
	service.Spec.Ports = []corev1.ServicePort{{Port: 1}, {Port: 65535}}
	for _, port := range []int32{1, 65535} {
		require.True(t, serviceBackendPortMatches(&service, "", port))
	}
	for _, port := range []int32{0, -1, 2, 65534, 65536} {
		require.False(t, serviceBackendPortMatches(&service, "", port))
	}
}

func TestBackendPort_InvalidWirePortIsReportedAsDecodeError(t *testing.T) {
	for _, invalid := range []any{"http", float64(80.5), map[string]any{"number": 80}} {
		_, err := decodeGatewayRoute("HTTPRoute", map[string]any{
			"metadata": map[string]any{"name": "route", "namespace": "ns"},
			"spec":     map[string]any{"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app", "port": invalid}}}}},
		})
		require.Error(t, err)
	}
}

func TestBackendPort_UnstructuredIngressUsesNamedServicePort(t *testing.T) {
	for _, portName := range []string{"http", "container-http"} {
		service := unstructuredResource(map[string]any{
			"apiVersion": "v1", "kind": "Service",
			"metadata": map[string]any{"name": "app", "namespace": "ns"},
			"spec":     map[string]any{"ports": []any{map[string]any{"name": "http", "port": 80, "targetPort": "container-http"}}},
		})
		ingress := unstructuredResource(map[string]any{
			"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
			"metadata": map[string]any{"name": "ingress", "namespace": "ns"},
			"spec":     map[string]any{"defaultBackend": map[string]any{"service": map[string]any{"name": "app", "port": map[string]any{"name": portName}}}},
		})
		resources := map[string]workloadinterface.IMetadata{service.GetID(): service, ingress.GetID(): ingress}
		services, ingresses, namespaces, errs := FromResources(resources)
		require.Empty(t, errs)
		idx := NewIndex(services, ingresses, nil, nil, namespaces)
		paths, unclear := idx.ServiceExposure(ref("ns", "app"))
		require.Equal(t, portName == "http", len(paths) > 0)
		require.False(t, unclear)
	}
}

func TestBackendPort_IngressResourceBackendNeverNamesService(t *testing.T) {
	ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "ns"}, Spec: networkingv1.IngressSpec{
		DefaultBackend: &networkingv1.IngressBackend{Resource: &corev1.TypedLocalObjectReference{Kind: "StorageBucket", Name: "app"}},
	}}
	idx := NewIndex([]corev1.Service{backendPortService()}, []networkingv1.Ingress{ing}, nil, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Empty(t, paths)
	require.False(t, unclear)
}

func TestBackendPort_PositiveWeightDoesNotChangePortResolution(t *testing.T) {
	for _, port := range []int32{80, 8080} {
		route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "app", "port": port, "weight": 5}})
		idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
		paths, unclear := idx.ServiceExposure(ref("ns", "app"))
		require.Equal(t, port == 80, len(paths) > 0)
		require.False(t, unclear)
	}
}

func TestBackendPort_PortlessIngressInventoryRetainsPossibleExposure(t *testing.T) {
	service := svc("ns", "app", corev1.ServiceTypeClusterIP)
	ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "ingress", Namespace: "ns"}, Spec: networkingv1.IngressSpec{
		DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app", Port: networkingv1.ServiceBackendPort{Number: 80}}},
	}}
	idx := NewIndex([]corev1.Service{service}, []networkingv1.Ingress{ing}, nil, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Len(t, paths, 1)
	require.Equal(t, ExposureIngress, paths[0].Kind)
	require.False(t, unclear)
}

func TestBackendPort_ExplicitNamespaceStillUsesMatchingLocalPort(t *testing.T) {
	route := backendPortRoute(t, "HTTPRoute", "ns", []any{map[string]any{"name": "app", "namespace": "ns", "port": 80}})
	idx := NewIndex([]corev1.Service{backendPortService()}, nil, []gatewayRoute{route}, nil, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	require.Len(t, paths, 1)
	require.Equal(t, ExposureHTTPRoute, paths[0].Kind)
	require.False(t, unclear)
}
