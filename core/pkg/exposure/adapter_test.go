package exposure

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
)

func unstructuredResource(obj map[string]any) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(obj)
}

func TestFromResources_ExtractsServicesIngressesAndNamespacesOnly(t *testing.T) {
	s := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "app", "namespace": "prod"},
		"spec":       map[string]any{"type": "LoadBalancer"},
	})
	ing := unstructuredResource(map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "Ingress",
		"metadata":   map[string]any{"name": "web", "namespace": "prod"},
		"spec": map[string]any{
			"defaultBackend": map[string]any{"service": map[string]any{"name": "app"}},
		},
	})
	ns := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": "prod", "labels": map[string]any{"env": "prod"}},
	})
	pod := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "app", "namespace": "prod"},
	})

	resources := map[string]workloadinterface.IMetadata{
		s.GetID():   s,
		ing.GetID(): ing,
		ns.GetID():  ns,
		pod.GetID(): pod,
	}

	services, ingresses, namespaces, errs := FromResources(resources)

	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(services) != 1 || services[0].Name != "app" {
		t.Errorf("services = %+v, want one named app", services)
	}
	if len(ingresses) != 1 || ingresses[0].Name != "web" {
		t.Errorf("ingresses = %+v, want one named web", ingresses)
	}
	if len(namespaces) != 1 || namespaces[0].Name != "prod" || namespaces[0].Labels["env"] != "prod" {
		t.Errorf("namespaces = %+v, want one prod with env=prod", namespaces)
	}
}

func TestFromResources_MalformedServiceIsSkippedNotFatal(t *testing.T) {
	good := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "good", "namespace": "ns"},
		"spec":       map[string]any{"type": "ClusterIP"},
	})
	bad := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "bad", "namespace": "ns"},
		// type must be a string; this cannot decode into corev1.ServiceType.
		"spec": map[string]any{"type": 12345},
	})

	resources := map[string]workloadinterface.IMetadata{
		good.GetID(): good,
		bad.GetID():  bad,
	}

	services, _, _, errs := FromResources(resources)

	if len(services) != 1 || services[0].Name != "good" {
		t.Fatalf("expected the well-formed Service to still decode, got %+v", services)
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly one decode error, got %d: %v", len(errs), errs)
	}
}

func TestFromUnstructuredGatewayAPI_DecodesHTTPRouteAndGateway(t *testing.T) {
	route := unstructuredResource(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "route", "namespace": "ns"},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": "gw"}},
			"hostnames":  []any{"app.example.com"},
			"rules": []any{
				map[string]any{"backendRefs": []any{map[string]any{"name": "app"}}},
			},
		},
	})
	gw := unstructuredResource(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "Gateway",
		"metadata":   map[string]any{"name": "gw", "namespace": "ns"},
		"spec": map[string]any{
			"listeners": []any{
				map[string]any{
					"name": "http",
					"allowedRoutes": map[string]any{
						"namespaces": map[string]any{
							"from": "Selector",
							"selector": map[string]any{
								"matchLabels": map[string]any{"team": "payments"},
							},
						},
					},
				},
			},
		},
	})

	resources := map[string]workloadinterface.IMetadata{
		route.GetID(): route,
		gw.GetID():    gw,
	}

	httpRoutes, gateways, errs := FromUnstructuredGatewayAPI(resources)

	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(httpRoutes) != 1 {
		t.Fatalf("httpRoutes = %+v, want one", httpRoutes)
	}
	r := httpRoutes[0]
	if r.Namespace != "ns" || r.Name != "route" || len(r.ParentRefs) != 1 || r.ParentRefs[0].Name != "gw" {
		t.Errorf("route decoded incorrectly: %+v", r)
	}
	if len(r.Hostnames) != 1 || r.Hostnames[0] != "app.example.com" {
		t.Errorf("route.Hostnames = %v, want [app.example.com]", r.Hostnames)
	}
	if len(r.Rules) != 1 || len(r.Rules[0].BackendRefs) != 1 || r.Rules[0].BackendRefs[0].Name != "app" {
		t.Errorf("route.Rules decoded incorrectly: %+v", r.Rules)
	}

	if len(gateways) != 1 {
		t.Fatalf("gateways = %+v, want one", gateways)
	}
	g := gateways[0]
	if g.Namespace != "ns" || g.Name != "gw" || len(g.Listeners) != 1 {
		t.Fatalf("gateway decoded incorrectly: %+v", g)
	}
	l := g.Listeners[0]
	if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil || l.AllowedRoutes.Namespaces.From == nil || *l.AllowedRoutes.Namespaces.From != fromSelector {
		t.Fatalf("listener.AllowedRoutes decoded incorrectly: %+v", l.AllowedRoutes)
	}
	if l.AllowedRoutes.Namespaces.Selector == nil || l.AllowedRoutes.Namespaces.Selector.MatchLabels["team"] != "payments" {
		t.Errorf("listener.AllowedRoutes.Namespaces.Selector decoded incorrectly: %+v", l.AllowedRoutes.Namespaces.Selector)
	}
}

func TestFromUnstructuredGatewayAPI_IgnoresOtherKinds(t *testing.T) {
	pod := unstructuredResource(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "app", "namespace": "ns"},
	})
	resources := map[string]workloadinterface.IMetadata{pod.GetID(): pod}

	httpRoutes, gateways, errs := FromUnstructuredGatewayAPI(resources)
	if len(httpRoutes) != 0 || len(gateways) != 0 || len(errs) != 0 {
		t.Errorf("httpRoutes=%v gateways=%v errs=%v, want all empty", httpRoutes, gateways, errs)
	}
}

func TestFromUnstructuredGatewayAPI_MalformedHTTPRouteIsSkippedNotFatal(t *testing.T) {
	good := unstructuredResource(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "good", "namespace": "ns"},
		"spec":       map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}},
	})
	bad := unstructuredResource(map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"name": "bad", "namespace": "ns"},
		// hostnames must be a list of strings.
		"spec": map[string]any{"hostnames": 12345},
	})

	resources := map[string]workloadinterface.IMetadata{
		good.GetID(): good,
		bad.GetID():  bad,
	}

	httpRoutes, _, errs := FromUnstructuredGatewayAPI(resources)
	if len(httpRoutes) != 1 || httpRoutes[0].Name != "good" {
		t.Fatalf("expected the well-formed HTTPRoute to still decode, got %+v", httpRoutes)
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly one decode error, got %d: %v", len(errs), errs)
	}
}
