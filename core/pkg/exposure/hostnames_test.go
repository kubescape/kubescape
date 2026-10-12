package exposure

import (
	"reflect"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestListenerRouteHostnameIntersection(t *testing.T) {
	for _, tt := range []struct {
		name     string
		listener string
		route    []string
		want     []string
	}{
		{"both unrestricted", "", nil, []string{""}},
		{"listener unrestricted", "", []string{"app.example.com"}, []string{"app.example.com"}},
		{"route unrestricted", "app.example.com", nil, []string{"app.example.com"}},
		{"exact match", "app.example.com", []string{"app.example.com"}, []string{"app.example.com"}},
		{"exact mismatch", "other.example.com", []string{"app.example.com"}, nil},
		{"listener wildcard", "*.example.com", []string{"app.example.com"}, []string{"app.example.com"}},
		{"listener wildcard multilabel", "*.example.com", []string{"api.team.example.com"}, []string{"api.team.example.com"}},
		{"listener wildcard apex excluded", "*.example.com", []string{"example.com"}, nil},
		{"listener wildcard boundary", "*.example.com", []string{"notexample.com"}, nil},
		{"listener wildcard foreign suffix", "*.example.com", []string{"app.example.net"}, nil},
		{"route wildcard", "app.example.com", []string{"*.example.com"}, []string{"app.example.com"}},
		{"route wildcard multilabel", "api.team.example.com", []string{"*.example.com"}, []string{"api.team.example.com"}},
		{"route wildcard apex excluded", "example.com", []string{"*.example.com"}, nil},
		{"identical wildcards", "*.example.com", []string{"*.example.com"}, []string{"*.example.com"}},
		{"narrower listener wildcard", "*.team.example.com", []string{"*.example.com"}, []string{"*.team.example.com"}},
		{"narrower route wildcard", "*.example.com", []string{"*.team.example.com"}, []string{"*.team.example.com"}},
		{"disjoint wildcards", "*.example.com", []string{"*.example.net"}, nil},
		{"partial intersection", "*.example.com", []string{"a.example.net", "b.example.com", "c.example.com"}, []string{"b.example.com", "c.example.com"}},
		{"no route hosts with wildcard listener", "*.example.com", nil, []string{"*.example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := listenerRouteHostnames(tt.listener, tt.route); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("intersection = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceExposure_GatewayHostnameAdmission(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		t.Run(kind, func(t *testing.T) {
			for _, tt := range []struct {
				name     string
				listener string
				hosts    []string
				want     []string
			}{
				{"mismatch is not exposure", "other.example.com", []string{"app.example.com"}, nil},
				{"matching host", "app.example.com", []string{"app.example.com"}, []string{"app.example.com"}},
				{"only accepted hosts", "*.example.com", []string{"api.example.net", "app.example.com"}, []string{"app.example.com"}},
				{"route wildcard narrowed", "app.example.com", []string{"*.example.com"}, []string{"app.example.com"}},
				{"unrestricted route narrowed", "app.example.com", nil, []string{"app.example.com"}},
				{"both unrestricted", "", nil, []string{""}},
				{"wildcard apex excluded", "*.example.com", []string{"example.com"}, nil},
			} {
				t.Run(tt.name, func(t *testing.T) {
					route := gatewayRoute{
						Kind: kind, Namespace: "ns", Name: "route",
						Hostnames: tt.hosts, ParentRefs: []parentRef{{Name: "gw"}},
						Rules: []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
					}
					gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "web", Hostname: tt.listener}}}
					idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
					paths, unclear := idx.ServiceExposure(ref("ns", "app"))
					if unclear {
						t.Fatal("same-namespace admission should be determinable")
					}
					var hosts []string
					for _, path := range paths {
						if path.Source != "ns/route" || path.Kind != routeExposureKind(kind) {
							t.Fatalf("wrong exposure attribution: %+v", path)
						}
						hosts = append(hosts, path.Host)
					}
					if !reflect.DeepEqual(hosts, tt.want) {
						t.Fatalf("path hosts = %v, want %v", hosts, tt.want)
					}
				})
			}
		})
	}
}

func TestGatewayHostnames_SectionNameStillPinsListener(t *testing.T) {
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{
		{Name: "matching", Hostname: "app.example.com"},
		{Name: "other", Hostname: "other.example.com"},
	}}
	for _, tt := range []struct {
		section string
		want    bool
	}{
		{"matching", true},
		{"other", false},
		{"missing", false},
	} {
		t.Run(tt.section, func(t *testing.T) {
			route := gatewayRoute{
				Kind: "HTTPRoute", Namespace: "ns", Name: "route",
				Hostnames:  []string{"app.example.com"},
				ParentRefs: []parentRef{{Name: "gw", SectionName: &tt.section}},
			}
			idx := NewIndex(nil, nil, nil, []gateway{gw}, nil)
			if got := idx.routeAttachesToAGateway(&route); got != tt.want {
				t.Fatalf("attached = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGatewayHostnames_MultipleParentsAndListenersDoNotDuplicatePaths(t *testing.T) {
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "ns", Name: "route",
		Hostnames:  []string{"a.example.com", "b.example.com", "outside.example.net"},
		ParentRefs: []parentRef{{Name: "first"}, {Name: "second"}, {Name: "first"}},
		Rules:      []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	gateways := []gateway{
		{Namespace: "ns", Name: "first", Listeners: []listener{
			{Name: "a", Hostname: "a.example.com"},
			{Name: "a-again", Hostname: "a.example.com"},
		}},
		{Namespace: "ns", Name: "second", Listeners: []listener{{Name: "b", Hostname: "b.example.com"}}},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, gateways, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	var hosts []string
	for _, path := range paths {
		hosts = append(hosts, path.Host)
	}
	if !reflect.DeepEqual(hosts, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("admitted hosts = %v", hosts)
	}
}

func TestGatewayHostnames_DoNotBypassNamespaceOrKindAdmission(t *testing.T) {
	from := fromAll
	for _, tt := range []struct {
		name    string
		allowed *allowedRoutes
		want    bool
	}{
		{"same namespace default rejects foreign route", nil, false},
		{"all namespaces accepts matching kind", &allowedRoutes{Namespaces: &routeNamespaces{From: &from}}, true},
		{"wrong kind rejects matching hostname", &allowedRoutes{Namespaces: &routeNamespaces{From: &from}, Kinds: []routeGroupKind{{Kind: "GRPCRoute"}}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parentNS := "edge"
			route := gatewayRoute{
				Kind: "HTTPRoute", Namespace: "app", Name: "route",
				Hostnames:  []string{"app.example.com"},
				ParentRefs: []parentRef{{Name: "gw", Namespace: &parentNS}},
			}
			gw := gateway{Namespace: "edge", Name: "gw", Listeners: []listener{
				{Name: "web", Hostname: "app.example.com", AllowedRoutes: tt.allowed},
			}}
			idx := NewIndex(nil, nil, nil, []gateway{gw}, nil)
			if got := idx.routeAttachesToAGateway(&route); got != tt.want {
				t.Fatalf("attached = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGatewayHostnames_UnknownNamespaceSelectorCannotOverrideMismatch(t *testing.T) {
	from := fromSelector
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "app", Name: "route",
		Hostnames:  []string{"app.example.com"},
		ParentRefs: []parentRef{{Name: "gw"}},
	}
	gw := gateway{Namespace: "app", Name: "gw", Listeners: []listener{
		{Name: "web", Hostname: "other.example.com", AllowedRoutes: &allowedRoutes{
			Namespaces: &routeNamespaces{From: &from, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "app"}}},
		}},
	}}
	idx := NewIndex(nil, nil, nil, []gateway{gw}, nil)
	if idx.routeAttachesToAGateway(&route) {
		t.Fatal("unknown namespace labels cannot make disjoint hostnames attach")
	}
	gw.Listeners[0].Hostname = "app.example.com"
	idx = NewIndex(nil, nil, nil, []gateway{gw}, nil)
	if !idx.routeAttachesToAGateway(&route) {
		t.Fatal("matching host must preserve conservative unknown-selector behavior")
	}
}

func TestGatewayHostnames_UncollectedGatewayRemainsConservative(t *testing.T) {
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "ns", Name: "route",
		Hostnames:  []string{"app.example.com", "other.example.net"},
		ParentRefs: []parentRef{{Name: "known"}, {Name: "missing"}},
	}
	gw := gateway{Namespace: "ns", Name: "known", Listeners: []listener{{Name: "web", Hostname: "unrelated.example.org"}}}
	idx := NewIndex(nil, nil, nil, []gateway{gw}, nil)
	if got := idx.attachedRouteHostnames(&route); !reflect.DeepEqual(got, route.Hostnames) {
		t.Fatalf("uncollected Gateway lost possible hosts: %v", got)
	}
	route.Hostnames = nil
	if got := idx.attachedRouteHostnames(&route); !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("uncollected Gateway lost unrestricted path: %v", got)
	}
}

func TestGatewayHostnames_CrossNamespaceUncertaintyRequiresAttachment(t *testing.T) {
	backendNS := "backend"
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "edge", Name: "route",
		Hostnames:  []string{"app.example.com"},
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app", Namespace: &backendNS}}}},
	}
	for _, tt := range []struct {
		host    string
		unclear bool
	}{
		{"other.example.com", false},
		{"app.example.com", true},
	} {
		t.Run(tt.host, func(t *testing.T) {
			gw := gateway{Namespace: "edge", Name: "gw", Listeners: []listener{{Name: "web", Hostname: tt.host}}}
			idx := NewIndex([]corev1.Service{svc("backend", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
			paths, unclear := idx.ServiceExposure(ref("backend", "app"))
			if len(paths) != 0 || unclear != tt.unclear {
				t.Fatalf("paths = %v, unclear = %v, want no paths and unclear=%v", paths, unclear, tt.unclear)
			}
		})
	}
}

func TestGatewayHostnames_UnstructuredScanBoundary(t *testing.T) {
	for _, kind := range []string{"HTTPRoute", "GRPCRoute"} {
		for _, apiVersion := range []string{"gateway.networking.k8s.io/v1", "gateway.networking.k8s.io/v1beta1"} {
			t.Run(kind+"/"+apiVersion, func(t *testing.T) {
				route := unstructuredResource(map[string]any{
					"apiVersion": apiVersion, "kind": kind,
					"metadata": map[string]any{"namespace": "ns", "name": "route"},
					"spec": map[string]any{
						"parentRefs": []any{map[string]any{"name": "gw"}},
						"hostnames":  []any{"app.example.com", "other.example.net"},
						"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "app"}}}},
					},
				})
				gw := unstructuredResource(map[string]any{
					"apiVersion": apiVersion, "kind": "Gateway",
					"metadata": map[string]any{"namespace": "ns", "name": "gw"},
					"spec": map[string]any{
						"listeners": []any{map[string]any{"name": "web", "hostname": "*.example.com"}},
					},
				})
				routes, gateways, errs := FromUnstructuredGatewayAPI(map[string]workloadinterface.IMetadata{
					route.GetID(): route, gw.GetID(): gw,
				})
				if len(errs) != 0 || len(gateways) != 1 || len(routes) != 1 {
					t.Fatalf("decode failed: gateways %v routes %v errors %v", gateways, routes, errs)
				}
				if gateways[0].Listeners[0].Hostname != "*.example.com" {
					t.Fatalf("listener hostname lost at collection boundary: %+v", gateways[0])
				}
				idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, routes, gateways, nil)
				paths, unclear := idx.ServiceExposure(ref("ns", "app"))
				if unclear || len(paths) != 1 || paths[0].Host != "app.example.com" || paths[0].Kind != routeExposureKind(kind) {
					t.Fatalf("decoded exposure = %+v unclear=%v", paths, unclear)
				}
			})
		}
	}
}

func TestGatewayHostnames_RejectedRouteDoesNotHideDirectServiceExposure(t *testing.T) {
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "ns", Name: "route",
		Hostnames: []string{"app.example.com"}, ParentRefs: []parentRef{{Name: "gw"}},
		Rules: []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "web", Hostname: "other.example.com"}}}
	for _, serviceType := range []corev1.ServiceType{corev1.ServiceTypeNodePort, corev1.ServiceTypeLoadBalancer} {
		t.Run(string(serviceType), func(t *testing.T) {
			idx := NewIndex([]corev1.Service{svc("ns", "app", serviceType)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
			paths, unclear := idx.ServiceExposure(ref("ns", "app"))
			if unclear || len(paths) != 1 {
				t.Fatalf("expected only direct Service exposure: paths=%+v unclear=%v", paths, unclear)
			}
			if paths[0].Kind == ExposureHTTPRoute || paths[0].Host != "" {
				t.Fatalf("rejected route contributed an exposure path: %+v", paths[0])
			}
		})
	}
}

func TestGatewayHostnames_NonGatewayParentCannotExposeMatchingHost(t *testing.T) {
	serviceKind := "Service"
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "ns", Name: "route",
		Hostnames:  []string{"app.example.com"},
		ParentRefs: []parentRef{{Name: "gw", Kind: &serviceKind}},
		Rules:      []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "web", Hostname: "app.example.com"}}}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 0 || unclear {
		t.Fatalf("non-Gateway parent produced paths=%+v unclear=%v", paths, unclear)
	}
}

func TestGatewayHostnames_UnrestrictedListenerSupersedesNarrowerPath(t *testing.T) {
	route := gatewayRoute{
		Kind: "HTTPRoute", Namespace: "ns", Name: "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []gatewayRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	for _, listeners := range [][]listener{
		{{Name: "narrow", Hostname: "app.example.com"}, {Name: "all"}},
		{{Name: "all"}, {Name: "narrow", Hostname: "app.example.com"}},
	} {
		gw := gateway{Namespace: "ns", Name: "gw", Listeners: listeners}
		idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []gatewayRoute{route}, []gateway{gw}, nil)
		paths, _ := idx.ServiceExposure(ref("ns", "app"))
		if len(paths) != 1 || paths[0].Host != "" {
			t.Fatalf("unrestricted listener should cover the narrower host: %+v", paths)
		}
	}
}
