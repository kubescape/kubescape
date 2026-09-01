package exposure

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svc(namespace, name string, svcType corev1.ServiceType) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ServiceSpec{Type: svcType},
	}
}

func ref(namespace, name string) ServiceRef {
	return ServiceRef{Namespace: namespace, Name: name}
}

func TestServiceExposure_UnknownServiceIsEmpty(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "missing")); paths != nil {
		t.Errorf("paths = %v, want nil", paths)
	}
}

func TestServiceExposure_ClusterIPAloneIsNotExposed(t *testing.T) {
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, nil, nil, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "app")); len(paths) != 0 {
		t.Errorf("paths = %v, want empty", paths)
	}
}

func TestServiceExposure_LoadBalancerIsExposed(t *testing.T) {
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeLoadBalancer)}, nil, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureLoadBalancer {
		t.Errorf("paths = %+v, want one ExposureLoadBalancer", paths)
	}
}

func TestServiceExposure_NodePortIsExposed(t *testing.T) {
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeNodePort)}, nil, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureNodePort {
		t.Errorf("paths = %+v, want one ExposureNodePort", paths)
	}
}

func TestServiceExposure_ExternalIPsExposesClusterIPService(t *testing.T) {
	s := svc("ns", "app", corev1.ServiceTypeClusterIP)
	s.Spec.ExternalIPs = []string{"203.0.113.10"}
	idx := NewIndex([]corev1.Service{s}, nil, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureExternalIP {
		t.Errorf("paths = %+v, want one ExposureExternalIP: kube-proxy programs spec.externalIPs on every node regardless of spec.type (CVE-2020-8554)", paths)
	}
}

func TestServiceExposure_ExternalIPsAlongsideLoadBalancerReportsBothPaths(t *testing.T) {
	s := svc("ns", "app", corev1.ServiceTypeLoadBalancer)
	s.Spec.ExternalIPs = []string{"203.0.113.10"}
	idx := NewIndex([]corev1.Service{s}, nil, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 2 {
		t.Errorf("paths = %+v, want two paths: LoadBalancer and ExternalIP are independent exposure mechanisms", paths)
	}
}

func TestServiceExposure_NoExternalIPsDoesNotAddAPath(t *testing.T) {
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 0 {
		t.Errorf("paths = %+v, want empty", paths)
	}
}

func ingressBackend(name string) networkingv1.IngressBackend {
	return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name}}
}

func TestServiceExposure_IngressDefaultBackendExposesService(t *testing.T) {
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
		Spec:       networkingv1.IngressSpec{DefaultBackend: ptrBackend(ingressBackend("app"))},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, []networkingv1.Ingress{ing}, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureIngress || paths[0].Source != "ns/web" || paths[0].Host != "" {
		t.Errorf("paths = %+v, want one ExposureIngress from ns/web with empty host", paths)
	}
}

func TestServiceExposure_IngressRuleExposesServiceWithHost(t *testing.T) {
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{
			{
				Host: "app.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{Backend: ingressBackend("app")}},
					},
				},
			},
		}},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, []networkingv1.Ingress{ing}, nil, nil, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureIngress || paths[0].Host != "app.example.com" {
		t.Errorf("paths = %+v, want one ExposureIngress with host app.example.com", paths)
	}
}

func TestServiceExposure_IngressForDifferentServiceDoesNotMatch(t *testing.T) {
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web"},
		Spec:       networkingv1.IngressSpec{DefaultBackend: ptrBackend(ingressBackend("other"))},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, []networkingv1.Ingress{ing}, nil, nil, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "app")); len(paths) != 0 {
		t.Errorf("paths = %v, want empty", paths)
	}
}

func TestServiceExposure_IngressInAnotherNamespaceDoesNotApply(t *testing.T) {
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns", Name: "web"},
		Spec:       networkingv1.IngressSpec{DefaultBackend: ptrBackend(ingressBackend("app"))},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, []networkingv1.Ingress{ing}, nil, nil, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "app")); len(paths) != 0 {
		t.Errorf("paths = %v, want empty: an Ingress can only name a Service in its own namespace", paths)
	}
}

func TestServiceExposure_HTTPRouteWithUncollectedGatewayStillReportsPath(t *testing.T) {
	route := httpRoute{
		Namespace:  "ns",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "missing-gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	// No Gateway named missing-gw was collected. This is the most
	// indeterminate case there is -- the Gateway could simply live outside
	// what was collected rather than not exist -- so it must be treated as a
	// possible exposure, not silently dropped.
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, nil, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "app")); len(paths) != 1 {
		t.Errorf("paths = %v, want one path: an uncollected Gateway must be treated as a possible exposure", paths)
	}
}

func TestServiceExposure_HTTPRouteAttachedToGatewayExposesService(t *testing.T) {
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "http"}}}
	route := httpRoute{
		Namespace:  "ns",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Hostnames:  []string{"app.example.com"},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Kind != ExposureHTTPRoute || paths[0].Source != "ns/route" || paths[0].Host != "app.example.com" {
		t.Errorf("paths = %+v, want one ExposureHTTPRoute from ns/route with host app.example.com", paths)
	}
}

func TestServiceExposure_HTTPRouteWithNoHostnamesProducesOnePathWithEmptyHost(t *testing.T) {
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "http"}}}
	route := httpRoute{
		Namespace:  "ns",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, _ := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 1 || paths[0].Host != "" {
		t.Errorf("paths = %+v, want one path with empty host", paths)
	}
}

func TestServiceExposure_CrossNamespaceParentRefBlockedByDefaultSameNamespaceAllowedRoutes(t *testing.T) {
	gw := gateway{Namespace: "gw-ns", Name: "gw", Listeners: []listener{{Name: "http"}}}
	gwNS := "gw-ns"
	route := httpRoute{
		Namespace:  "route-ns",
		Name:       "route",
		ParentRefs: []parentRef{{Namespace: &gwNS, Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	idx := NewIndex([]corev1.Service{svc("route-ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, _ := idx.ServiceExposure(ref("route-ns", "app"))
	if len(paths) != 0 {
		t.Errorf("paths = %+v, want empty: AllowedRoutes defaults to Same, and the route's namespace differs from the Gateway's", paths)
	}
}

func TestServiceExposure_CrossNamespaceParentRefAllowedByExplicitFromAll(t *testing.T) {
	all := fromAll
	gwNS := "gw-ns"
	gw := gateway{Namespace: "gw-ns", Name: "gw", Listeners: []listener{{
		Name:          "http",
		AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{From: &all}},
	}}}
	route := httpRoute{
		Namespace:  "route-ns",
		Name:       "route",
		ParentRefs: []parentRef{{Namespace: &gwNS, Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	idx := NewIndex([]corev1.Service{svc("route-ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, _ := idx.ServiceExposure(ref("route-ns", "app"))
	if len(paths) != 1 {
		t.Errorf("paths = %+v, want one ExposureHTTPRoute: the listener explicitly allows routes from all namespaces", paths)
	}
}

func TestServiceExposure_HTTPRouteBackendInAnotherNamespaceIsNotModeled(t *testing.T) {
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{Name: "http"}}}
	otherNS := "other-ns"
	route := httpRoute{
		Namespace:  "ns",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Namespace: &otherNS, Name: "app"}}}},
	}
	// The Service actually lives in ns, but the route's backendRef claims
	// other-ns -- without a ReferenceGrant (not modeled), this must not
	// match ns/app.
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 0 {
		t.Errorf("paths = %v, want empty", paths)
	}
	if unclear {
		t.Error("unclear = true, want false: the backendRef names other-ns/app, not ns/app, so it says nothing about ns/app's exposure")
	}
}

func TestServiceExposure_UnclearWhenCrossNamespaceHTTPRouteBackendRefIsUnmodeled(t *testing.T) {
	gw := gateway{Namespace: "edge", Name: "gw", Listeners: []listener{{Name: "http"}}}
	targetNS := "ns"
	// A real, working topology: an HTTPRoute living in "edge" names ns/app as
	// its backend via an explicit backendRef.namespace, authorized by a
	// ReferenceGrant in ns (not modeled by this package -- see
	// crossNamespaceBackendRefIsUnmodeled's doc comment). idx.httpRoutesByNS
	// only looks up routes living *in* ref.Namespace when building paths, so
	// this route is never examined there; the unclear signal exists
	// precisely to catch what that omission would otherwise hide.
	route := httpRoute{
		Namespace:  "edge",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Namespace: &targetNS, Name: "app"}}}},
	}
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	paths, unclear := idx.ServiceExposure(ref("ns", "app"))
	if len(paths) != 0 {
		t.Errorf("paths = %v, want empty: this package does not confirm cross-namespace backendRefs", paths)
	}
	if !unclear {
		t.Error("unclear = false, want true: a cross-namespace backendRef from an admitted HTTPRoute names this Service")
	}
}

func TestServiceExposure_CrossNamespaceRouteWithUncollectedGatewayIsStillUnclear(t *testing.T) {
	targetNS := "ns"
	route := httpRoute{
		Namespace:  "edge",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "missing-gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Namespace: &targetNS, Name: "app"}}}},
	}
	// No Gateway at all was collected, so routeAttachesToAGateway takes the
	// conservative "uncollected Gateway" path and reports it as attached --
	// crossNamespaceBackendRefIsUnmodeled piggybacks on that same
	// conservative check rather than re-deriving its own, so this must still
	// be unclear rather than silently dropped for lack of Gateway data.
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, nil, nil)
	_, unclear := idx.ServiceExposure(ref("ns", "app"))
	if !unclear {
		t.Error("unclear = false, want true: an uncollected Gateway is conservatively treated as attached, same as routeAttachesToAGateway")
	}
}

func TestGatewayAdmitsRouteNamespace_DefaultIsSameNamespace(t *testing.T) {
	idx := NewIndex(nil, nil, nil, nil, nil)
	admits, determinable := idx.gatewayAdmitsRouteNamespace(listener{}, "ns", "ns")
	if !admits || !determinable {
		t.Errorf("admits=%v determinable=%v, want true,true for same namespace under the default", admits, determinable)
	}
	admits, determinable = idx.gatewayAdmitsRouteNamespace(listener{}, "other-ns", "ns")
	if admits || !determinable {
		t.Errorf("admits=%v determinable=%v, want false,true for a different namespace under the default", admits, determinable)
	}
}

func TestGatewayAdmitsRouteNamespace_FromAllAdmitsEveryNamespace(t *testing.T) {
	all := fromAll
	l := listener{AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{From: &all}}}
	idx := NewIndex(nil, nil, nil, nil, nil)
	admits, determinable := idx.gatewayAdmitsRouteNamespace(l, "anything", "gw-ns")
	if !admits || !determinable {
		t.Errorf("admits=%v determinable=%v, want true,true", admits, determinable)
	}
}

func TestGatewayAdmitsRouteNamespace_FromSelectorNeedsNamespaceLabels(t *testing.T) {
	sel := fromSelector
	l := listener{AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{
		From:     &sel,
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}},
	}}}

	idxNoLabels := NewIndex(nil, nil, nil, nil, nil)
	_, determinable := idxNoLabels.gatewayAdmitsRouteNamespace(l, "route-ns", "gw-ns")
	if determinable {
		t.Error("determinable = true, want false: no namespace labels were collected for route-ns")
	}

	idxWithLabels := NewIndex(nil, nil, nil, nil, []NamespaceInfo{{Name: "route-ns", Labels: map[string]string{"team": "payments"}}})
	admits, determinable := idxWithLabels.gatewayAdmitsRouteNamespace(l, "route-ns", "gw-ns")
	if !admits || !determinable {
		t.Errorf("admits=%v determinable=%v, want true,true: route-ns's labels satisfy the selector", admits, determinable)
	}

	idxWrongLabels := NewIndex(nil, nil, nil, nil, []NamespaceInfo{{Name: "route-ns", Labels: map[string]string{"team": "platform"}}})
	admits, determinable = idxWrongLabels.gatewayAdmitsRouteNamespace(l, "route-ns", "gw-ns")
	if admits || !determinable {
		t.Errorf("admits=%v determinable=%v, want false,true: route-ns's labels do not satisfy the selector", admits, determinable)
	}
}

func TestServiceExposure_HTTPRouteIndeterminateAdmissionStillReportsPath(t *testing.T) {
	sel := fromSelector
	gw := gateway{Namespace: "ns", Name: "gw", Listeners: []listener{{
		AllowedRoutes: &allowedRoutes{Namespaces: &routeNamespaces{
			From:     &sel,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}},
		}},
	}}}
	route := httpRoute{
		Namespace:  "ns",
		Name:       "route",
		ParentRefs: []parentRef{{Name: "gw"}},
		Rules:      []httpRouteRule{{BackendRefs: []backendRef{{Name: "app"}}}},
	}
	// No NamespaceInfo for "ns" was collected, so the selector can't be
	// evaluated -- this must still report the path rather than silently
	// dropping a possible exposure.
	idx := NewIndex([]corev1.Service{svc("ns", "app", corev1.ServiceTypeClusterIP)}, nil, []httpRoute{route}, []gateway{gw}, nil)
	if paths, _ := idx.ServiceExposure(ref("ns", "app")); len(paths) != 1 {
		t.Errorf("paths = %v, want one path: an indeterminate admission must still be reported", paths)
	}
}

func ptrBackend(b networkingv1.IngressBackend) *networkingv1.IngressBackend {
	return &b
}
