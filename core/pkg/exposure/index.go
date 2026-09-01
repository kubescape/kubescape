package exposure

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Index indexes a cluster's Service, Ingress, HTTPRoute, Gateway, and
// Namespace objects for repeated exposure queries against the same
// snapshot.
type Index struct {
	services         map[ServiceRef]*corev1.Service
	ingressesByNS    map[string][]*networkingv1.Ingress
	httpRoutesByNS   map[string][]*httpRoute
	gateways         map[ServiceRef]*gateway // keyed the same shape as ServiceRef: namespace+name
	namespacesByName map[string]NamespaceInfo
}

// NewIndex builds an Index from a cluster's (or a query's) collected
// objects. A nil slice for any parameter is treated as "none collected,"
// not an error -- a cluster without the Gateway API installed simply has no
// httpRoutes/gateways to pass, and every query still works, just without
// that exposure mechanism ever matching.
func NewIndex(services []corev1.Service, ingresses []networkingv1.Ingress, httpRoutes []httpRoute, gateways []gateway, namespaces []NamespaceInfo) *Index {
	idx := &Index{
		services:         make(map[ServiceRef]*corev1.Service, len(services)),
		ingressesByNS:    make(map[string][]*networkingv1.Ingress),
		httpRoutesByNS:   make(map[string][]*httpRoute),
		gateways:         make(map[ServiceRef]*gateway, len(gateways)),
		namespacesByName: make(map[string]NamespaceInfo, len(namespaces)),
	}

	for i := range services {
		s := &services[i]
		idx.services[ServiceRef{Namespace: s.Namespace, Name: s.Name}] = s
	}
	for i := range ingresses {
		ing := &ingresses[i]
		idx.ingressesByNS[ing.Namespace] = append(idx.ingressesByNS[ing.Namespace], ing)
	}
	for i := range httpRoutes {
		r := &httpRoutes[i]
		idx.httpRoutesByNS[r.Namespace] = append(idx.httpRoutesByNS[r.Namespace], r)
	}
	for i := range gateways {
		g := &gateways[i]
		idx.gateways[ServiceRef{Namespace: g.Namespace, Name: g.Name}] = g
	}
	for _, ns := range namespaces {
		idx.namespacesByName[ns.Name] = ns
	}

	return idx
}

// ServiceExposure reports every path that exposes the named Service to
// traffic from outside the cluster, plus whether at least one plausible but
// unmodeled exposure path exists that this function cannot confirm either
// way. An empty paths with unclear=false means nothing in this snapshot
// exposes the Service -- it is only reachable from inside the cluster (or
// not collected/does not exist at all, which this function cannot tell
// apart from "exists but not exposed"). unclear=true means paths must NOT
// be read as a confirmed all-clear: a cross-namespace HTTPRoute backendRef
// names this Service, and whether that reference is authorized (via a
// ReferenceGrant this package does not collect or evaluate -- see the
// package doc comment) is genuinely unknown.
func (idx *Index) ServiceExposure(ref ServiceRef) (paths []ExposurePath, unclear bool) {
	svc, ok := idx.services[ref]
	if !ok {
		return nil, false
	}

	switch svc.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		paths = append(paths, ExposurePath{Kind: ExposureLoadBalancer, Source: fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)})
	case corev1.ServiceTypeNodePort:
		paths = append(paths, ExposurePath{Kind: ExposureNodePort, Source: fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)})
	}
	if len(svc.Spec.ExternalIPs) > 0 {
		paths = append(paths, ExposurePath{Kind: ExposureExternalIP, Source: fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)})
	}

	for _, ing := range idx.ingressesByNS[ref.Namespace] {
		paths = append(paths, ingressPathsFor(ing, ref.Name)...)
	}

	for _, route := range idx.httpRoutesByNS[ref.Namespace] {
		if !idx.routeAttachesToAGateway(route) {
			continue
		}
		if !httpRouteReferencesService(route, ref) {
			continue
		}
		source := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
		if len(route.Hostnames) == 0 {
			paths = append(paths, ExposurePath{Kind: ExposureHTTPRoute, Source: source})
			continue
		}
		for _, host := range route.Hostnames {
			paths = append(paths, ExposurePath{Kind: ExposureHTTPRoute, Source: source, Host: host})
		}
	}

	return paths, idx.crossNamespaceBackendRefIsUnmodeled(ref)
}

// crossNamespaceBackendRefIsUnmodeled reports whether some HTTPRoute this
// Index was given, living outside ref's namespace and admitted by at least
// one Gateway, explicitly names ref as a backend via backendRef.namespace.
// That is a real, working, externally-reachable path when a matching
// ReferenceGrant exists in ref's namespace -- a resource kind this package
// does not collect or evaluate (see the package doc comment) -- so its
// presence must not be silently folded into a confirmed "not exposed".
func (idx *Index) crossNamespaceBackendRefIsUnmodeled(ref ServiceRef) bool {
	for ns, routes := range idx.httpRoutesByNS {
		if ns == ref.Namespace {
			continue
		}
		for _, route := range routes {
			if !idx.routeAttachesToAGateway(route) {
				continue
			}
			for _, rule := range route.Rules {
				for _, backend := range rule.BackendRefs {
					if backend.Namespace != nil && *backend.Namespace == ref.Namespace && backend.Name == ref.Name {
						return true
					}
				}
			}
		}
	}
	return false
}

// ingressPathsFor returns one ExposurePath per Ingress rule (or the
// defaultBackend) whose backend names serviceName.
func ingressPathsFor(ing *networkingv1.Ingress, serviceName string) []ExposurePath {
	var paths []ExposurePath
	source := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)

	if backendNamesService(ing.Spec.DefaultBackend, serviceName) {
		paths = append(paths, ExposurePath{Kind: ExposureIngress, Source: source})
	}

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if backendNamesService(&path.Backend, serviceName) {
				paths = append(paths, ExposurePath{Kind: ExposureIngress, Source: source, Host: rule.Host})
			}
		}
	}

	return paths
}

func backendNamesService(backend *networkingv1.IngressBackend, serviceName string) bool {
	return backend != nil && backend.Service != nil && backend.Service.Name == serviceName
}

// httpRouteReferencesService reports whether any rule in route sends
// traffic to ref. A backendRef with no Namespace defaults to the route's
// own namespace, per Gateway API's own defaulting rules -- this package
// does not model a backendRef reaching into another namespace via a
// ReferenceGrant, since that requires collecting and evaluating a third
// resource kind this Index is not given.
func httpRouteReferencesService(route *httpRoute, ref ServiceRef) bool {
	for _, rule := range route.Rules {
		for _, backend := range rule.BackendRefs {
			ns := route.Namespace
			if backend.Namespace != nil {
				ns = *backend.Namespace
			}
			if ns == ref.Namespace && backend.Name == ref.Name {
				return true
			}
		}
	}
	return false
}

// routeAttachesToAGateway reports whether route is admitted by at least one
// listener of a Gateway object this Index was given, via any of the
// route's parentRefs. A listener whose AllowedRoutes cannot be confirmed to
// exclude the route (a Selector needing namespace labels this Index was not
// given) is conservatively treated as admitting it: this package errs
// toward reporting a possible exposure rather than silently hiding one, the
// same choice core/pkg/mapreconcile makes for its own indeterminate
// matches. A parentRef naming a Gateway this Index has no record of at all
// is the most indeterminate case there is -- the Gateway may simply live
// outside what was collected (a cross-namespace reference, or a caller
// without RBAC to list it elsewhere) rather than not exist -- so it gets the
// same conservative treatment rather than being silently treated as a
// non-match.
func (idx *Index) routeAttachesToAGateway(route *httpRoute) bool {
	for _, ref := range route.ParentRefs {
		ns := route.Namespace
		if ref.Namespace != nil {
			ns = *ref.Namespace
		}
		gw, ok := idx.gateways[ServiceRef{Namespace: ns, Name: ref.Name}]
		if !ok {
			return true
		}
		for _, l := range gw.Listeners {
			admits, determinable := idx.gatewayAdmitsRouteNamespace(l, route.Namespace, gw.Namespace)
			if admits || !determinable {
				return true
			}
		}
	}
	return false
}

// gatewayAdmitsRouteNamespace evaluates one listener's AllowedRoutes against
// a candidate route namespace, honestly reporting indeterminate when a
// Selector's target needs namespace labels this Index was not given -- the
// same "determinable" pattern core/pkg/networkpolicy's peer matching uses.
func (idx *Index) gatewayAdmitsRouteNamespace(l listener, routeNamespace, gatewayNamespace string) (admits bool, determinable bool) {
	if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil {
		return routeNamespace == gatewayNamespace, true // default: Same
	}
	ns := l.AllowedRoutes.Namespaces
	from := fromSame
	if ns.From != nil {
		from = *ns.From
	}
	switch from {
	case fromAll:
		return true, true
	case fromSame:
		return routeNamespace == gatewayNamespace, true
	case fromSelector:
		if ns.Selector == nil {
			return false, true
		}
		sel, err := metav1.LabelSelectorAsSelector(ns.Selector)
		if err != nil {
			return false, true
		}
		if sel.Empty() {
			return true, true
		}
		info, ok := idx.namespacesByName[routeNamespace]
		if !ok {
			return false, false
		}
		return sel.Matches(labels.Set(info.Labels)), true
	default:
		return false, true
	}
}
