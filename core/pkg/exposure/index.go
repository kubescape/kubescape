package exposure

import (
	"fmt"
	"slices"
	"sort"

	"github.com/kubescape/kubescape/v4/core/pkg/namespaceselector"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Index indexes a cluster's Service, Ingress, Gateway API route
// (HTTPRoute/GRPCRoute), Gateway, and Namespace objects for repeated
// exposure queries against the same snapshot.
type Index struct {
	services         map[ServiceRef]*corev1.Service
	ingressesByNS    map[string][]*networkingv1.Ingress
	routesByNS       map[string][]*gatewayRoute
	gateways         map[ServiceRef]*gateway // keyed the same shape as ServiceRef: namespace+name
	namespacesByName map[string]NamespaceInfo

	// grantsCollected records that the caller supplied the cluster's
	// ReferenceGrants (see WithReferenceGrants). Without it a cross-namespace
	// backendRef can be neither confirmed nor ruled out.
	grantsCollected bool
	// grantsByNS holds the collected grants by the namespace they live in,
	// which is the namespace of the Services each one authorizes references to.
	grantsByNS map[string][]referenceGrant
}

// Option customizes an Index built by NewIndex.
type Option func(*Index)

// WithReferenceGrants supplies every ReferenceGrant of the cluster, letting the
// Index decide whether a route's cross-namespace Service backendRef is
// authorized: a referenced Service becomes exposed through the route when a
// grant permits it, and the reference is ruled out when none does.
//
// The list must be what a successful, complete listing returned. An empty list
// is a real answer -- the cluster has no grants, so no cross-namespace
// reference is authorized. A caller that could not list the grants, or could
// not decode all of them, must not pass this option: an Index without it keeps
// reporting such references as unclear instead of denying them.
func WithReferenceGrants(grants []referenceGrant) Option {
	return func(idx *Index) {
		idx.grantsCollected = true
		idx.grantsByNS = make(map[string][]referenceGrant)
		for _, g := range grants {
			idx.grantsByNS[g.Namespace] = append(idx.grantsByNS[g.Namespace], g)
		}
	}
}

// NewIndex builds an Index from a cluster's (or a query's) collected
// objects. A nil slice for any parameter is treated as "none collected,"
// not an error -- a cluster without the Gateway API installed simply has no
// routes/gateways to pass, and every query still works, just without
// that exposure mechanism ever matching.
func NewIndex(services []corev1.Service, ingresses []networkingv1.Ingress, routes []gatewayRoute, gateways []gateway, namespaces []NamespaceInfo, opts ...Option) *Index {
	idx := &Index{
		services:         make(map[ServiceRef]*corev1.Service, len(services)),
		ingressesByNS:    make(map[string][]*networkingv1.Ingress),
		routesByNS:       make(map[string][]*gatewayRoute),
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
	for i := range routes {
		r := &routes[i]
		idx.routesByNS[r.Namespace] = append(idx.routesByNS[r.Namespace], r)
	}
	for i := range gateways {
		g := &gateways[i]
		idx.gateways[ServiceRef{Namespace: g.Namespace, Name: g.Name}] = g
	}
	for _, ns := range namespaces {
		idx.namespacesByName[ns.Name] = ns
	}
	for _, opt := range opts {
		opt(idx)
	}

	return idx
}

// ServiceExposure reports every path that exposes the named Service to
// traffic from outside the cluster, plus whether at least one plausible but
// unconfirmable exposure path exists that this function cannot settle either
// way. An empty paths with unclear=false means nothing in this snapshot
// exposes the Service -- it is only reachable from inside the cluster (or
// not collected/does not exist at all, which this function cannot tell
// apart from "exists but not exposed"). unclear=true means paths must NOT
// be read as a confirmed all-clear: a cross-namespace route backendRef
// names this Service, and the Index was not given the cluster's
// ReferenceGrants (see WithReferenceGrants), so whether that reference is
// authorized is genuinely unknown. With grants supplied, an authorized
// cross-namespace reference is a path like any other and an unauthorized one
// is not exposure, so unclear is never set.
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
		paths = append(paths, ingressPathsFor(ing, svc)...)
	}

	// A route may live in any namespace and reach this Service through a
	// cross-namespace backendRef, so every route is examined. The Service's own
	// namespace comes first, then the rest in name order, keeping the result
	// independent of map iteration order.
	for _, ns := range idx.routeNamespacesFor(ref) {
		for _, route := range idx.routesByNS[ns] {
			permitted, undetermined := idx.routeReferencesService(route, ref, svc)
			if !permitted && !undetermined {
				continue
			}
			hosts := idx.attachedRouteHostnames(route)
			if len(hosts) == 0 {
				continue
			}
			if !permitted {
				unclear = true
				continue
			}
			source := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
			for _, host := range hosts {
				paths = append(paths, ExposurePath{Kind: routeExposureKind(route.Kind), Source: source, Host: host})
			}
		}
	}

	return paths, unclear
}

// routeNamespacesFor lists the namespaces holding routes, ref's own first.
func (idx *Index) routeNamespacesFor(ref ServiceRef) []string {
	namespaces := make([]string, 0, len(idx.routesByNS))
	for ns := range idx.routesByNS {
		if ns != ref.Namespace {
			namespaces = append(namespaces, ns)
		}
	}
	sort.Strings(namespaces)
	if _, ok := idx.routesByNS[ref.Namespace]; ok {
		namespaces = append([]string{ref.Namespace}, namespaces...)
	}
	return namespaces
}

// routeExposureKind maps a Gateway API route kind to the ExposureKind that
// attributes its paths. Unrecognized kinds (possible only if a future
// Gateway API route kind is decoded before this mapping learns it) fall
// back to ExposureHTTPRoute, keeping the conservative-report-a-path
// posture of the rest of the package.
func routeExposureKind(routeKind string) ExposureKind {
	if routeKind == "GRPCRoute" {
		return ExposureGRPCRoute
	}
	return ExposureHTTPRoute
}

// ingressPathsFor returns one ExposurePath per Ingress rule (or the
// defaultBackend) whose backend names serviceName.
func ingressPathsFor(ing *networkingv1.Ingress, svc *corev1.Service) []ExposurePath {
	var paths []ExposurePath
	source := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)

	if backendNamesService(ing.Spec.DefaultBackend, svc) {
		paths = append(paths, ExposurePath{Kind: ExposureIngress, Source: source})
	}

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if backendNamesService(&path.Backend, svc) {
				paths = append(paths, ExposurePath{Kind: ExposureIngress, Source: source, Host: rule.Host})
			}
		}
	}

	return paths
}

func backendNamesService(backend *networkingv1.IngressBackend, svc *corev1.Service) bool {
	return backend != nil && backend.Service != nil && backend.Service.Name == svc.Name &&
		serviceBackendPortMatches(svc, backend.Service.Port.Name, backend.Service.Port.Number)
}

// routeReferencesService reports how route's rules reach ref. permitted is
// true when some rule sends traffic to it through a reference that is
// authorized; undetermined is true when the route has such a reference but
// whether it is authorized cannot be told (a cross-namespace backendRef and no
// grants supplied). A reference that is known unauthorized sets neither.
//
// Zero-weight backends receive no requests. Only effective core-Service
// backends count (per Gateway API's group/kind defaults -- a backendRef naming
// another kind must not produce a Service exposure path however closely its
// name matches). A backendRef with no Namespace defaults to the route's own
// namespace, per Gateway API's own defaulting rules.
func (idx *Index) routeReferencesService(route *gatewayRoute, ref ServiceRef, svc *corev1.Service) (permitted, undetermined bool) {
	for _, rule := range route.Rules {
		for _, backend := range rule.BackendRefs {
			if !isServiceBackendRef(backend) || (backend.Weight != nil && *backend.Weight == 0) {
				continue
			}
			if !idx.mirrorParentCanForward(backend, route) {
				continue
			}
			if !gatewayBackendPortMatches(backend, svc) {
				continue
			}
			ns := route.Namespace
			if backend.Namespace != nil {
				ns = *backend.Namespace
			}
			if ns != ref.Namespace || backend.Name != ref.Name {
				continue
			}
			switch idx.authorizeServiceReference(route, ref) {
			case referencePermitted:
				return true, false
			case referenceUndetermined:
				undetermined = true
			}
		}
	}
	return false, undetermined
}

// referenceVerdict is the outcome of authorizing a route's reference to a
// Service in another namespace.
type referenceVerdict int

const (
	// referencePermitted: same namespace, or a collected ReferenceGrant allows it.
	referencePermitted referenceVerdict = iota
	// referenceDenied: grants were collected and none allows it. Gateway API
	// forbids the reference, so it carries no traffic and is not exposure.
	referenceDenied
	// referenceUndetermined: grants were not collected, so the reference is
	// neither confirmed nor ruled out.
	referenceUndetermined
)

// authorizeServiceReference decides whether route may reference target. A
// reference within the route's own namespace never needs a grant; one into
// another namespace is permitted only by a ReferenceGrant in the target's
// namespace, and the Service merely existing authorizes nothing.
func (idx *Index) authorizeServiceReference(route *gatewayRoute, target ServiceRef) referenceVerdict {
	if route.Namespace == target.Namespace {
		return referencePermitted
	}
	if !idx.grantsCollected {
		return referenceUndetermined
	}
	from := routeReferrer{Kind: route.Kind, Namespace: route.Namespace}
	for _, g := range idx.grantsByNS[target.Namespace] {
		if g.permitsService(from, target) {
			return referencePermitted
		}
	}
	return referenceDenied
}

// routeAttachesToAGateway reports whether route is admitted by at least
// one listener of a Gateway object this Index was given, via any of the
// route's parentRefs. Only effective Gateway parents count (per Gateway
// API's group/kind defaults -- a parentRef naming another kind must not
// attach a route to a Gateway that merely shares its namespace/name). When
// a parentRef carries a sectionName, it pins the attachment to the one
// listener with that name -- no other listener of the Gateway may admit
// the route, and a sectionName naming no collected listener contributes
// nothing. A specified port also restricts attachment; with both fields
// present a listener must match both. Otherwise every listener is evaluated.
// A listener must admit the route's hostname as well as its AllowedRoutes
// namespaces and kinds
// policies. A listener whose namespace admission cannot
// be confirmed to exclude the route (a Selector needing namespace labels
// this Index was not given) is conservatively treated as admitting it:
// this package errs toward reporting a possible exposure rather than
// silently hiding one, the same choice core/pkg/mapreconcile makes for its
// own indeterminate matches. A parentRef naming a Gateway this Index has
// no record of at all is the most indeterminate case there is -- the
// Gateway may simply live outside what was collected (a cross-namespace
// reference, or a caller without RBAC to list it elsewhere) rather than
// not exist -- so it gets the same conservative treatment rather than
// being silently treated as a non-match.
func (idx *Index) routeAttachesToAGateway(route *gatewayRoute) bool {
	return len(idx.attachedRouteHostnames(route)) > 0
}

// attachedRouteHostnames returns only the intersections admitted by a
// listener. An empty hostname denotes unrestricted host matching; a nil
// slice means no collected listener can accept the route. Missing Gateway
// data retains the existing conservative possible-exposure behavior.
func (idx *Index) attachedRouteHostnames(route *gatewayRoute) []string {
	var hosts []string
	add := func(candidates []string) {
		for _, host := range candidates {
			if host == "" {
				hosts = []string{""}
				return
			}
			if slices.Contains(hosts, "") {
				continue
			}
			if !slices.Contains(hosts, host) {
				hosts = append(hosts, host)
			}
		}
	}
	for _, ref := range route.ParentRefs {
		if !isGatewayParentRef(ref) {
			continue
		}
		ns := route.Namespace
		if ref.Namespace != nil {
			ns = *ref.Namespace
		}
		gw, ok := idx.gateways[ServiceRef{Namespace: ns, Name: ref.Name}]
		if !ok {
			add(listenerRouteHostnames("", route.Hostnames))
			continue
		}
		for _, l := range gw.Listeners {
			if ref.SectionName != nil && l.Name != *ref.SectionName {
				continue
			}
			if ref.Port != nil && l.Port != *ref.Port {
				continue
			}
			if !idx.listenerAdmitsRouteKind(l, route.Kind) {
				continue
			}
			admits, determinable := idx.gatewayAdmitsRouteNamespace(l, route.Namespace, gw.Namespace)
			if admits || !determinable {
				add(listenerRouteHostnames(l.Hostname, route.Hostnames))
			}
		}
	}
	return hosts
}

// listenerAdmitsRouteKind checks protocol compatibility and allowedRoutes.kinds.
// Unlike namespace admission, these checks never depend on uncollected labels.
// An omitted kinds list adds no restriction beyond protocol compatibility.
func (idx *Index) listenerAdmitsRouteKind(l listener, routeKind string) bool {
	// allowedRoutes.kinds cannot make an HTTP-family route compatible with
	// a transport listener. TLS passthrough requires TLSRoute, not HTTPRoute.
	// Missing/custom protocols remain conservative for incomplete inventory
	// and implementation-specific protocols this static model cannot resolve.
	if routeKind == "HTTPRoute" || routeKind == "GRPCRoute" {
		switch l.Protocol {
		case "TCP", "UDP", "TLS":
			return false
		}
	}
	if l.AllowedRoutes == nil {
		return true
	}
	return l.AllowedRoutes.admitsRouteKind(routeKind)
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
		info, collected := idx.namespacesByName[routeNamespace]
		return namespaceselector.Matches(sel, routeNamespace, info.Labels, collected)
	default:
		return false, true
	}
}
