// Package exposure models which of a cluster's Service objects are reachable
// from outside the cluster, and by what mechanism: a Service of type
// LoadBalancer or NodePort is exposed directly; a networking.k8s.io/v1
// Ingress or a Gateway API HTTPRoute/GRPCRoute exposes whatever Service it
// names as a backend.
//
// This is the "outside-in" counterpart to core/pkg/networkpolicy's
// reachability model: that package answers "can this pod reach that pod
// inside the cluster," this one answers "does anything let traffic in from
// outside the cluster in the first place." Like that package, this is a
// static model computed from spec -- existence of an Ingress/HTTPRoute
// naming a Service is treated as intent to expose it, the same trust model
// the rest of kubescape's posture scanning uses; it does not verify that an
// Ingress controller or Gateway implementation is actually running and
// wired up to fulfil what the object declares.
package exposure

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExposureKind identifies which Kubernetes mechanism exposes a Service.
type ExposureKind int

const (
	// ExposureLoadBalancer means the Service itself is type LoadBalancer:
	// exposed directly via a cloud load balancer, no Ingress/Route needed.
	ExposureLoadBalancer ExposureKind = iota
	// ExposureNodePort means the Service itself is type NodePort: exposed
	// directly on every node's IP, no Ingress/Route needed.
	ExposureNodePort
	// ExposureIngress means a networking.k8s.io/v1 Ingress names this
	// Service as a backend (a rule's path backend, or the defaultBackend).
	ExposureIngress
	// ExposureHTTPRoute means a Gateway API HTTPRoute names this Service as
	// a backend, and at least one of its parentRefs names a Gateway object
	// this Index was given whose listener admits the route (per
	// AllowedRoutes and hostname intersection). A listener
	// whose admission can't be confirmed one way or the other is
	// conservatively treated as admitting it.
	ExposureHTTPRoute
	// ExposureGRPCRoute means a Gateway API GRPCRoute names this Service as
	// a backend. GRPCRoute has been a v1 core Gateway API kind since
	// Gateway API v1.1 and carries the same parentRefs/hostnames/
	// backendRefs shape as HTTPRoute, so the same admission model applies;
	// only the wire protocol the Gateway serves differs, which is outside
	// this package's concern.
	ExposureGRPCRoute
	// ExposureExternalIP means the Service has one or more spec.externalIPs
	// set. kube-proxy programs these on every node regardless of
	// spec.type, so a ClusterIP Service with externalIPs set is reachable
	// from off-cluster the same as a NodePort Service -- this is the
	// mechanism behind CVE-2020-8554 (arbitrary externalIPs hijack via a
	// Service create/update in a namespace an attacker controls).
	ExposureExternalIP
)

func (k ExposureKind) String() string {
	switch k {
	case ExposureLoadBalancer:
		return "LoadBalancer"
	case ExposureNodePort:
		return "NodePort"
	case ExposureIngress:
		return "Ingress"
	case ExposureHTTPRoute:
		return "HTTPRoute"
	case ExposureGRPCRoute:
		return "GRPCRoute"
	case ExposureExternalIP:
		return "ExternalIP"
	default:
		return "unknown"
	}
}

// ExposurePath is one specific reason a Service is reachable from outside
// the cluster.
type ExposurePath struct {
	Kind ExposureKind
	// Source names the object responsible: the Ingress/HTTPRoute/GRPCRoute
	// (namespace/name) that names this Service as a backend, or the
	// Service itself for LoadBalancer/NodePort.
	Source string
	// Host is the hostname traffic must arrive with to reach this path, per
	// the responsible Ingress rule or route/listener hostname intersection. Empty means any
	// host (an Ingress rule/defaultBackend with no host restriction, a
	// LoadBalancer/NodePort Service, or a route/listener pair with no
	// hostnames declared).
	Host string
}

// ServiceRef identifies one Service by namespace and name.
type ServiceRef struct {
	Namespace string
	Name      string
}

// NamespaceInfo carries a namespace's own labels, needed for a Gateway
// listener's AllowedRoutes selector (see gatewayAdmitsRouteNamespace).
type NamespaceInfo struct {
	Name   string
	Labels map[string]string
}

// gatewayRoute is a minimal local mirror of the Gateway API route kinds
// this package models (HTTPRoute, and GRPCRoute which shares its spec
// shape) -- only the fields exposure analysis needs, plus which kind the
// object is so exposure paths can be attributed correctly. Defined locally
// rather than vendoring sigs.k8s.io/gateway-api, since decoding the
// handful of fields used here from the same generic unstructured object
// this package's adapter already reads for every other resource kind needs
// nothing else from that module.
type gatewayRoute struct {
	// Kind is the object's Gateway API kind: "HTTPRoute" or "GRPCRoute".
	// The spec fields below are identical across the two kinds, so all
	// route logic is kind-blind; only ExposurePath attribution differs.
	Kind       string
	Namespace  string
	Name       string
	ParentRefs []parentRef
	Hostnames  []string
	Rules      []gatewayRouteRule
}

// gatewayAPIGroup is the Gateway API group all route kinds and their
// parent references belong to. Gateway API's own defaulting rules treat an
// absent group on a ParentReference as this group.
const gatewayAPIGroup = "gateway.networking.k8s.io"

// parentRef names the Gateway (or other parent) a route attaches to.
// Namespace is a pointer because the API defaults an absent namespace to
// the route's own, per Gateway API's own defaulting rules -- this mirrors
// that rather than assuming empty-string means "same namespace" implicitly.
// Group and Kind follow the same rules: an absent group is the Gateway API
// group and an absent kind is Gateway, so a reference to anything else
// (e.g. a Service parent for mesh use cases) is not a Gateway reference
// and must not attach a route to a Gateway that merely shares its name.
// SectionName, when present, pins the attachment to the one listener with
// that name: per the Gateway API spec the route then attaches to that
// section only, and no other listener of the Gateway may admit it.
// Port, when present, further restricts attachment to listeners on that port.
// Both restrictions must match when supplied together.
type parentRef struct {
	Group       *string
	Kind        *string
	Namespace   *string
	Name        string
	SectionName *string
	Port        *int32
}

// isGatewayParentRef reports whether ref effectively names a Gateway once
// Gateway API's own group/kind defaults are applied.
func isGatewayParentRef(ref parentRef) bool {
	return (ref.Group == nil || *ref.Group == gatewayAPIGroup) &&
		(ref.Kind == nil || *ref.Kind == "Gateway")
}

type gatewayRouteRule struct {
	BackendRefs []backendRef
}

// backendRef names a Service a route rule sends traffic to. Namespace
// defaults to the route's own namespace when nil, same as parentRef --
// Gateway API does not support a backendRef reaching into another
// namespace without a ReferenceGrant, which Index evaluates when it is
// given the cluster's grants (see WithReferenceGrants). Group and Kind
// default to a core-group Service when absent; anything else names a non-Service
// backend (e.g. a multicluster ServiceImport) that this package does not
// model as a Service exposure path, however closely its name matches one.
type backendRef struct {
	// Parent is set only for a backend-scoped mirror. Its filter can run
	// only if forwarding to this originating backend is possible. Rule-level
	// mirrors have no parent and remain independent of ordinary backend refs.
	Parent *backendRef
	// Port names a Service port, not a targetPort or Gateway listener port.
	Port *int32
	// Weight defaults to 1; an explicit zero forwards no requests.
	Weight    *int32
	Group     *string
	Kind      *string
	Namespace *string
	Name      string
}

// isServiceBackendRef reports whether ref effectively names a core-group
// Service once Gateway API's own group/kind defaults are applied.
func isServiceBackendRef(ref backendRef) bool {
	return (ref.Group == nil || *ref.Group == "") &&
		(ref.Kind == nil || *ref.Kind == "Service")
}

// gateway is a minimal local mirror of gateway.networking.k8s.io/v1 Gateway.
type gateway struct {
	Namespace string
	Name      string
	Listeners []listener
}

type listener struct {
	Protocol      string
	Port          int32
	Name          string
	Hostname      string
	AllowedRoutes *allowedRoutes
}

// allowedRoutes mirrors Gateway API's AllowedRoutes: which namespaces'
// routes this listener admits, and which route kinds. A nil AllowedRoutes
// (or a nil Namespaces within it) defaults to "Same" -- routes in the
// Gateway's own namespace only -- per the Gateway API spec's own default.
// A nil or empty Kinds list admits every route kind, also per the spec's
// default.
type allowedRoutes struct {
	Namespaces *routeNamespaces
	Kinds      []routeGroupKind
}

// routeGroupKind mirrors Gateway API's RouteGroupKind. An absent group is
// the Gateway API group, per the spec's defaulting rules.
type routeGroupKind struct {
	Group *string
	Kind  string
}

// admitsRouteKind reports whether the AllowedRoutes kinds list admits a
// route of the given kind once the group default is applied. An empty list
// admits every kind.
func (ar *allowedRoutes) admitsRouteKind(routeKind string) bool {
	if len(ar.Kinds) == 0 {
		return true
	}
	for _, k := range ar.Kinds {
		if (k.Group == nil || *k.Group == gatewayAPIGroup) && k.Kind == routeKind {
			return true
		}
	}
	return false
}

type fromNamespaces string

const (
	fromAll      fromNamespaces = "All"
	fromSelector fromNamespaces = "Selector"
	fromSame     fromNamespaces = "Same"
)

type routeNamespaces struct {
	From     *fromNamespaces
	Selector *metav1.LabelSelector
}

// referenceGrant is a minimal local mirror of Gateway API's ReferenceGrant
// (gateway.networking.k8s.io, served as v1 since Gateway API v1.5 and as
// v1beta1 before that with an identical spec) -- only what authorizing a
// route's cross-namespace Service backendRef needs.
//
// A grant lives in the namespace of the resources it makes referenceable and
// says which kinds, from which namespaces, may reference which kinds there.
type referenceGrant struct {
	// Namespace is the grant's own namespace, which is the namespace of every
	// resource it authorizes references to. ReferenceGrantTo has no namespace.
	Namespace string
	Name      string
	From      []referenceGrantFrom
	To        []referenceGrantTo
}

// referenceGrantFrom is one trusted source of references.
type referenceGrantFrom struct {
	// Group is the referrer's API group. The Gateway API spec says an empty
	// group means the Kubernetes core group, so "" does not name a route.
	Group     string
	Kind      string
	Namespace string
}

// referenceGrantTo is one kind of resource that may be referenced.
type referenceGrantTo struct {
	// Group is the referent's API group; "" is the core group, where Service lives.
	Group string
	Kind  string
	// Name is nil or empty when the entry covers every resource of Group and
	// Kind in the grant's namespace.
	Name *string
}

// routeReferrer identifies the route a cross-namespace reference comes from.
type routeReferrer struct {
	Kind      string
	Namespace string
}

// permitsService reports whether the grant authorizes a route, identified by
// its kind and namespace, to reference the core-group Service target. Per the
// Gateway API spec, the entries of From are alternatives and so are the
// entries of To, so a grant authorizes any From entry together with any To
// entry; separate grants add to one another and are evaluated one by one by
// the caller. Group, kind and namespace are compared exactly.
func (g referenceGrant) permitsService(from routeReferrer, target ServiceRef) bool {
	if g.Namespace != target.Namespace {
		return false
	}
	fromMatches := false
	for _, f := range g.From {
		if f.Group == gatewayAPIGroup && f.Kind == from.Kind && f.Namespace == from.Namespace {
			fromMatches = true
			break
		}
	}
	if !fromMatches {
		return false
	}
	for _, t := range g.To {
		if t.Group != "" || t.Kind != "Service" {
			continue
		}
		if t.Name == nil || *t.Name == "" || *t.Name == target.Name {
			return true
		}
	}
	return false
}
