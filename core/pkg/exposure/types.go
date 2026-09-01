// Package exposure models which of a cluster's Service objects are reachable
// from outside the cluster, and by what mechanism: a Service of type
// LoadBalancer or NodePort is exposed directly; a networking.k8s.io/v1
// Ingress or a Gateway API HTTPRoute exposes whatever Service it names as a
// backend.
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
	// AllowedRoutes -- see Index.gatewayAdmitsRouteNamespace). A listener
	// whose admission can't be confirmed one way or the other is
	// conservatively treated as admitting it.
	ExposureHTTPRoute
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
	// Source names the object responsible: the Ingress/HTTPRoute
	// (namespace/name) that names this Service as a backend, or the
	// Service itself for LoadBalancer/NodePort.
	Source string
	// Host is the hostname traffic must arrive with to reach this path, per
	// the responsible Ingress rule or HTTPRoute hostname. Empty means any
	// host (an Ingress rule/defaultBackend with no host restriction, a
	// LoadBalancer/NodePort Service, or an HTTPRoute with no hostnames
	// declared).
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

// httpRoute is a minimal local mirror of gateway.networking.k8s.io/v1
// HTTPRoute -- only the fields exposure analysis needs. Defined locally
// rather than vendoring sigs.k8s.io/gateway-api, since decoding the handful
// of fields used here from the same generic unstructured object this
// package's adapter already reads for every other resource kind needs
// nothing else from that module.
type httpRoute struct {
	Namespace  string
	Name       string
	ParentRefs []parentRef
	Hostnames  []string
	Rules      []httpRouteRule
}

// parentRef names the Gateway (or other parent) an HTTPRoute attaches to.
// Namespace is a pointer because the API defaults an absent namespace to
// the route's own, per Gateway API's own defaulting rules -- this mirrors
// that rather than assuming empty-string means "same namespace" implicitly.
type parentRef struct {
	Namespace *string
	Name      string
}

type httpRouteRule struct {
	BackendRefs []backendRef
}

// backendRef names a Service an HTTPRoute rule sends matching traffic to.
// Namespace defaults to the route's own namespace when nil, same as
// parentRef -- Gateway API does not support a backendRef reaching into
// another namespace without a ReferenceGrant, which this package does not
// model (see AnalyzeExposure's doc comment).
type backendRef struct {
	Namespace *string
	Name      string
}

// gateway is a minimal local mirror of gateway.networking.k8s.io/v1 Gateway.
type gateway struct {
	Namespace string
	Name      string
	Listeners []listener
}

type listener struct {
	Name          string
	AllowedRoutes *allowedRoutes
}

// allowedRoutes mirrors Gateway API's AllowedRoutes: which namespaces'
// HTTPRoutes this listener admits. A nil AllowedRoutes (or a nil Namespaces
// within it) defaults to "Same" -- routes in the Gateway's own namespace
// only -- per the Gateway API spec's own default.
type allowedRoutes struct {
	Namespaces *routeNamespaces
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
