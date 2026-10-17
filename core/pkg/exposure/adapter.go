package exposure

import (
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FromResources converts kubescape's generically-collected scan resources
// into the typed inputs NewIndex needs. Any object that is not a Service,
// Ingress, or Namespace is ignored -- Gateway API objects are decoded
// separately by FromUnstructuredGatewayAPI, since (unlike the other three)
// this repo has no typed Go representation of them to decode into via
// workloadinterface.IMetadata's usual JSON round-trip. A Service, Ingress,
// or Namespace object that fails to decode is skipped, with its error
// appended to errs, rather than aborting the whole conversion over one bad
// object.
func FromResources(resources map[string]workloadinterface.IMetadata) (services []corev1.Service, ingresses []networkingv1.Ingress, namespaces []NamespaceInfo, errs []error) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		switch resource.GetKind() {
		case "Service":
			var s corev1.Service
			if err := decode(resource.GetObject(), &s); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			services = append(services, s)
		case "Ingress":
			var ing networkingv1.Ingress
			if err := decode(resource.GetObject(), &ing); err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			ingresses = append(ingresses, ing)
		case "Namespace":
			namespaces = append(namespaces, NamespaceInfo{
				Name:   resource.GetName(),
				Labels: resourceLabels(resource),
			})
		}
	}
	return services, ingresses, namespaces, errs
}

// FromUnstructuredGatewayAPI decodes Gateway API route (HTTPRoute,
// GRPCRoute) and Gateway objects from their generic unstructured
// representation. Kept separate from FromResources because these kinds are
// not part of kubescape's generic scanned-resource set on every cluster
// (the Gateway API CRDs may not even be installed) and have no typed Go
// representation this repo already vendors to decode into. A malformed
// object of any of these kinds is skipped, with its error appended to
// errs, same as FromResources.
func FromUnstructuredGatewayAPI(resources map[string]workloadinterface.IMetadata) (routes []gatewayRoute, gateways []gateway, errs []error) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		switch resource.GetKind() {
		case "HTTPRoute", "GRPCRoute":
			r, err := decodeGatewayRoute(resource.GetKind(), resource.GetObject())
			if err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			routes = append(routes, r)
		case "Gateway":
			g, err := decodeGateway(resource.GetObject())
			if err != nil {
				errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
				continue
			}
			gateways = append(gateways, g)
		}
	}
	return routes, gateways, errs
}

// FromUnstructuredReferenceGrants decodes ReferenceGrant objects from their
// generic unstructured representation. v1 and v1beta1 share one spec shape, so
// the served version does not matter. Kept apart from
// FromUnstructuredGatewayAPI because grants are an independent collection with
// their own availability: a caller that could not list them must not pass an
// empty result off as "no grants" (see WithReferenceGrants).
//
// A grant that cannot be decoded, or that lacks what is needed to place it
// (its namespace, a non-empty from and to, a kind and a source namespace on
// every entry), is skipped and its error appended to errs. A skipped grant may
// have authorized a reference, so a caller that sees any error here must treat
// authorization as undetermined rather than as denied.
func FromUnstructuredReferenceGrants(resources map[string]workloadinterface.IMetadata) (grants []referenceGrant, errs []error) {
	for _, resource := range resources {
		if resource == nil || resource.GetKind() != "ReferenceGrant" {
			continue
		}
		g, err := decodeReferenceGrant(resource.GetObject())
		if err != nil {
			errs = append(errs, fmt.Errorf("resource %s: %w", resource.GetID(), err))
			continue
		}
		grants = append(grants, g)
	}
	return grants, errs
}

// ReferenceGrantsOption decodes a complete, successful listing of the
// cluster's ReferenceGrants into an Index option (see WithReferenceGrants). An
// empty resources map is a real answer: no grants exist.
//
// When any grant cannot be decoded the option is nil and errs says why: that
// grant may have authorized a reference, so authorization is undetermined and
// the caller must build the Index without grants (keeping such references
// reported as unclear) and surface the errors.
func ReferenceGrantsOption(resources map[string]workloadinterface.IMetadata) (opt Option, errs []error) {
	grants, errs := FromUnstructuredReferenceGrants(resources)
	if len(errs) > 0 {
		return nil, errs
	}
	return WithReferenceGrants(grants), nil
}

// referenceGrantWire is the ReferenceGrant JSON shape. Group is a pointer only
// so that an entry that omits it reads the same as the empty (core) group the
// spec infers.
type referenceGrantWire struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		From []struct {
			Group     *string `json:"group,omitempty"`
			Kind      string  `json:"kind"`
			Namespace string  `json:"namespace"`
		} `json:"from,omitempty"`
		To []struct {
			Group *string `json:"group,omitempty"`
			Kind  string  `json:"kind"`
			Name  *string `json:"name,omitempty"`
		} `json:"to,omitempty"`
	} `json:"spec"`
}

func decodeReferenceGrant(obj map[string]any) (referenceGrant, error) {
	var wire referenceGrantWire
	if err := decode(obj, &wire); err != nil {
		return referenceGrant{}, err
	}
	if wire.Metadata.Namespace == "" {
		return referenceGrant{}, fmt.Errorf("ReferenceGrant %q has no namespace", wire.Metadata.Name)
	}
	if len(wire.Spec.From) == 0 || len(wire.Spec.To) == 0 {
		return referenceGrant{}, fmt.Errorf("ReferenceGrant %s/%s needs at least one from and one to entry", wire.Metadata.Namespace, wire.Metadata.Name)
	}

	g := referenceGrant{Namespace: wire.Metadata.Namespace, Name: wire.Metadata.Name}
	for i, f := range wire.Spec.From {
		if f.Kind == "" || f.Namespace == "" {
			return referenceGrant{}, fmt.Errorf("ReferenceGrant %s/%s: from[%d] needs a kind and a namespace", g.Namespace, g.Name, i)
		}
		g.From = append(g.From, referenceGrantFrom{Group: derefString(f.Group), Kind: f.Kind, Namespace: f.Namespace})
	}
	for i, t := range wire.Spec.To {
		if t.Kind == "" {
			return referenceGrant{}, fmt.Errorf("ReferenceGrant %s/%s: to[%d] needs a kind", g.Namespace, g.Name, i)
		}
		g.To = append(g.To, referenceGrantTo{Group: derefString(t.Group), Kind: t.Kind, Name: t.Name})
	}
	return g, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// decode converts an unstructured object's generic map into its typed shape
// via a JSON round-trip, the same pattern core/pkg/networkpolicy's and
// core/pkg/mapreconcile's adapters use to bridge a dynamic client's generic
// representation and a concrete Kubernetes API type.
func decode(obj map[string]any, out any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	return nil
}

// gatewayAPIWireShape mirrors just the fields this package reads from a
// Gateway API route (HTTPRoute, GRPCRoute) or Gateway's spec, in their
// real Gateway API JSON shape (camelCase, pointer-optional fields),
// separate from this package's own internal gatewayRoute/gateway types so
// a JSON round-trip can populate it directly without custom unmarshaling.
// The route spec fields are identical between HTTPRoute and GRPCRoute.
type gatewayAPIWireShape struct {
	Metadata struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		// Route fields (HTTPRoute and GRPCRoute share this shape).
		ParentRefs []struct {
			Group       *string `json:"group,omitempty"`
			Kind        *string `json:"kind,omitempty"`
			Namespace   *string `json:"namespace,omitempty"`
			Name        string  `json:"name"`
			SectionName *string `json:"sectionName,omitempty"`
			Port        *int32  `json:"port,omitempty"`
		} `json:"parentRefs,omitempty"`
		Hostnames []string `json:"hostnames,omitempty"`
		Rules     []struct {
			BackendRefs []gatewayBackendWire `json:"backendRefs,omitempty"`
			Filters     []gatewayFilterWire  `json:"filters,omitempty"`
		} `json:"rules,omitempty"`

		// Gateway fields.
		Listeners []struct {
			Protocol      string `json:"protocol"`
			Name          string `json:"name"`
			Hostname      string `json:"hostname,omitempty"`
			Port          int32  `json:"port"`
			AllowedRoutes *struct {
				Namespaces *struct {
					From     *string              `json:"from,omitempty"`
					Selector *unstructuredRawJSON `json:"selector,omitempty"`
				} `json:"namespaces,omitempty"`
				Kinds []struct {
					Group *string `json:"group,omitempty"`
					Kind  string  `json:"kind"`
				} `json:"kinds,omitempty"`
			} `json:"allowedRoutes,omitempty"`
		} `json:"listeners,omitempty"`
	} `json:"spec"`
}

// unstructuredRawJSON defers a LabelSelector's decode: this package's own
// types.go uses k8s.io/apimachinery's own metav1.LabelSelector directly for
// routeNamespaces.Selector, so wireToSelector below re-marshals this raw
// blob into that type rather than duplicating its field shape here too.
type unstructuredRawJSON map[string]any

// decodeGatewayRoute decodes an HTTPRoute or GRPCRoute. The spec fields
// this package reads are identical between the two kinds, so only the
// kind attribution differs.
func decodeGatewayRoute(kind string, obj map[string]any) (gatewayRoute, error) {
	var wire gatewayAPIWireShape
	if err := decode(obj, &wire); err != nil {
		return gatewayRoute{}, err
	}

	r := gatewayRoute{
		Kind:      kind,
		Namespace: wire.Metadata.Namespace,
		Name:      wire.Metadata.Name,
		Hostnames: wire.Spec.Hostnames,
	}
	for _, p := range wire.Spec.ParentRefs {
		r.ParentRefs = append(r.ParentRefs, parentRef{Group: p.Group, Kind: p.Kind, Namespace: p.Namespace, Name: p.Name, SectionName: p.SectionName, Port: p.Port})
	}
	for _, rule := range wire.Spec.Rules {
		var backends []backendRef
		for _, b := range rule.BackendRefs {
			backends = append(backends, b.reference())
			// Backend filters apply only when traffic is sent to that backend.
			if b.Weight == nil || *b.Weight > 0 {
				parent := b.reference()
				for _, mirror := range mirrorBackends(b.Filters) {
					mirror.Parent = &parent
					backends = append(backends, mirror)
				}
			}
		}
		backends = append(backends, mirrorBackends(rule.Filters)...)
		r.Rules = append(r.Rules, gatewayRouteRule{BackendRefs: backends})
	}
	return r, nil
}

func decodeGateway(obj map[string]any) (gateway, error) {
	var wire gatewayAPIWireShape
	if err := decode(obj, &wire); err != nil {
		return gateway{}, err
	}

	g := gateway{Namespace: wire.Metadata.Namespace, Name: wire.Metadata.Name}
	for _, l := range wire.Spec.Listeners {
		out := listener{Name: l.Name, Hostname: l.Hostname, Port: l.Port, Protocol: l.Protocol}
		if l.AllowedRoutes != nil {
			ar := &allowedRoutes{}
			if l.AllowedRoutes.Namespaces != nil {
				rn := &routeNamespaces{}
				if l.AllowedRoutes.Namespaces.From != nil {
					f := fromNamespaces(*l.AllowedRoutes.Namespaces.From)
					rn.From = &f
				}
				if l.AllowedRoutes.Namespaces.Selector != nil {
					sel, err := wireToSelector(*l.AllowedRoutes.Namespaces.Selector)
					if err != nil {
						return gateway{}, fmt.Errorf("listener %q: allowedRoutes.namespaces.selector: %w", l.Name, err)
					}
					rn.Selector = sel
				}
				ar.Namespaces = rn
			}
			for _, k := range l.AllowedRoutes.Kinds {
				ar.Kinds = append(ar.Kinds, routeGroupKind{Group: k.Group, Kind: k.Kind})
			}
			out.AllowedRoutes = ar
		}
		g.Listeners = append(g.Listeners, out)
	}
	return g, nil
}

// wireToSelector re-marshals a raw selector blob (already-decoded generic
// JSON) into metav1.LabelSelector, the type routeNamespaces.Selector uses.
func wireToSelector(raw unstructuredRawJSON) (*metav1.LabelSelector, error) {
	b, err := json.Marshal(map[string]any(raw))
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var sel metav1.LabelSelector
	if err := json.Unmarshal(b, &sel); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &sel, nil
}

// resourceLabels extracts a resource's labels. IMetadata does not carry
// labels itself; IBasicWorkload does -- same helper as
// core/pkg/networkpolicy's and core/pkg/mapreconcile's adapters.
func resourceLabels(resource workloadinterface.IMetadata) map[string]string {
	bw, ok := resource.(workloadinterface.IBasicWorkload)
	if !ok {
		return nil
	}
	return bw.GetLabels()
}
