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
			Namespace *string `json:"namespace,omitempty"`
			Name      string  `json:"name"`
		} `json:"parentRefs,omitempty"`
		Hostnames []string `json:"hostnames,omitempty"`
		Rules     []struct {
			BackendRefs []struct {
				Namespace *string `json:"namespace,omitempty"`
				Name      string  `json:"name"`
			} `json:"backendRefs,omitempty"`
		} `json:"rules,omitempty"`

		// Gateway fields.
		Listeners []struct {
			Name          string `json:"name"`
			AllowedRoutes *struct {
				Namespaces *struct {
					From     *string              `json:"from,omitempty"`
					Selector *unstructuredRawJSON `json:"selector,omitempty"`
				} `json:"namespaces,omitempty"`
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
		r.ParentRefs = append(r.ParentRefs, parentRef{Namespace: p.Namespace, Name: p.Name})
	}
	for _, rule := range wire.Spec.Rules {
		var backends []backendRef
		for _, b := range rule.BackendRefs {
			backends = append(backends, backendRef{Namespace: b.Namespace, Name: b.Name})
		}
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
		out := listener{Name: l.Name}
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
