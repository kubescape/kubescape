package exposure

// gatewayBackendWire is shared by ordinary backends and mirror targets so
// group/kind, namespace, and Service port defaults follow the same path.
// Only ordinary backendRefs have weights and per-backend filters.
type gatewayBackendWire struct {
	Group     *string             `json:"group,omitempty"`
	Kind      *string             `json:"kind,omitempty"`
	Namespace *string             `json:"namespace,omitempty"`
	Name      string              `json:"name"`
	Weight    *int32              `json:"weight,omitempty"`
	Port      *int32              `json:"port,omitempty"`
	Filters   []gatewayFilterWire `json:"filters,omitempty"`
}

type gatewayFilterWire struct {
	Type          string             `json:"type"`
	RequestMirror *requestMirrorWire `json:"requestMirror,omitempty"`
}

type requestMirrorWire struct {
	BackendRef gatewayBackendWire `json:"backendRef"`
	Percent    *int32             `json:"percent,omitempty"`
	Fraction   *struct {
		Numerator   int32  `json:"numerator"`
		Denominator *int32 `json:"denominator,omitempty"`
	} `json:"fraction,omitempty"`
}

func (b gatewayBackendWire) reference() backendRef {
	return backendRef{Group: b.Group, Kind: b.Kind, Namespace: b.Namespace, Name: b.Name, Weight: b.Weight, Port: b.Port}
}

// mirrorBackends includes targets that receive any request copies. A mirror
// is an exposure path even though its response is discarded: external input
// still reaches that service. Both HTTPRoute and GRPCRoute use this shape.
//
// Active mirror references reuse listener admission, hostname, Service-port
// and ReferenceGrant uncertainty handling. Backend-scoped mirrors additionally
// retain their parent reference until Service inventory can validate it.
func mirrorBackends(filters []gatewayFilterWire) []backendRef {
	var backends []backendRef
	for _, filter := range filters {
		mirror := filter.RequestMirror
		if filter.Type != "RequestMirror" || mirror == nil {
			continue
		}
		if mirror.Percent != nil && *mirror.Percent == 0 {
			continue
		}
		if mirror.Fraction != nil && mirror.Fraction.Numerator == 0 {
			continue
		}
		b := mirror.BackendRef.reference()
		// A mirror's BackendObjectReference has no weight. The parent backend's
		// weight gates its filters, but must not suppress a rule-level mirror.
		b.Weight = nil
		backends = append(backends, b)
	}
	return backends
}

// mirrorParentCanForward excludes a dependent mirror only when collected
// parent data proves forwarding impossible. Missing Service/port inventory or
// an unmodeled backend kind remains possible, as with ordinary backend refs.
// Resolve the parent in its own namespace, not the mirror target's namespace.
func (idx *Index) mirrorParentCanForward(mirror backendRef, routeNamespace string) bool {
	parent := mirror.Parent
	if parent == nil {
		return true
	}
	if parent.Weight != nil && *parent.Weight == 0 {
		return false
	}
	if !isServiceBackendRef(*parent) {
		return true
	}
	namespace := routeNamespace
	if parent.Namespace != nil {
		namespace = *parent.Namespace
	}
	service := idx.services[ServiceRef{Namespace: namespace, Name: parent.Name}]
	return gatewayBackendPortMatches(*parent, service)
}
