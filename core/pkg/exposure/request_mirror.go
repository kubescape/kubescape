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
// Folding active mirror references into the rule's effective backend list
// reuses listener admission, hostname, Service-port and ReferenceGrant
// uncertainty handling rather than introducing a less strict parallel path.
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
