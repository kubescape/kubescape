package networkpolicy

import (
	networkingv1 "k8s.io/api/networking/v1"
)

// ruleVerdict evaluates one rule's peer list and port list -- both must
// allow for the rule as a whole to allow (a rule's ports and peers are an
// AND, matching the Kubernetes API: a rule matches a connection only if the
// connection's peer is in the rule's from/to list AND its port is in the
// rule's ports list).
func (idx *Index) ruleVerdict(policyNamespace string, peers []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort, counterpart Endpoint, port *PortSpec) (Verdict, string) {
	peerV, peerReason := idx.peerListVerdict(peers, policyNamespace, counterpart)
	if peerV == Denied {
		return Denied, peerReason
	}

	portV, portReason := portVerdict(ports, port)
	if portV == Denied {
		return Denied, portReason
	}

	if peerV == Unknown || portV == Unknown {
		return Unknown, peerReason + "; " + portReason
	}
	return Allowed, peerReason + "; " + portReason
}

// AllowsIngress reports whether dst's combined ingress policies allow
// traffic from src on port. If dst is not ingress-isolated at all (no
// policy selects it and declares Ingress), the connection is allowed by
// default -- NetworkPolicy is opt-in per pod.
//
// When dst is isolated, its matching policies' ingress rules are combined
// with OR (any one matching rule, across any one matching policy, is
// enough to allow the connection) -- this is how multiple NetworkPolicy
// objects selecting the same pod compose in the real API.
func (idx *Index) AllowsIngress(src, dst Endpoint, port *PortSpec) Decision {
	if !idx.IsIsolated(dst, Ingress) {
		return allow("destination is not ingress-isolated by any NetworkPolicy (default allow)", "")
	}

	sawUnknown := false
	for _, cp := range idx.matchingPolicies(dst) {
		if !cp.hasIngress {
			continue
		}
		for _, rule := range cp.policy.Spec.Ingress {
			v, reason := idx.ruleVerdict(cp.policy.Namespace, rule.From, rule.Ports, src, port)
			if v == Allowed {
				return allow(reason, cp.policy.Namespace+"/"+cp.policy.Name)
			}
			if v == Unknown {
				sawUnknown = true
			}
		}
	}

	if sawUnknown {
		return unknown("destination is ingress-isolated; no rule was confirmed to allow this traffic, but at least one rule could not be fully resolved")
	}
	return deny("destination is ingress-isolated and no matching policy rule allows this traffic")
}

// AllowsEgress mirrors AllowsIngress for the source's egress policies.
func (idx *Index) AllowsEgress(src, dst Endpoint, port *PortSpec) Decision {
	if !idx.IsIsolated(src, Egress) {
		return allow("source is not egress-isolated by any NetworkPolicy (default allow)", "")
	}

	sawUnknown := false
	for _, cp := range idx.matchingPolicies(src) {
		if !cp.hasEgress {
			continue
		}
		for _, rule := range cp.policy.Spec.Egress {
			v, reason := idx.ruleVerdict(cp.policy.Namespace, rule.To, rule.Ports, dst, port)
			if v == Allowed {
				return allow(reason, cp.policy.Namespace+"/"+cp.policy.Name)
			}
			if v == Unknown {
				sawUnknown = true
			}
		}
	}

	if sawUnknown {
		return unknown("source is egress-isolated; no rule was confirmed to allow this traffic, but at least one rule could not be fully resolved")
	}
	return deny("source is egress-isolated and no matching policy rule allows this traffic")
}

// Reaches reports whether src can reach dst on port: real NetworkPolicy
// semantics require BOTH src's egress rules AND dst's ingress rules to
// allow the connection independently -- one side allowing is not enough.
// The two Decisions are always returned alongside the combined Verdict so a
// caller can explain which side (or both) was responsible.
func (idx *Index) Reaches(src, dst Endpoint, port *PortSpec) (Verdict, Decision, Decision) {
	egress := idx.AllowsEgress(src, dst, port)
	ingress := idx.AllowsIngress(src, dst, port)

	if egress.Verdict == Denied || ingress.Verdict == Denied {
		return Denied, egress, ingress
	}
	if egress.Verdict == Unknown || ingress.Verdict == Unknown {
		return Unknown, egress, ingress
	}
	return Allowed, egress, ingress
}
