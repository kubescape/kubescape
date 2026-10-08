package networkpolicy

import (
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ruleVerdict evaluates one rule's peer list and port list -- both must
// allow for the rule as a whole to allow (a rule's ports and peers are an
// AND, matching the Kubernetes API: a rule matches a connection only if the
// connection's peer is in the rule's from/to list AND its port is in the
// rule's ports list). selected is the endpoint the rule's policy selects (the
// destination of an ingress rule, the source of an egress rule) and
// counterpart is the endpoint its peers are matched against.
func (idx *Index) ruleVerdict(policyNamespace string, peers []networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort, selected, counterpart Endpoint, port *PortSpec) (Verdict, string) {
	peerV, peerReason := idx.peerListVerdict(peers, policyNamespace, selected, counterpart)
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
			v, reason := idx.ruleVerdict(cp.policy.Namespace, rule.From, rule.Ports, dst, src, port)
			if v == Allowed {
				return allow(reason, cp.policy.Namespace+"/"+cp.policy.Name)
			}
			if v == Unknown {
				sawUnknown = true
			}
		}
	}

	if sawUnknown {
		return unknown("destination is ingress-isolated; no rule was confirmed to allow this traffic, but at least one rule could not be fully resolved" + hostNetworkNote(src, dst))
	}
	return denyUnlessHostNetwork(src, dst, "destination is ingress-isolated and no matching policy rule allows this traffic")
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
			v, reason := idx.ruleVerdict(cp.policy.Namespace, rule.To, rule.Ports, src, dst, port)
			if v == Allowed {
				return allow(reason, cp.policy.Namespace+"/"+cp.policy.Name)
			}
			if v == Unknown {
				sawUnknown = true
			}
		}
	}

	if sawUnknown {
		return unknown("source is egress-isolated; no rule was confirmed to allow this traffic, but at least one rule could not be fully resolved" + hostNetworkNote(src, dst))
	}
	return denyUnlessHostNetwork(src, dst, "source is egress-isolated and no matching policy rule allows this traffic")
}

// denyUnlessHostNetwork is deny, except when either end of the connection is
// a hostNetwork pod, where a denial cannot be confirmed (see
// Endpoint.HostNetwork): if the isolated pod is the hostNetwork one, most
// network plugins do not enforce the policy that isolates it; if the other
// pod is, its traffic is the node's, which a plugin always allows to and
// from the pods on that same node whatever their policies say.
func denyUnlessHostNetwork(src, dst Endpoint, reason string) Decision {
	if note := hostNetworkNote(src, dst); note != "" {
		return unknown(reason + note)
	}
	return deny(reason)
}

// hostNetworkNote is the suffix that explains an Unknown decision involving
// a hostNetwork pod, or "" when neither src nor dst is one.
func hostNetworkNote(src, dst Endpoint) string {
	var who string
	switch {
	case src.HostNetwork && dst.HostNetwork:
		who = "source and destination use"
	case src.HostNetwork:
		who = "source uses"
	case dst.HostNetwork:
		who = "destination uses"
	default:
		return ""
	}
	return "; the " + who + " the host network (hostNetwork: true), where NetworkPolicy behaviour is undefined and most network plugins treat the traffic as the node's own instead of applying pod policies to it"
}

// Reaches reports whether src can reach dst on port: real NetworkPolicy
// semantics require BOTH src's egress rules AND dst's ingress rules to
// allow the same port and protocol. A nil port asks whether any such pair
// exists across TCP, UDP, and SCTP on ports 1 through 65535.
// The two Decisions are always returned alongside the combined Verdict so a
// caller can explain which side (or both) was responsible. With a nil port,
// a Denied verdict can accompany two independently Allowed decisions when
// the directions allow different ports/protocols; their reasons explain this.
//
// Exception: a Pod can always reach itself. The Kubernetes NetworkPolicy
// docs list this as one of the ways a peer is identified -- "a pod cannot
// block access to itself" -- regardless of any policy selecting it, so
// same-Pod traffic is never evaluated against policy at all.
func (idx *Index) Reaches(src, dst Endpoint, port *PortSpec) (Verdict, Decision, Decision) {
	if samePod(src, dst) {
		d := allow("source and destination are the same Pod; NetworkPolicy cannot block a Pod from reaching itself", "")
		return Allowed, d, d
	}
	if port == nil {
		return idx.reachesAnyPort(src, dst)
	}
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

// reachabilityPorts partitions the valid port space at every numeric rule
// boundary. For a fixed protocol, explicit matching is constant between these
// boundaries: peers do not depend on ports, and named ports remain Unknown.
// Evaluating one port per partition therefore covers every possible outcome
// without exhaustively checking all 65535 ports.
func (idx *Index) reachabilityPorts(src, dst Endpoint) []int32 {
	ports := []int32{1}
	add := func(boundary int32) {
		if boundary >= 1 && boundary <= 65535 {
			ports = append(ports, boundary)
		}
	}
	collect := func(entries []networkingv1.NetworkPolicyPort) {
		for _, p := range entries {
			if p.Port == nil || p.Port.Type == intstr.String {
				continue
			}
			lo, ok := safePort(p.Port.IntValue())
			if !ok {
				continue
			}
			hi := lo
			if p.EndPort != nil {
				hi = *p.EndPort
			}
			add(lo)
			// Check before adding to avoid overflowing malformed manifest
			// values. Boundaries outside the valid query space are irrelevant.
			if hi >= 1 && hi < 65535 {
				add(hi + 1)
			}
		}
	}
	for _, cp := range idx.matchingPolicies(src) {
		if cp.hasEgress {
			for _, rule := range cp.policy.Spec.Egress {
				collect(rule.Ports)
			}
		}
	}
	for _, cp := range idx.matchingPolicies(dst) {
		if cp.hasIngress {
			for _, rule := range cp.policy.Spec.Ingress {
				collect(rule.Ports)
			}
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

func (idx *Index) reachesAnyPort(src, dst Endpoint) (Verdict, Decision, Decision) {
	ports := idx.reachabilityPorts(src, dst)
	egressSummary := deny("no egress rule allows any port/protocol to this destination")
	ingressSummary := deny("no ingress rule allows any port/protocol from this source")
	var unknownEgress, unknownIngress Decision
	sawUnknown := false
	// Each direction is an OR across all candidates: Allowed wins over
	// Unknown, which wins over Denied. Preserve the first supporting decision.
	summarize := func(summary *Decision, candidate Decision) {
		if (candidate.Verdict == Allowed && summary.Verdict != Allowed) ||
			(candidate.Verdict == Unknown && summary.Verdict == Denied) {
			*summary = candidate
		}
	}
	for _, protocol := range []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP} {
		for _, port := range ports {
			v, egress, ingress := idx.Reaches(src, dst, &PortSpec{Port: port, Protocol: protocol})
			prefix := fmt.Sprintf("port %d/%s: ", port, protocol)
			egress.Reason = prefix + egress.Reason
			ingress.Reason = prefix + ingress.Reason
			if v == Allowed {
				return Allowed, egress, ingress
			}
			if v == Unknown && !sawUnknown {
				sawUnknown = true
				unknownEgress, unknownIngress = egress, ingress
			}
			summarize(&egressSummary, egress)
			summarize(&ingressSummary, ingress)
		}
	}
	if sawUnknown {
		return Unknown, unknownEgress, unknownIngress
	}
	const noOverlap = "; no common port/protocol is possible across egress and ingress"
	egressSummary.Reason = "egress considered independently: " + egressSummary.Reason + noOverlap
	ingressSummary.Reason = "ingress considered independently: " + ingressSummary.Reason + noOverlap
	return Denied, egressSummary, ingressSummary
}

// samePod reports whether a and b identify the same Pod (same namespace and
// name). Both must be non-empty: two Endpoints with an unset Namespace or Name
// are not "the same pod" just because those fields are blank.
func samePod(a, b Endpoint) bool {
	return a.Namespace != "" && a.Name != "" &&
		a.Namespace == b.Namespace && a.Name == b.Name
}
