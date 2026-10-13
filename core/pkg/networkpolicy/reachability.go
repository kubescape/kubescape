package networkpolicy

import (
	"fmt"
	"net"
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
// When the two Pods have addresses in more than one IP family (dual-stack),
// a connection still uses a single family at both ends, so an ipBlock peer
// in src's egress rules and one in dst's ingress rules must admit the same
// family. Each family the Pods share is evaluated on its own and the
// connection is Allowed if any one of them is; as with a nil port, a Denied
// verdict can then accompany two independently Allowed decisions. Reasons
// name an IP family only when the families do not all give the same answer.
//
// For the same reason, two Pods whose addresses are all known and share no
// IP family are Denied outright, whatever any policy says: there is no
// connection for a policy to allow. An address that is missing or does not
// parse is not known to be of another family, so it never causes this, and
// neither do the addresses of a hostNetwork Pod, which are its node's and
// need not be all the node has: that case is Unknown.
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
	if d, none := noCommonIPFamily(src, dst); none {
		return d.Verdict, d, d
	}
	if pairs := sameFamilyPairs(src, dst); len(pairs) > 0 {
		return idx.reachesAnyFamily(pairs, port)
	}
	if port == nil {
		return idx.reachesAnyPort([]familyPair{{src: src, dst: dst}})
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

// reachesAnyPort answers Reaches for a nil port. pairs is the single src/dst
// pair of the query or, when the answer depends on the IP family, that pair
// narrowed to each family (see reachesAnyFamily); the rule ports to probe do
// not depend on addresses, so they are the same for every pair.
func (idx *Index) reachesAnyPort(pairs []familyPair) (Verdict, Decision, Decision) {
	ports := idx.reachabilityPorts(pairs[0].src, pairs[0].dst)
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
	noOverlap := "; no common port/protocol is possible across egress and ingress"
	for _, pair := range pairs {
		family := ""
		if pair.family != "" {
			family = pair.family + ": "
			noOverlap = "; no common IP family and port/protocol is possible across egress and ingress"
		}
		for _, protocol := range []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP} {
			for _, port := range ports {
				v, egress, ingress := idx.Reaches(pair.src, pair.dst, &PortSpec{Port: port, Protocol: protocol})
				prefix := fmt.Sprintf("%sport %d/%s: ", family, port, protocol)
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
	}
	if sawUnknown {
		return Unknown, unknownEgress, unknownIngress
	}
	egressSummary.Reason = "egress considered independently: " + egressSummary.Reason + noOverlap
	ingressSummary.Reason = "ingress considered independently: " + ingressSummary.Reason + noOverlap
	return Denied, egressSummary, ingressSummary
}

// familyPair is src and dst narrowed to the one address each has in family.
// With an empty family it is a src/dst pair as queried, not narrowed.
type familyPair struct {
	family   string
	src, dst Endpoint
}

// ipFamily names the IP family of ip, or "" when ip does not parse.
func ipFamily(ip string) string {
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil:
		return ""
	case parsed.To4() != nil:
		return "IPv4"
	default:
		return "IPv6"
	}
}

// noCommonIPFamily reports whether the addresses of src and dst share no IP
// family, with the decision that follows from it. That takes an address on
// both sides and every one of them parsing: a pod with no known address, or
// with one that is not an IP address, may still have an address in the other
// pod's family, so nothing is concluded about it here.
//
// A pod's own addresses (status.podIPs) are all it has, so two such pods
// cannot connect and the decision is Denied. A hostNetwork pod instead
// reports the addresses registered for its node, at most one per family,
// and uses the node's network, which may have addresses beyond those; the
// decision is then Unknown rather than a guess either way.
func noCommonIPFamily(src, dst Endpoint) (decision Decision, none bool) {
	families := func(e Endpoint) (only string, known bool) {
		for _, ip := range e.addresses() {
			family := ipFamily(ip)
			if family == "" || (only != "" && family != only) {
				// Unparseable, or both families: either way not a pod
				// known to have a single family.
				return "", false
			}
			only = family
		}
		return only, only != ""
	}
	srcFamily, srcKnown := families(src)
	dstFamily, dstKnown := families(dst)
	if !srcKnown || !dstKnown || srcFamily == dstFamily {
		return Decision{}, false
	}
	reason := fmt.Sprintf("source has only %s addresses and destination has only %s addresses; ", srcFamily, dstFamily)
	if src.HostNetwork || dst.HostNetwork {
		return unknown(reason + "they share no IP family, but a pod on the host network (hostNetwork: true) reports only the addresses registered for its node, which may have others"), true
	}
	return deny(reason + "with no IP family in common no connection between them is possible, whatever NetworkPolicy allows"), true
}

// sameFamilyPairs lists the address pairs a connection from src to dst can
// use when at least one of them has more than one address: every src address
// with every dst address of the same IP family. It returns nil when neither
// endpoint has several addresses, and also when one of them has no known
// address or none that parses -- there is nothing to pair then, and each
// direction is evaluated against whatever addresses are known (see
// peerMatches for a peer that only some of them satisfy). Pods whose known
// addresses share no family never get here (see noCommonIPFamily).
func sameFamilyPairs(src, dst Endpoint) []familyPair {
	srcAddrs, dstAddrs := src.addresses(), dst.addresses()
	if len(srcAddrs) < 2 && len(dstAddrs) < 2 {
		return nil
	}
	var pairs []familyPair
	for _, s := range srcAddrs {
		family := ipFamily(s)
		if family == "" {
			continue
		}
		for _, d := range dstAddrs {
			if ipFamily(d) != family {
				continue
			}
			pair := familyPair{family: family, src: src, dst: dst}
			pair.src.IP, pair.src.IPs = s, nil
			pair.dst.IP, pair.dst.IPs = d, nil
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

// reachesAnyFamily ORs Reaches across pairs: Allowed wins over Unknown, which
// wins over Denied. When every family gives the same verdict and the same two
// decisions, the IP family plays no part in the answer and that common result
// is returned as it is; otherwise each returned reason names the family it
// was reached in.
func (idx *Index) reachesAnyFamily(pairs []familyPair, port *PortSpec) (Verdict, Decision, Decision) {
	type result struct {
		verdict         Verdict
		egress, ingress Decision
	}
	results := make([]result, len(pairs))
	sameForEveryFamily := true
	for i, pair := range pairs {
		v, egress, ingress := idx.Reaches(pair.src, pair.dst, port)
		results[i] = result{v, egress, ingress}
		if results[i] != results[0] {
			sameForEveryFamily = false
		}
	}
	if sameForEveryFamily {
		return results[0].verdict, results[0].egress, results[0].ingress
	}
	if port == nil {
		// Probe the families port by port in one pass, so that a Denied is
		// summarised once across both instead of once per family.
		return idx.reachesAnyPort(pairs)
	}

	var egressSummary, ingressSummary, unknownEgress, unknownIngress Decision
	sawUnknown := false
	summarize := func(summary *Decision, candidate Decision) {
		if (candidate.Verdict == Allowed && summary.Verdict != Allowed) ||
			(candidate.Verdict == Unknown && summary.Verdict == Denied) {
			*summary = candidate
		}
	}
	for i, pair := range pairs {
		v, egress, ingress := results[i].verdict, results[i].egress, results[i].ingress
		egress.Reason = pair.family + ": " + egress.Reason
		ingress.Reason = pair.family + ": " + ingress.Reason
		if v == Allowed {
			return Allowed, egress, ingress
		}
		if v == Unknown && !sawUnknown {
			sawUnknown = true
			unknownEgress, unknownIngress = egress, ingress
		}
		if i == 0 {
			egressSummary, ingressSummary = egress, ingress
			continue
		}
		summarize(&egressSummary, egress)
		summarize(&ingressSummary, ingress)
	}
	if sawUnknown {
		return Unknown, unknownEgress, unknownIngress
	}
	if egressSummary.Verdict != Denied && ingressSummary.Verdict != Denied {
		const noOverlap = "; no IP family is allowed by both egress and ingress"
		egressSummary.Reason = "egress considered independently: " + egressSummary.Reason + noOverlap
		ingressSummary.Reason = "ingress considered independently: " + ingressSummary.Reason + noOverlap
	}
	return Denied, egressSummary, ingressSummary
}

// samePod reports whether a and b identify the same Pod (same namespace and
// name). Both must be non-empty: two Endpoints with an unset Namespace or Name
// are not "the same pod" just because those fields are blank.
func samePod(a, b Endpoint) bool {
	return a.Namespace != "" && a.Name != "" &&
		a.Namespace == b.Namespace && a.Name == b.Name
}
