package networkpolicy

import (
	"fmt"
	"math"
	"net"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// safePort converts an int (from intstr.IntValue, which is always a plain
// int regardless of platform width) to int32, reporting false instead of
// silently wrapping when v falls outside int32's range.
func safePort(v int) (int32, bool) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, false
	}
	return int32(v), true
}

// corev1ProtocolOrDefault mirrors the Kubernetes API's own default: an
// unset NetworkPolicyPort.Protocol means TCP.
func corev1ProtocolOrDefault(p corev1.Protocol) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return p
}

// peerMatches reports whether one NetworkPolicyPeer selects candidate, given
// the namespace the owning policy (and rule) lives in. The bool return is
// the match result; the second return is false only when the peer's kind
// cannot be evaluated at all from the data available (an ipBlock peer
// against a candidate with no known IP, or a namespaceSelector against a
// namespace this Index was never given labels for) -- in that case the
// first return is meaningless and callers must treat this as Unknown, not
// as a confident false.
func (idx *Index) peerMatches(peer networkingv1.NetworkPolicyPeer, policyNamespace string, candidate Endpoint) (matched bool, determinable bool) {
	if peer.IPBlock != nil {
		if candidate.IP == "" {
			return false, false
		}
		return ipBlockMatches(peer.IPBlock, candidate.IP), true
	}

	switch {
	case peer.NamespaceSelector != nil && peer.PodSelector != nil:
		nsSel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return false, true
		}
		podSel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false, true
		}
		if !podSel.Matches(labels.Set(candidate.Labels)) {
			return false, true // pod side already fails; namespace labels are moot
		}
		nsMatch, determinable := idx.namespaceSelectorMatches(nsSel, candidate.Namespace)
		return nsMatch, determinable

	case peer.NamespaceSelector != nil:
		nsSel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return false, true
		}
		return idx.namespaceSelectorMatches(nsSel, candidate.Namespace)

	case peer.PodSelector != nil:
		// A podSelector with no namespaceSelector only ever selects pods in
		// the same namespace as the policy that declares it.
		if candidate.Namespace != policyNamespace {
			return false, true
		}
		podSel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return false, true
		}
		return podSel.Matches(labels.Set(candidate.Labels)), true

	default:
		// No selector or ipBlock at all. The API server rejects a peer like
		// this, but a defensively-parsed object should not be treated as
		// matching everything.
		return false, true
	}
}

// namespaceSelectorMatches evaluates nsSel against namespace's labels.
// A selector that matches everything (nil or empty matchLabels/
// matchExpressions) is determinable regardless of whether this Index was
// given that namespace's labels, since the labels can't change the answer;
// any other selector requires the namespace's labels to be known.
func (idx *Index) namespaceSelectorMatches(nsSel labels.Selector, namespace string) (matched bool, determinable bool) {
	if nsSel.Empty() {
		return true, true
	}
	nsInfo, ok := idx.namespaces[namespace]
	if !ok {
		return false, false
	}
	return nsSel.Matches(labels.Set(nsInfo.Labels)), true
}

// ipBlockMatches reports whether ip falls inside block.CIDR and outside
// every one of block.Except.
func ipBlockMatches(block *networkingv1.IPBlock, ip string) bool {
	if block.CIDR == "" {
		return false
	}
	_, cidrNet, err := net.ParseCIDR(block.CIDR)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	if !cidrNet.Contains(parsedIP) {
		return false
	}
	for _, except := range block.Except {
		_, exceptNet, err := net.ParseCIDR(except)
		if err != nil {
			continue
		}
		if exceptNet.Contains(parsedIP) {
			return false
		}
	}
	return true
}

// peerListVerdict OR-combines every peer in peers against candidate: an
// empty/nil peer list matches everything (a rule with no from/to
// restriction), matching Kubernetes' own semantics for an absent peer list.
func (idx *Index) peerListVerdict(peers []networkingv1.NetworkPolicyPeer, policyNamespace string, candidate Endpoint) (Verdict, string) {
	if len(peers) == 0 {
		return Allowed, "rule has no source/destination restriction"
	}

	sawUnknown := false
	for _, peer := range peers {
		matched, determinable := idx.peerMatches(peer, policyNamespace, candidate)
		if !determinable {
			sawUnknown = true
			continue
		}
		if matched {
			return Allowed, "matched a peer in this rule"
		}
	}
	if sawUnknown {
		return Unknown, "a peer in this rule could not be resolved (unknown IP or namespace labels)"
	}
	return Denied, "no peer in this rule matched"
}

// portVerdict reports whether ports allows query. An empty/nil port list
// matches every port, matching Kubernetes' own semantics for an absent port
// list. A rule entry with a named (string) container port cannot be
// resolved without that container's port-name mapping, which this static,
// container-spec-free model does not have, so it reports Unknown rather
// than silently skipping or guessing.
func portVerdict(ports []networkingv1.NetworkPolicyPort, query *PortSpec) (Verdict, string) {
	if len(ports) == 0 {
		return Allowed, "rule has no port restriction"
	}
	if query == nil {
		// Caller did not ask about a specific port; a rule that restricts
		// ports at all cannot be confirmed to cover "any port."
		return Unknown, "rule restricts ports, but no specific port was queried"
	}

	sawUnknown := false
	for _, p := range ports {
		var protoVal corev1.Protocol
		if p.Protocol != nil {
			protoVal = *p.Protocol
		}
		proto := corev1ProtocolOrDefault(protoVal)
		if proto != query.protocol() {
			continue
		}
		if p.Port == nil {
			// No port specified alongside a protocol restriction: matches
			// every port of that protocol.
			return Allowed, fmt.Sprintf("matched protocol %s with no port restriction", proto)
		}
		if p.Port.Type == intstr.String {
			sawUnknown = true
			continue
		}
		lo, ok := safePort(p.Port.IntValue())
		if !ok {
			// A scan can read a NetworkPolicy straight from a manifest that
			// was never actually applied (and so never validated by the
			// API server), so a port outside 0-65535 is a real possibility
			// here, not just a defensive check. Such an entry can never
			// match a real port, rather than wrapping into a bogus value.
			continue
		}
		hi := lo
		if p.EndPort != nil {
			hi = *p.EndPort
		}
		if query.Port >= lo && query.Port <= hi {
			return Allowed, fmt.Sprintf("matched port %d/%s", query.Port, proto)
		}
	}
	if sawUnknown {
		return Unknown, "rule includes a named (string) container port this model cannot resolve"
	}
	return Denied, "no port entry in this rule matched"
}
