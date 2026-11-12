package networkpolicy

import (
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// ExposureLevel classifies how broadly an endpoint is reachable on ingress,
// from most to least exposed. Unlike Verdict (which answers "can THIS
// specific source reach THIS destination"), ExposureLevel answers "what is
// the widest reasonable source class that some NetworkPolicy rule already
// admits" -- a structural property of the rule's own shape (an empty
// selector, an ipBlock, a missing From list), not a per-candidate match
// test. That is what makes it always fully determinable: no case here needs
// a specific candidate's IP or a namespace's actual labels the way Reaches
// does, only the policy objects themselves.
type ExposureLevel int

const (
	// ExposureRestricted means every ingress rule that selects this endpoint
	// scopes its peers: a podSelector (always same-namespace-only, per
	// NetworkPolicy's own semantics) or a namespaceSelector that only matches
	// namespaces carrying a label someone had to add on purpose, or ones it
	// names explicitly.
	ExposureRestricted ExposureLevel = iota
	// ExposureAnyNamespace means some ingress rule's namespaceSelector matches
	// a namespace that has no labels of its own, only the
	// kubernetes.io/metadata.name label Kubernetes sets on every namespace.
	// That covers an empty selector, which matches every namespace, as well
	// as selectors built only from Exists on the name label, NotIn, or
	// DoesNotExist: any namespace created from now on is admitted, so the
	// endpoint is reachable from pods in namespaces nobody chose to trust.
	ExposureAnyNamespace
	// ExposureExternalCIDR means some ingress rule admits an ipBlock peer:
	// reachable by IP address rather than by pod/namespace identity at all,
	// which typically includes traffic from outside the cluster's own pod
	// network.
	ExposureExternalCIDR
	// ExposureOpen means the endpoint is not ingress-isolated by any
	// NetworkPolicy at all (default allow), or some rule has no From
	// restriction whatsoever -- either way, reachable from literally
	// anywhere. It is also the worst-case classification of an isolated
	// hostNetwork endpoint, whose policies may not be enforced (see
	// Endpoint.HostNetwork): there Open is not a confirmed admission, and
	// Reason says so.
	ExposureOpen
)

func (l ExposureLevel) String() string {
	switch l {
	case ExposureOpen:
		return "open"
	case ExposureExternalCIDR:
		return "external-cidr"
	case ExposureAnyNamespace:
		return "any-namespace"
	default:
		return "restricted"
	}
}

// Exposure is the result of classifying one endpoint's ingress exposure.
type Exposure struct {
	Level ExposureLevel
	// Reason explains what produced Level: which rule shape was found, or
	// that no policy isolates the endpoint at all.
	Reason string
	// MatchedPolicy names the NetworkPolicy (namespace/name) responsible for
	// Level, when a specific policy is what determined it. Empty when Level
	// is ExposureOpen because nothing isolates the endpoint at all -- there
	// is no specific policy to blame for that.
	MatchedPolicy string
}

// IngressExposure classifies the widest ingress source class any
// NetworkPolicy rule already admits for ep. It is a coarser question than
// Reaches: not "can pod X reach this," but "what is the broadest class of
// pod this endpoint is already open to, per its own NetworkPolicy rules."
// This is the signal a vulnerability-prioritization consumer wants: a
// critical CVE on a pod that is ExposureOpen or ExposureExternalCIDR is a
// materially different risk than the same CVE on an ExposureRestricted pod.
// If idx is nil, the endpoint is not isolated and ExposureOpen is returned.
func (idx *Index) IngressExposure(ep Endpoint) Exposure {
	if idx == nil || !idx.IsIsolated(ep, Ingress) {
		return Exposure{Level: ExposureOpen, Reason: "no NetworkPolicy selects this endpoint for ingress; default allow"}
	}
	if ep.HostNetwork {
		// The policies that select a hostNetwork pod cannot be counted on
		// to restrict it (see Endpoint.HostNetwork), and it listens on its
		// node's own addresses, so it is classified by the worst case.
		return Exposure{Level: ExposureOpen, Reason: "worst case, not a confirmed policy admission: endpoint uses the host network (hostNetwork: true), where NetworkPolicy behaviour is undefined and most network plugins do not enforce the policies that select it"}
	}

	// haveBest tracks whether best has ever been assigned from a real
	// matching policy, since ExposureRestricted is also ExposureLevel's zero
	// value: a plain "level > best.Level" comparison starting from a
	// zero-valued best would never fire for the common case where the
	// widest level found really is Restricted, leaving MatchedPolicy empty
	// even though a specific policy is responsible for it.
	var best Exposure
	haveBest := false
	for _, cp := range idx.byNamespace[ep.Namespace] {
		if !cp.hasIngress || !cp.podSelector.Matches(labels.Set(ep.Labels)) {
			continue
		}
		policyName := fmt.Sprintf("%s/%s", cp.policy.Namespace, cp.policy.Name)

		if len(cp.policy.Spec.Ingress) == 0 {
			// hasIngress is true (Ingress is in this policy's policyTypes)
			// but it declares no ingress rules at all: it isolates the
			// endpoint and admits nothing. Still a real, attributable
			// policy -- record it unless a wider level already applies.
			if !haveBest {
				best = Exposure{Level: ExposureRestricted, Reason: "isolated by a policy with no ingress rules; admits nothing", MatchedPolicy: policyName}
				haveBest = true
			}
			continue
		}

		for _, rule := range cp.policy.Spec.Ingress {
			level, reason := classifyPeers(rule.From)
			if !haveBest || level > best.Level {
				best = Exposure{Level: level, Reason: reason, MatchedPolicy: policyName}
				haveBest = true
				if best.Level == ExposureOpen {
					return best
				}
			}
		}
	}
	return best
}

// classifyPeers reports the widest exposure level a single ingress rule's
// From list admits. An empty/nil From list matches every peer, the same
// "absent means unrestricted" semantics portVerdict/peerListVerdict already
// apply elsewhere in this package.
func classifyPeers(peers []networkingv1.NetworkPolicyPeer) (ExposureLevel, string) {
	if len(peers) == 0 {
		return ExposureOpen, "rule has no source restriction; matches every peer"
	}

	best := ExposureRestricted
	reason := "matches only specific, scoped peers"
	for i, peer := range peers {
		level, r := classifyPeer(peer)
		if level > best {
			best, reason = level, r
		} else if i == 0 && len(peers) == 1 {
			// A lone peer's own explanation (e.g. a fully excluded
			// ipBlock) is more specific than the generic default.
			reason = r
		}
	}
	return best, reason
}

// classifyPeer reports the exposure level a single networkingv1.NetworkPolicyPeer
// contributes. A podSelector alone is always ExposureRestricted regardless
// of how permissive its own label match is: per NetworkPolicy's own
// semantics (see match.go's peerMatches), a podSelector with no
// namespaceSelector only ever reaches pods in the policy's own namespace.
func classifyPeer(peer networkingv1.NetworkPolicyPeer) (ExposureLevel, string) {
	if peer.IPBlock != nil {
		if ipBlockFullyExcluded(peer.IPBlock) {
			return ExposureRestricted, fmt.Sprintf("ipBlock %s admits no addresses: its except entries cover the whole CIDR", peer.IPBlock.CIDR)
		}
		return ExposureExternalCIDR, fmt.Sprintf("ipBlock %s admits peers by IP, not pod/namespace identity", peer.IPBlock.CIDR)
	}
	if peer.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		switch {
		case err != nil:
			return ExposureRestricted, "namespaceSelector scopes peers to specific namespaces"
		case sel.Empty():
			return ExposureAnyNamespace, "namespaceSelector is empty, matching every namespace"
		case admitsUnlabeledNamespace(sel):
			return ExposureAnyNamespace, fmt.Sprintf("namespaceSelector %q matches a namespace with no labels of its own, so it admits any newly created namespace", sel.String())
		}
		return ExposureRestricted, "namespaceSelector scopes peers to specific namespaces"
	}
	return ExposureRestricted, "podSelector only ever matches pods in this endpoint's own namespace"
}

// admitsUnlabeledNamespace reports whether sel matches a namespace whose only
// label is kubernetes.io/metadata.name, which the API server sets on every
// namespace to its name, under a name sel does not list. Anyone who can create
// a namespace gets one like that without asking, so such a selector does not
// limit peers to namespaces an administrator labeled: Exists on the name
// label, NotIn and DoesNotExist all match it. A selector needs In or Exists on
// some other label, or In on the name label, to rule it out.
func admitsUnlabeledNamespace(sel labels.Selector) bool {
	requirements, selectable := sel.Requirements()
	if !selectable {
		return false
	}
	name := unlistedNamespaceName(requirements)
	return sel.Matches(labels.Set{corev1.LabelMetadataName: name})
}

// unlistedNamespaceName returns a valid namespace name that none of
// requirements mentions as a value of the name label, so evaluating them
// against it stands in for a namespace nobody has created yet.
func unlistedNamespaceName(requirements labels.Requirements) string {
	listed := map[string]bool{}
	for _, r := range requirements {
		if r.Key() != corev1.LabelMetadataName {
			continue
		}
		for value := range r.Values() {
			listed[value] = true
		}
	}
	name := "new-namespace"
	for i := 1; listed[name]; i++ {
		name = fmt.Sprintf("new-namespace-%d", i)
	}
	return name
}

// ipBlockFullyExcluded reports whether block.Except collectively covers all of
// block.CIDR, so the block admits no address. Unparseable entries are ignored,
// as ipBlockMatches does, so a malformed block is never treated as excluded.
func ipBlockFullyExcluded(block *networkingv1.IPBlock) bool {
	cidr, err := netip.ParsePrefix(block.CIDR)
	if err != nil {
		return false
	}
	var excepts []netip.Prefix
	for _, e := range block.Except {
		p, err := netip.ParsePrefix(e)
		if err != nil || p.Addr().Is4() != cidr.Addr().Is4() {
			continue
		}
		excepts = append(excepts, p.Masked())
	}
	return prefixCovered(cidr.Masked(), excepts)
}

// prefixCovered reports whether the union of excepts contains every address of p.
func prefixCovered(p netip.Prefix, excepts []netip.Prefix) bool {
	var inside []netip.Prefix
	for _, e := range excepts {
		if e.Bits() <= p.Bits() && e.Contains(p.Addr()) {
			return true
		}
		if e.Bits() > p.Bits() && p.Contains(e.Addr()) {
			inside = append(inside, e)
		}
	}
	if len(inside) == 0 || p.Bits() >= p.Addr().BitLen() {
		return false
	}
	// Split p into its two halves; both must be fully covered.
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	hi := p.Addr().As16()
	idx := bits - 1
	if p.Addr().Is4() {
		idx += 96
	}
	hi[idx/8] |= 0x80 >> (idx % 8)
	hiAddr := netip.AddrFrom16(hi)
	if p.Addr().Is4() {
		hiAddr = hiAddr.Unmap()
	}
	return prefixCovered(lo, inside) && prefixCovered(netip.PrefixFrom(hiAddr, bits), inside)
}
