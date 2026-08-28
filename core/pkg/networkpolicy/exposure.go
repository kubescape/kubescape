package networkpolicy

import (
	"fmt"

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
	// NetworkPolicy's own semantics) or a namespaceSelector with actual
	// matchLabels/matchExpressions.
	ExposureRestricted ExposureLevel = iota
	// ExposureAnyNamespace means some ingress rule's namespaceSelector is
	// empty (matches every namespace, present and future), so the endpoint
	// is reachable from any pod in the cluster regardless of which
	// namespace it runs in.
	ExposureAnyNamespace
	// ExposureExternalCIDR means some ingress rule admits an ipBlock peer:
	// reachable by IP address rather than by pod/namespace identity at all,
	// which typically includes traffic from outside the cluster's own pod
	// network.
	ExposureExternalCIDR
	// ExposureOpen means the endpoint is not ingress-isolated by any
	// NetworkPolicy at all (default allow), or some rule has no From
	// restriction whatsoever -- either way, reachable from literally
	// anywhere.
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
func (idx *Index) IngressExposure(ep Endpoint) Exposure {
	if !idx.IsIsolated(ep, Ingress) {
		return Exposure{Level: ExposureOpen, Reason: "no NetworkPolicy selects this endpoint for ingress; default allow"}
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
	for _, peer := range peers {
		level, r := classifyPeer(peer)
		if level > best {
			best, reason = level, r
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
		return ExposureExternalCIDR, fmt.Sprintf("ipBlock %s admits peers by IP, not pod/namespace identity", peer.IPBlock.CIDR)
	}
	if peer.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err == nil && sel.Empty() {
			return ExposureAnyNamespace, "namespaceSelector is empty, matching every namespace"
		}
		return ExposureRestricted, "namespaceSelector scopes peers to specific namespaces"
	}
	return ExposureRestricted, "podSelector only ever matches pods in this endpoint's own namespace"
}
