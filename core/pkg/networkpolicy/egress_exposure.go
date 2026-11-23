package networkpolicy

import (
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
)

// EgressExposure classifies the broadest destination class admitted by the
// egress NetworkPolicies that select ep. It is the outbound counterpart to
// IngressExposure: rather than asking whether one specific connection is
// possible, it summarizes the widest destination class allowed by the
// policies' own rule shapes.
//
// NetworkPolicies are additive, so the broadest matching rule across every
// policy selecting ep determines the result. A nil Index, or an endpoint
// that no egress policy isolates, is default-allow and therefore ExposureOpen.
func (idx *Index) EgressExposure(ep Endpoint) Exposure {
	if idx == nil || !idx.IsIsolated(ep, Egress) {
		return Exposure{
			Level:  ExposureOpen,
			Reason: "no NetworkPolicy selects this endpoint for egress; default allow",
		}
	}
	if ep.HostNetwork {
		// NetworkPolicy enforcement for hostNetwork pods is undefined, and
		// most plugins do not enforce policies for them. Report the
		// conservative worst case, as IngressExposure does.
		return Exposure{
			Level:  ExposureOpen,
			Reason: "worst case, not a confirmed policy admission: endpoint uses the host network (hostNetwork: true), where NetworkPolicy behaviour is undefined and most network plugins do not enforce the policies that select it",
		}
	}

	var best Exposure
	haveBest := false
	for _, cp := range idx.byNamespace[ep.Namespace] {
		if !cp.hasEgress || !cp.podSelector.Matches(labels.Set(ep.Labels)) {
			continue
		}
		policyName := fmt.Sprintf("%s/%s", cp.policy.Namespace, cp.policy.Name)

		if len(cp.policy.Spec.Egress) == 0 {
			// An egress-isolating policy with no egress rules denies every
			// destination. It still needs attribution even though there is
			// no rule to classify.
			if !haveBest {
				best = Exposure{
					Level:         ExposureRestricted,
					Reason:        "isolated by a policy with no egress rules; admits no destinations",
					MatchedPolicy: policyName,
				}
				haveBest = true
			}
			continue
		}

		for _, rule := range cp.policy.Spec.Egress {
			level, reason := classifyPeers(rule.To)
			if !haveBest || level > best.Level {
				best = Exposure{
					Level:         level,
					Reason:        reason,
					MatchedPolicy: policyName,
				}
				haveBest = true
				if best.Level == ExposureOpen {
					return best
				}
			}
		}
	}

	// IsIsolated above guarantees at least one matching egress policy, so
	// either a policy with no rules or a rule has assigned best.
	if !haveBest {
		return Exposure{
			Level:  ExposureRestricted,
			Reason: "endpoint is egress-isolated and no matching rule admits a destination",
		}
	}
	return best
}
