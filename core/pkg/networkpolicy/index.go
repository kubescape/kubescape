// Package networkpolicy implements a static NetworkPolicy reachability model:
// given the NetworkPolicy, Pod, and Namespace objects a scan already
// collects, it answers "can this specific source reach this specific
// destination, on this port" by evaluating the real, additive Kubernetes
// NetworkPolicy semantics -- not just "does some policy exist."
//
// This is a static model computed from spec, the same trust model the rest
// of kubescape's posture scanning uses. It does not verify that a cluster's
// CNI actually enforces NetworkPolicy (many do not), and it does not resolve
// DNS-based egress destinations -- only ipBlock CIDRs.
package networkpolicy

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Endpoint identifies one pod for reachability purposes: which namespace it
// is in, and the labels a podSelector/namespaceSelector match against.
type Endpoint struct {
	Namespace string
	Name      string
	Labels    map[string]string

	// IP is optional. It is only consulted for ipBlock peer matching, which
	// operates on addresses, not labels -- a live-cluster caller that knows
	// the pod's assigned IP can set it; a caller working purely from scanned
	// manifests (no runtime status) leaves it empty, and any ipBlock peer
	// then reports Unknown rather than a guessed answer.
	IP string
}

// NamespaceInfo carries a namespace's own labels, needed for
// namespaceSelector matching (which reads the *namespace* object's labels,
// not anything on the pod).
type NamespaceInfo struct {
	Name   string
	Labels map[string]string
}

// Direction is which traffic direction a policy rule (and the isolation it
// establishes) applies to.
type Direction int

const (
	Ingress Direction = iota
	Egress
)

func (d Direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// Index indexes a cluster's NetworkPolicy objects (grouped by namespace) and
// namespace label metadata, for repeated reachability queries against the
// same snapshot.
type Index struct {
	byNamespace map[string][]*compiledPolicy
	namespaces  map[string]NamespaceInfo
}

// compiledPolicy pre-parses one NetworkPolicy's selectors once, rather than
// re-parsing label selectors on every query against it.
type compiledPolicy struct {
	policy      *networkingv1.NetworkPolicy
	podSelector labels.Selector
	hasIngress  bool // Ingress is in policyTypes (explicit, or defaulted)
	hasEgress   bool // Egress is in policyTypes (explicit, or defaulted from having egress rules when policyTypes is unset)
}

// NewIndex builds an Index from a cluster's (or a scan's) collected
// NetworkPolicy objects and namespace metadata. A policy with an
// unparseable podSelector is skipped rather than making the whole Index
// fail to build: one malformed object should not blind every query about
// every other namespace. Its error is appended to errs -- mirroring
// FromResources' decodeErrs -- so a caller can surface it (e.g. in a
// decode_warnings field) rather than have it disappear silently; dropping a
// policy this way can turn a real Denied into a false Allowed, so callers of
// a security-sensitive query should treat a non-empty errs as reason to
// distrust an Allowed verdict.
func NewIndex(policies []*networkingv1.NetworkPolicy, namespaces []NamespaceInfo) (idx *Index, errs []error) {
	idx = &Index{
		byNamespace: make(map[string][]*compiledPolicy),
		namespaces:  make(map[string]NamespaceInfo, len(namespaces)),
	}

	for _, ns := range namespaces {
		idx.namespaces[ns.Name] = ns
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
		if err != nil {
			errs = append(errs, fmt.Errorf("NetworkPolicy %s/%s: unparseable podSelector, skipped: %w", p.Namespace, p.Name, err))
			continue
		}

		hasIngress, hasEgress := policyTypesFor(p)

		idx.byNamespace[p.Namespace] = append(idx.byNamespace[p.Namespace], &compiledPolicy{
			policy:      p,
			podSelector: sel,
			hasIngress:  hasIngress,
			hasEgress:   hasEgress,
		})
	}

	return idx, errs
}

// policyTypesFor reproduces the Kubernetes API's own defaulting for
// spec.policyTypes (networking/v1 NetworkPolicySpec doc): Ingress always
// applies unless policyTypes is explicitly set and omits it; Egress applies
// only when policyTypes explicitly includes it, or -- when policyTypes is
// not set at all -- when the policy declares any egress rules. Egress is
// never defaulted "on" the way Ingress is: a policy with an empty
// policyTypes and no egress rules is not egress-isolating.
func policyTypesFor(p *networkingv1.NetworkPolicy) (ingress, egress bool) {
	if len(p.Spec.PolicyTypes) == 0 {
		return true, len(p.Spec.Egress) > 0
	}
	for _, t := range p.Spec.PolicyTypes {
		switch t {
		case networkingv1.PolicyTypeIngress:
			ingress = true
		case networkingv1.PolicyTypeEgress:
			egress = true
		}
	}
	return ingress, egress
}

// matchingPolicies returns every compiled policy in ep's namespace whose
// podSelector selects ep.
func (idx *Index) matchingPolicies(ep Endpoint) []*compiledPolicy {
	var out []*compiledPolicy
	for _, cp := range idx.byNamespace[ep.Namespace] {
		if cp.podSelector.Matches(labels.Set(ep.Labels)) {
			out = append(out, cp)
		}
	}
	return out
}

// IsIsolated reports whether ep is isolated for dir: at least one policy in
// its namespace selects it and declares dir (see policyTypesFor for the
// exact defaulting rules). An endpoint that is not isolated for a direction
// allows all traffic in that direction, regardless of what any policy that
// does not select it says -- NetworkPolicy is opt-in per pod, not
// cluster-wide default-deny.
func (idx *Index) IsIsolated(ep Endpoint, dir Direction) bool {
	for _, cp := range idx.matchingPolicies(ep) {
		if dir == Ingress && cp.hasIngress {
			return true
		}
		if dir == Egress && cp.hasEgress {
			return true
		}
	}
	return false
}

// PortSpec is a protocol+port pair to check reachability for. A nil
// *PortSpec passed to a query means "is there any port at all this
// connection could use," i.e. match a rule regardless of its ports.
type PortSpec struct {
	// Protocol defaults to TCP if empty, matching the Kubernetes API's own
	// default for NetworkPolicyPort.Protocol.
	Protocol corev1.Protocol
	Port     int32
}

func (p *PortSpec) protocol() corev1.Protocol {
	if p == nil || p.Protocol == "" {
		return corev1.ProtocolTCP
	}
	return p.Protocol
}

// Verdict is a reachability answer. It is three-valued rather than a plain
// bool because some inputs genuinely cannot be resolved from a static
// model: a peer selected by IP block when the candidate's IP is unknown, or
// a rule whose port is a named (string) container port this model has no
// container spec to resolve. Collapsing those cases into a guessed
// Allowed/Denied would be worse than saying so.
type Verdict int

const (
	Denied Verdict = iota
	Allowed
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	default:
		return "unknown"
	}
}

// Decision is the outcome of one reachability query, with the specific
// policy responsible so a caller can explain the answer, not just report a
// verdict.
type Decision struct {
	Verdict Verdict
	// Reason is a short, human-readable explanation: which policy/rule
	// allowed the connection, why it was denied, or what could not be
	// resolved.
	Reason string
	// MatchedPolicy names the NetworkPolicy (namespace/name) whose rule
	// produced an Allowed decision. Empty for Denied/Unknown, and empty
	// for an Allowed verdict that holds only because the endpoint is not
	// isolated for this direction at all (no specific policy to name).
	MatchedPolicy string
}

func allow(reason, policy string) Decision {
	return Decision{Verdict: Allowed, Reason: reason, MatchedPolicy: policy}
}

func deny(reason string) Decision {
	return Decision{Verdict: Denied, Reason: reason}
}

func unknown(reason string) Decision {
	return Decision{Verdict: Unknown, Reason: reason}
}
