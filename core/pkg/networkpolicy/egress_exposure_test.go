package networkpolicy

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func egressRule(to ...networkingv1.NetworkPolicyPeer) networkingv1.NetworkPolicyEgressRule {
	return networkingv1.NetworkPolicyEgressRule{To: to}
}

func TestEgressExposure_NoPolicySelectsPodIsOpen(t *testing.T) {
	idx, _ := NewIndex(nil, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	got := idx.EgressExposure(ep)
	if got.Level != ExposureOpen {
		t.Fatalf("Level = %v, want ExposureOpen", got.Level)
	}
}

func TestEgressExposure_NilIndexIsOpen(t *testing.T) {
	var idx *Index
	got := idx.EgressExposure(Endpoint{Namespace: "ns"})
	if got.Level != ExposureOpen {
		t.Fatalf("Level = %v, want ExposureOpen", got.Level)
	}
}

func TestEgressExposure_PolicyWithNoEgressRulesIsRestrictedAndAttributed(t *testing.T) {
	p := policy("ns", "deny-all-egress", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", got.Level)
	}
	if got.MatchedPolicy != "ns/deny-all-egress" {
		t.Fatalf("MatchedPolicy = %q, want ns/deny-all-egress", got.MatchedPolicy)
	}
	if !strings.Contains(got.Reason, "no egress rules") {
		t.Fatalf("Reason = %q, want explanation for empty egress rules", got.Reason)
	}
}

func TestEgressExposure_EmptyToListIsOpen(t *testing.T) {
	p := policy("ns", "allow-all-egress", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule()})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureOpen {
		t.Fatalf("Level = %v, want ExposureOpen", got.Level)
	}
	if got.MatchedPolicy != "ns/allow-all-egress" {
		t.Fatalf("MatchedPolicy = %q, want ns/allow-all-egress", got.MatchedPolicy)
	}
}

func TestEgressExposure_IPBlockIsExternalCIDR(t *testing.T) {
	p := policy("ns", "allow-internet", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(ipBlockPeer("0.0.0.0/0"))})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureExternalCIDR {
		t.Fatalf("Level = %v, want ExposureExternalCIDR", got.Level)
	}
	if got.MatchedPolicy != "ns/allow-internet" {
		t.Fatalf("MatchedPolicy = %q, want ns/allow-internet", got.MatchedPolicy)
	}
}

func TestEgressExposure_FullyExcludedIPBlockIsRestricted(t *testing.T) {
	block := networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{
		CIDR:   "10.0.0.0/24",
		Except: []string{"10.0.0.0/25", "10.0.0.128/25"},
	}}
	p := policy("ns", "excluded-range", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(block)})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", got.Level)
	}
	if !strings.Contains(got.Reason, "admits no addresses") {
		t.Fatalf("Reason = %q, want fully-excluded IPBlock explanation", got.Reason)
	}
}

func TestEgressExposure_EmptyNamespaceSelectorIsAnyNamespace(t *testing.T) {
	p := policy("ns", "allow-any-namespace", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(emptyNamespaceSelectorPeer())})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureAnyNamespace {
		t.Fatalf("Level = %v, want ExposureAnyNamespace", got.Level)
	}
}

func TestEgressExposure_PodSelectorOnlyIsRestricted(t *testing.T) {
	p := policy("ns", "allow-local-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(podSelectorPeer("app", "client"))})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", got.Level)
	}
}

func TestEgressExposure_WidestRuleAcrossPoliciesWins(t *testing.T) {
	restricted := policy("ns", "local-only", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(podSelectorPeer("app", "client"))})
	external := policy("ns", "external", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(ipBlockPeer("192.0.2.0/24"))})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{restricted, external}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureExternalCIDR {
		t.Fatalf("Level = %v, want ExposureExternalCIDR: policies are additive", got.Level)
	}
	if got.MatchedPolicy != "ns/external" {
		t.Fatalf("MatchedPolicy = %q, want ns/external", got.MatchedPolicy)
	}
}

func TestEgressExposure_PolicyInAnotherNamespaceDoesNotApply(t *testing.T) {
	p := policy("other-ns", "allow-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule()})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureOpen {
		t.Fatalf("Level = %v, want ExposureOpen: policies in another namespace do not select this endpoint", got.Level)
	}
}

func TestEgressExposure_DefaultPolicyTypesIncludeEgressWhenRulesExist(t *testing.T) {
	p := policy("ns", "defaulted-egress", metav1.LabelSelector{}, nil, nil,
		[]networkingv1.NetworkPolicyEgressRule{egressRule(ipBlockPeer("198.51.100.0/24"))})
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app"})
	if got.Level != ExposureExternalCIDR {
		t.Fatalf("Level = %v, want ExposureExternalCIDR", got.Level)
	}
}

func TestEgressExposure_HostNetworkIsConservativelyOpen(t *testing.T) {
	p := policy("ns", "deny-egress", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	got := idx.EgressExposure(Endpoint{Namespace: "ns", Name: "app", HostNetwork: true})
	if got.Level != ExposureOpen {
		t.Fatalf("Level = %v, want ExposureOpen for conservative hostNetwork handling", got.Level)
	}
	if !strings.Contains(got.Reason, "hostNetwork") {
		t.Fatalf("Reason = %q, want hostNetwork explanation", got.Reason)
	}
}

func TestEgressExposure_ZeroRulePolicyBeforeScopedPolicyDoesNotMaskRule(t *testing.T) {
	denyAll := policy("ns", "00-deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil)
	allowClient := policy("ns", "allow-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(podSelectorPeer("app", "client"))})

	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{denyAll, allowClient}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	got := idx.EgressExposure(ep)
	if got.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", got.Level)
	}
	if got.MatchedPolicy != "ns/allow-client" {
		t.Fatalf("MatchedPolicy = %q, want ns/allow-client: scoped rule must not be masked by zero-rule deny-all policy", got.MatchedPolicy)
	}
	if strings.Contains(got.Reason, "admits no destinations") {
		t.Fatalf("Reason = %q, must not claim 'admits no destinations' when an admitting rule exists", got.Reason)
	}
}

func TestEgressExposure_DeterministicTieBreakBetweenEqualPolicies(t *testing.T) {
	pB := policy("ns", "b-allow-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(podSelectorPeer("app", "client-b"))})
	pA := policy("ns", "a-allow-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil, []networkingv1.NetworkPolicyEgressRule{egressRule(podSelectorPeer("app", "client-a"))})

	idx1, _ := NewIndex([]*networkingv1.NetworkPolicy{pB, pA}, nil)
	idx2, _ := NewIndex([]*networkingv1.NetworkPolicy{pA, pB}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	got1 := idx1.EgressExposure(ep)
	got2 := idx2.EgressExposure(ep)
	if got1.MatchedPolicy != "ns/a-allow-client" || got2.MatchedPolicy != "ns/a-allow-client" {
		t.Fatalf("got1 MatchedPolicy = %q, got2 MatchedPolicy = %q; want ns/a-allow-client for both", got1.MatchedPolicy, got2.MatchedPolicy)
	}
}
