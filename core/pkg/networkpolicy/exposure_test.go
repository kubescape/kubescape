package networkpolicy

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ingressRule(from ...networkingv1.NetworkPolicyPeer) networkingv1.NetworkPolicyIngressRule {
	return networkingv1.NetworkPolicyIngressRule{From: from}
}

func podSelectorPeer(kv ...string) networkingv1.NetworkPolicyPeer {
	s := selector(kv...)
	return networkingv1.NetworkPolicyPeer{PodSelector: &s}
}

func namespaceSelectorPeer(kv ...string) networkingv1.NetworkPolicyPeer {
	s := selector(kv...)
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &s}
}

func emptyNamespaceSelectorPeer() networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}}
}

func ipBlockPeer(cidr string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}}
}

func TestIngressExposure_NoPolicySelectsPodIsOpen(t *testing.T) {
	idx, _ := NewIndex(nil, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureOpen {
		t.Errorf("Level = %v, want ExposureOpen", exposure.Level)
	}
}

func TestIngressExposure_EmptyFromListIsOpen(t *testing.T) {
	p := policy("ns", "allow-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule()}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureOpen {
		t.Errorf("Level = %v, want ExposureOpen", exposure.Level)
	}
}

func TestIngressExposure_IPBlockPeerIsExternalCIDR(t *testing.T) {
	p := policy("ns", "allow-cidr", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(ipBlockPeer("0.0.0.0/0"))}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureExternalCIDR {
		t.Errorf("Level = %v, want ExposureExternalCIDR", exposure.Level)
	}
	if exposure.MatchedPolicy != "ns/allow-cidr" {
		t.Errorf("MatchedPolicy = %q, want ns/allow-cidr", exposure.MatchedPolicy)
	}
}

func TestIngressExposure_EmptyNamespaceSelectorIsAnyNamespace(t *testing.T) {
	p := policy("ns", "allow-any-ns", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(emptyNamespaceSelectorPeer())}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureAnyNamespace {
		t.Errorf("Level = %v, want ExposureAnyNamespace", exposure.Level)
	}
}

func TestIngressExposure_PodSelectorOnlyIsRestricted(t *testing.T) {
	p := policy("ns", "allow-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(podSelectorPeer("app", "client"))}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureRestricted {
		t.Errorf("Level = %v, want ExposureRestricted (podSelector alone never crosses namespaces)", exposure.Level)
	}
}

func TestIngressExposure_NonEmptyNamespaceSelectorIsRestricted(t *testing.T) {
	p := policy("ns", "allow-labeled-ns", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(namespaceSelectorPeer("team", "payments"))}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureRestricted {
		t.Errorf("Level = %v, want ExposureRestricted", exposure.Level)
	}
}

// TestIngressExposure_RestrictedResultStillNamesMatchedPolicy is the direct
// regression test for the bug this fixes: ExposureRestricted is also
// ExposureLevel's zero value, so a naive "level > best.Level" comparison
// starting from a zero-valued best never fires for the common case (a
// well-scoped policy), leaving MatchedPolicy empty even though a specific
// policy caused the classification.
func TestIngressExposure_RestrictedResultStillNamesMatchedPolicy(t *testing.T) {
	p := policy("ns", "allow-client", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(podSelectorPeer("app", "client"))}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", exposure.Level)
	}
	if exposure.MatchedPolicy != "ns/allow-client" {
		t.Errorf("MatchedPolicy = %q, want \"ns/allow-client\": the responsible policy must be named even when the result is Restricted", exposure.MatchedPolicy)
	}
}

// TestIngressExposure_PolicyWithNoIngressRulesStillNamesMatchedPolicy covers
// the related edge case the same bug produced: a policy that isolates the
// endpoint (Ingress is in policyTypes) but declares zero ingress rules at
// all never enters the rule loop, so it needs its own explicit attribution.
func TestIngressExposure_PolicyWithNoIngressRulesStillNamesMatchedPolicy(t *testing.T) {
	p := policy("ns", "deny-all-no-rules", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureRestricted {
		t.Fatalf("Level = %v, want ExposureRestricted", exposure.Level)
	}
	if exposure.MatchedPolicy != "ns/deny-all-no-rules" {
		t.Errorf("MatchedPolicy = %q, want \"ns/deny-all-no-rules\"", exposure.MatchedPolicy)
	}
}

func TestIngressExposure_WidestAcrossMultipleRulesWins(t *testing.T) {
	p := policy("ns", "mixed", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			ingressRule(podSelectorPeer("app", "client")),
			ingressRule(ipBlockPeer("10.0.0.0/8")),
		}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureExternalCIDR {
		t.Errorf("Level = %v, want ExposureExternalCIDR (the wider of the two rules)", exposure.Level)
	}
}

func TestIngressExposure_WidestAcrossMultiplePoliciesWins(t *testing.T) {
	restrictive := policy("ns", "restrictive", selector("app", "web"), []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(podSelectorPeer("app", "client"))}, nil)
	open := policy("ns", "open", selector("app", "web"), []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule()}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{restrictive, open}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureOpen {
		t.Errorf("Level = %v, want ExposureOpen: multiple policies selecting the same pod combine via OR, so the more permissive one wins", exposure.Level)
	}
}

func TestIngressExposure_PolicyInAnotherNamespaceDoesNotApply(t *testing.T) {
	p := policy("other-ns", "open", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule()}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	ep := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	exposure := idx.IngressExposure(ep)

	if exposure.Level != ExposureOpen {
		t.Errorf("Level = %v, want ExposureOpen: no policy in ep's own namespace isolates it, so it is not isolated at all (default allow), regardless of what a policy in a different namespace says", exposure.Level)
	}
}

func TestExposureLevel_String(t *testing.T) {
	cases := map[ExposureLevel]string{
		ExposureRestricted:   "restricted",
		ExposureAnyNamespace: "any-namespace",
		ExposureExternalCIDR: "external-cidr",
		ExposureOpen:         "open",
	}
	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", int(level), got, want)
		}
	}
}
