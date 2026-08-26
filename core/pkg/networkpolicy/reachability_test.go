package networkpolicy

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestReaches_NoPoliciesAtAll_AllowsEverything(t *testing.T) {
	idx := NewIndex(nil, nil)
	src := Endpoint{Namespace: "ns", Name: "client"}
	dst := Endpoint{Namespace: "ns", Name: "server"}

	v, egress, ingress := idx.Reaches(src, dst, portSpec(80))
	if v != Allowed {
		t.Errorf("verdict = %v, want Allowed", v)
	}
	if egress.Verdict != Allowed || ingress.Verdict != Allowed {
		t.Errorf("expected both sides allowed by default, got egress=%v ingress=%v", egress.Verdict, ingress.Verdict)
	}
}

func TestReaches_DefaultDenyIngress_BlocksEverySource(t *testing.T) {
	denyAll := policy("ns", "deny-all-ingress", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{denyAll}, nil)

	src := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	v, _, ingress := idx.Reaches(src, dst, portSpec(80))
	if v != Denied {
		t.Errorf("verdict = %v, want Denied", v)
	}
	if ingress.Verdict != Denied {
		t.Errorf("ingress decision = %v, want Denied", ingress.Verdict)
	}
}

func TestReaches_IngressRuleAllowsSpecificPodSelector(t *testing.T) {
	allowFromClient := policy("ns", "allow-client", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{
				From: []networkingv1.NetworkPolicyPeer{
					{PodSelector: podSelectorPtr(selector("app", "client"))},
				},
			},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allowFromClient}, nil)

	allowedClient := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	otherClient := Endpoint{Namespace: "ns", Name: "other", Labels: map[string]string{"app": "other"}}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(allowedClient, dst, nil); v != Allowed {
		t.Errorf("allowed client: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(otherClient, dst, nil); v != Denied {
		t.Errorf("other client: verdict = %v, want Denied", v)
	}
}

func TestReaches_PodSelectorPeerIsSameNamespaceOnly(t *testing.T) {
	allow := policy("ns", "allow-same-ns", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "client"))}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)

	sameNsClient := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	otherNsClient := Endpoint{Namespace: "other-ns", Name: "client", Labels: map[string]string{"app": "client"}}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(sameNsClient, dst, nil); v != Allowed {
		t.Errorf("same-namespace client: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(otherNsClient, dst, nil); v != Denied {
		t.Errorf("a podSelector-only peer must not match a pod in a different namespace: verdict = %v, want Denied", v)
	}
}

func TestReaches_NamespaceSelectorPeerAllowsAnyNamespaceMatchingLabels(t *testing.T) {
	allow := policy("ns", "allow-from-prod-ns", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: namespaceSelectorPtr(selector("env", "prod"))}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, []NamespaceInfo{
		{Name: "prod-ns", Labels: map[string]string{"env": "prod"}},
		{Name: "dev-ns", Labels: map[string]string{"env": "dev"}},
	})

	prodPod := Endpoint{Namespace: "prod-ns", Name: "any-pod"} // no pod label constraint
	devPod := Endpoint{Namespace: "dev-ns", Name: "any-pod"}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(prodPod, dst, nil); v != Allowed {
		t.Errorf("pod in a matching namespace: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(devPod, dst, nil); v != Denied {
		t.Errorf("pod in a non-matching namespace: verdict = %v, want Denied", v)
	}
}

func TestReaches_CombinedNamespaceAndPodSelectorIsAND(t *testing.T) {
	allow := policy("ns", "allow-prod-client", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{
				NamespaceSelector: namespaceSelectorPtr(selector("env", "prod")),
				PodSelector:       podSelectorPtr(selector("app", "client")),
			}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, []NamespaceInfo{
		{Name: "prod-ns", Labels: map[string]string{"env": "prod"}},
	})

	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}
	rightNsRightLabel := Endpoint{Namespace: "prod-ns", Name: "c1", Labels: map[string]string{"app": "client"}}
	rightNsWrongLabel := Endpoint{Namespace: "prod-ns", Name: "c2", Labels: map[string]string{"app": "not-client"}}

	if v, _, _ := idx.Reaches(rightNsRightLabel, dst, nil); v != Allowed {
		t.Errorf("namespace matches and pod label matches: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(rightNsWrongLabel, dst, nil); v != Denied {
		t.Errorf("namespace matches but pod label does not: verdict = %v, want Denied (AND, not OR)", v)
	}
}

func TestReaches_MultiplePeerEntriesAreOR(t *testing.T) {
	allow := policy("ns", "allow-a-or-b", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{
				{PodSelector: podSelectorPtr(selector("app", "a"))},
				{PodSelector: podSelectorPtr(selector("app", "b"))},
			}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	for _, label := range []string{"a", "b"} {
		src := Endpoint{Namespace: "ns", Name: label, Labels: map[string]string{"app": label}}
		if v, _, _ := idx.Reaches(src, dst, nil); v != Allowed {
			t.Errorf("app=%s: verdict = %v, want Allowed", label, v)
		}
	}
	other := Endpoint{Namespace: "ns", Name: "c", Labels: map[string]string{"app": "c"}}
	if v, _, _ := idx.Reaches(other, dst, nil); v != Denied {
		t.Errorf("app=c matches neither peer entry: verdict = %v, want Denied", v)
	}
}

func TestReaches_MultiplePoliciesOnSamePodAreOR(t *testing.T) {
	fromA := policy("ns", "allow-a", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "a"))}}}}, nil)
	fromB := policy("ns", "allow-b", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "b"))}}}}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{fromA, fromB}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	srcA := Endpoint{Namespace: "ns", Name: "a", Labels: map[string]string{"app": "a"}}
	srcB := Endpoint{Namespace: "ns", Name: "b", Labels: map[string]string{"app": "b"}}
	srcC := Endpoint{Namespace: "ns", Name: "c", Labels: map[string]string{"app": "c"}}

	if v, _, _ := idx.Reaches(srcA, dst, nil); v != Allowed {
		t.Errorf("policy A allows app=a: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(srcB, dst, nil); v != Allowed {
		t.Errorf("policy B allows app=b: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(srcC, dst, nil); v != Denied {
		t.Errorf("neither policy allows app=c: verdict = %v, want Denied", v)
	}
}

func TestReaches_EgressOnlyPolicyDoesNotIsolateIngress(t *testing.T) {
	egressOnly := policy("ns", "egress-only", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil,
		[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "external"))}}}})
	idx := NewIndex([]*networkingv1.NetworkPolicy{egressOnly}, nil)

	src := Endpoint{Namespace: "ns", Name: "anyone", Labels: map[string]string{"app": "anyone"}}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	// dst has a policy selecting it, but that policy is egress-only, so dst
	// must not be ingress-isolated by it.
	if idx.IsIsolated(dst, Ingress) {
		t.Error("an egress-only policy must not isolate its selected pod for ingress")
	}
	if v, _, ingress := idx.Reaches(src, dst, nil); v != Allowed || ingress.Verdict != Allowed {
		t.Errorf("ingress must default-allow: verdict = %v, ingress = %v", v, ingress.Verdict)
	}
}

func TestReaches_RequiresBothEgressAndIngressToAllow(t *testing.T) {
	// src is egress-isolated and only allowed to reach "allowed-dst"; dst is
	// ingress-isolated and only allows "allowed-src". Neither name matches
	// the other's policy, so despite each having *a* permissive-looking rule,
	// the pairing must be denied on each side independently.
	srcEgress := policy("ns", "src-egress", selector("app", "client"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil,
		[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "allowed-dst"))}}}})
	dstIngress := policy("ns", "dst-ingress", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "allowed-src"))}}}},
		nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{srcEgress, dstIngress}, nil)

	client := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	server := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	v, egress, ingress := idx.Reaches(client, server, nil)
	if v != Denied {
		t.Errorf("verdict = %v, want Denied (client's egress rule names a different destination than 'server')", v)
	}
	if egress.Verdict != Denied {
		t.Errorf("egress decision = %v, want Denied", egress.Verdict)
	}
	if ingress.Verdict != Denied {
		t.Errorf("ingress decision = %v, want Denied", ingress.Verdict)
	}

	// Now retarget so both sides actually agree on each other -- this must
	// allow, proving the AND is not accidentally always-false.
	srcEgress2 := policy("ns", "src-egress", selector("app", "client"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		nil,
		[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "server"))}}}})
	dstIngress2 := policy("ns", "dst-ingress", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "client"))}}}},
		nil)
	idx2 := NewIndex([]*networkingv1.NetworkPolicy{srcEgress2, dstIngress2}, nil)
	v2, _, _ := idx2.Reaches(client, server, nil)
	if v2 != Allowed {
		t.Errorf("verdict = %v, want Allowed once both sides agree", v2)
	}
}

func TestReaches_PortMatching(t *testing.T) {
	allow := policy("ns", "allow-port-80", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{Ports: tcpPort(80)}}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	src := Endpoint{Namespace: "ns", Name: "client"}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(src, dst, portSpec(80)); v != Allowed {
		t.Errorf("port 80: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(src, dst, portSpec(443)); v != Denied {
		t.Errorf("port 443: verdict = %v, want Denied", v)
	}
}

func TestReaches_PortRangeWithEndPort(t *testing.T) {
	lo := int32(8000)
	hi := int32(8080)
	port := intstr.FromInt32(lo)
	allow := policy("ns", "allow-range", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{Ports: []networkingv1.NetworkPolicyPort{{Port: &port, EndPort: &hi}}}}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	src := Endpoint{Namespace: "ns", Name: "client"}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(src, dst, portSpec(8050)); v != Allowed {
		t.Errorf("port inside range: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(src, dst, portSpec(9000)); v != Denied {
		t.Errorf("port outside range: verdict = %v, want Denied", v)
	}
}

func TestReaches_NamedPortIsUnknown(t *testing.T) {
	allow := policy("ns", "allow-named-port", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{Ports: namedPort("https")}}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	src := Endpoint{Namespace: "ns", Name: "client"}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	v, _, ingress := idx.Reaches(src, dst, portSpec(443))
	if v != Unknown {
		t.Errorf("verdict = %v, want Unknown (a named port cannot be resolved without container spec)", v)
	}
	if ingress.Verdict != Unknown {
		t.Errorf("ingress decision = %v, want Unknown", ingress.Verdict)
	}
}

func TestReaches_IPBlockWithExcept(t *testing.T) {
	allow := policy("ns", "allow-cidr", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
				CIDR:   "10.0.0.0/24",
				Except: []string{"10.0.0.128/25"},
			}}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	inRange := Endpoint{Namespace: "ns", Name: "client", IP: "10.0.0.50"}
	inExcept := Endpoint{Namespace: "ns", Name: "client", IP: "10.0.0.200"}
	outOfRange := Endpoint{Namespace: "ns", Name: "client", IP: "10.0.1.50"}

	if v, _, _ := idx.Reaches(inRange, dst, nil); v != Allowed {
		t.Errorf("IP in CIDR, not in except: verdict = %v, want Allowed", v)
	}
	if v, _, _ := idx.Reaches(inExcept, dst, nil); v != Denied {
		t.Errorf("IP in the except range: verdict = %v, want Denied", v)
	}
	if v, _, _ := idx.Reaches(outOfRange, dst, nil); v != Denied {
		t.Errorf("IP outside the CIDR: verdict = %v, want Denied", v)
	}
}

func TestReaches_IPBlockWithoutKnownIPIsUnknown(t *testing.T) {
	allow := policy("ns", "allow-cidr", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/24"}}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}
	src := Endpoint{Namespace: "ns", Name: "client"} // no IP set

	v, _, ingress := idx.Reaches(src, dst, nil)
	if v != Unknown {
		t.Errorf("verdict = %v, want Unknown (ipBlock peer with no known source IP)", v)
	}
	if ingress.Verdict != Unknown {
		t.Errorf("ingress decision = %v, want Unknown", ingress.Verdict)
	}
}

func TestReaches_NamespaceSelectorWithUncollectedNamespaceIsUnknown(t *testing.T) {
	allow := policy("ns", "allow-from-labelled-ns", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: namespaceSelectorPtr(selector("env", "prod"))}}},
		}, nil)
	// Deliberately no NamespaceInfo at all: the scan never collected the
	// Namespace object for "unknown-ns".
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}
	src := Endpoint{Namespace: "unknown-ns", Name: "client"}

	v, _, ingress := idx.Reaches(src, dst, nil)
	if v != Unknown {
		t.Errorf("verdict = %v, want Unknown (can't evaluate namespaceSelector without that namespace's labels)", v)
	}
	if ingress.Verdict != Unknown {
		t.Errorf("ingress decision = %v, want Unknown", ingress.Verdict)
	}
}

func TestReaches_EmptyNamespaceSelectorMatchesEverythingEvenIfUncollected(t *testing.T) {
	allow := policy("ns", "allow-from-any-ns", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil) // no namespaces collected at all
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}
	src := Endpoint{Namespace: "any-uncollected-ns", Name: "client"}

	v, _, _ := idx.Reaches(src, dst, nil)
	if v != Allowed {
		t.Errorf("verdict = %v, want Allowed: an empty namespaceSelector matches every namespace regardless of label data", v)
	}
}

func TestReaches_EmptyFromListMatchesNoOne(t *testing.T) {
	// A rule with an explicit, empty from list ([]NetworkPolicyPeer{}) is a
	// different Go value than a nil slice, but Kubernetes treats both the
	// same: len(from) == 0 means "matches all sources." Confirm this
	// package does too, rather than accidentally treating empty-but-non-nil
	// as "matches nobody."
	allow := policy("ns", "allow-empty-from", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{}}}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	src := Endpoint{Namespace: "ns", Name: "anyone"}
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	if v, _, _ := idx.Reaches(src, dst, nil); v != Allowed {
		t.Errorf("verdict = %v, want Allowed: an empty (non-nil) from list still matches all sources", v)
	}
}

func TestReaches_MultipleRulesOnOnePolicyAreOR(t *testing.T) {
	allow := policy("ns", "two-rules", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{
			{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "a"))}}},
			{From: []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "b"))}}},
		}, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{allow}, nil)
	dst := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	a := Endpoint{Namespace: "ns", Name: "a", Labels: map[string]string{"app": "a"}}
	b := Endpoint{Namespace: "ns", Name: "b", Labels: map[string]string{"app": "b"}}

	if v, _, _ := idx.Reaches(a, dst, nil); v != Allowed {
		t.Errorf("rule 1 should allow app=a: verdict = %v", v)
	}
	if v, _, _ := idx.Reaches(b, dst, nil); v != Allowed {
		t.Errorf("rule 2 should allow app=b: verdict = %v", v)
	}
}

func podSelectorPtr(s metav1.LabelSelector) *metav1.LabelSelector       { return &s }
func namespaceSelectorPtr(s metav1.LabelSelector) *metav1.LabelSelector { return &s }
