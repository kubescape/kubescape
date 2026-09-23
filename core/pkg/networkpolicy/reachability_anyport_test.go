package networkpolicy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestReaches_AnyPort(t *testing.T) {
	ports := func(proto corev1.Protocol, lo, hi int32) []networkingv1.NetworkPolicyPort {
		p := intstr.FromInt32(lo)
		return []networkingv1.NetworkPolicyPort{{Protocol: &proto, Port: &p, EndPort: &hi}}
	}
	udp := corev1.ProtocolUDP
	unknownPeer := []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}}}
	wrongPeer := []networkingv1.NetworkPolicyPeer{{PodSelector: podSelectorPtr(selector("app", "other"))}}
	for _, tc := range []struct {
		name       string
		out, in    []networkingv1.NetworkPolicyPort
		peers      []networkingv1.NetworkPolicyPeer
		deny       bool
		want       Verdict
		exhaustive bool
	}{
		{name: "disjoint ports", out: tcpPort(80), in: tcpPort(443), want: Denied, exhaustive: true},
		{name: "disjoint protocols", out: tcpPort(80), in: ports(udp, 80, 80), want: Denied, exhaustive: true},
		{name: "shared TCP default", out: tcpPort(80), in: tcpPort(80), want: Allowed, exhaustive: true},
		{name: "overlapping ranges", out: ports(corev1.ProtocolTCP, 80, 90), in: ports(corev1.ProtocolTCP, 85, 100), want: Allowed, exhaustive: true},
		{name: "inclusive end", out: ports(corev1.ProtocolTCP, 80, 90), in: tcpPort(90), want: Allowed},
		{name: "adjacent ranges", out: ports(corev1.ProtocolTCP, 80, 90), in: ports(corev1.ProtocolTCP, 91, 100), want: Denied},
		{name: "port one", out: tcpPort(1), in: tcpPort(1), want: Allowed},
		{name: "port 65535", out: tcpPort(65535), in: tcpPort(65535), want: Allowed},
		{name: "UDP", out: ports(udp, 53, 53), in: ports(udp, 53, 53), want: Allowed},
		{name: "SCTP", out: ports(corev1.ProtocolSCTP, 80, 80), in: ports(corev1.ProtocolSCTP, 80, 80), want: Allowed},
		{name: "protocol only", out: []networkingv1.NetworkPolicyPort{{Protocol: &udp}}, in: ports(udp, 53, 53), want: Allowed},
		{name: "protocol only disjoint", out: []networkingv1.NetworkPolicyPort{{Protocol: &udp}}, in: tcpPort(53), want: Denied},
		{name: "empty port entry defaults TCP", out: []networkingv1.NetworkPolicyPort{{}}, in: ports(udp, 53, 53), want: Denied},
		{name: "unrestricted egress", in: tcpPort(443), want: Allowed},
		{name: "unrestricted ingress", out: tcpPort(80), want: Allowed},
		{name: "both unrestricted", want: Allowed},
		{name: "default deny", out: tcpPort(80), deny: true, want: Denied},
		{name: "named possible overlap", out: namedPort("http"), in: tcpPort(80), want: Unknown, exhaustive: true},
		{name: "named disjoint protocol", out: namedPort("http"), in: ports(udp, 80, 80), want: Denied},
		{name: "named with denied ingress", out: namedPort("http"), deny: true, want: Denied},
		{name: "known overlap wins", out: append(namedPort("http"), tcpPort(80)...), in: tcpPort(80), want: Allowed},
		{name: "later known overlap wins", out: append(namedPort("http"), tcpPort(80)...), want: Allowed, exhaustive: true},
		{name: "later protocol wins", out: append(namedPort("http"), ports(udp, 53, 53)...), want: Allowed},
		{name: "unresolved peer overlap", out: tcpPort(80), in: tcpPort(80), peers: unknownPeer, want: Unknown},
		{name: "unresolved peer disjoint ports", out: tcpPort(80), in: tcpPort(443), peers: unknownPeer, want: Denied},
		{name: "nonmatching peer", out: tcpPort(80), in: tcpPort(80), peers: wrongPeer, want: Denied},
		{name: "invalid reversed range", out: ports(corev1.ProtocolTCP, 100, 80), in: tcpPort(90), want: Denied},
		{name: "out of range port", out: tcpPort(65536), want: Denied},
		{name: "range crossing lower bound", out: ports(corev1.ProtocolTCP, -1, 80), in: tcpPort(1), want: Allowed},
		{name: "range crossing upper bound", out: ports(corev1.ProtocolTCP, 65535, 2147483647), in: tcpPort(65535), want: Allowed},
		{name: "unknown beyond numeric range", out: tcpPort(100), in: namedPort("http"), want: Unknown, exhaustive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ingress := []networkingv1.NetworkPolicyIngressRule{{Ports: tc.in}}
			if tc.deny {
				ingress = nil
			}
			policies := []*networkingv1.NetworkPolicy{
				policy("ns", "egress", selector("app", "client"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
					[]networkingv1.NetworkPolicyEgressRule{{Ports: tc.out, To: tc.peers}}),
				policy("ns", "ingress", selector("app", "server"), []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, ingress, nil),
			}
			idx, errs := NewIndex(policies, nil)
			if len(errs) != 0 {
				t.Fatal(errs)
			}
			src := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "client"}}
			dst := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "server"}}
			v, egress, in := idx.Reaches(src, dst, nil)
			if v != tc.want {
				t.Errorf("omitted port = %s, want %s", v, tc.want)
			}
			for _, d := range []Decision{egress, in} {
				if v == Denied {
					if !strings.Contains(d.Reason, "no common port/protocol") {
						t.Errorf("denial must explain lack of overlap: %q", d.Reason)
					}
				} else if !strings.Contains(d.Reason, "/TCP") && !strings.Contains(d.Reason, "/UDP") && !strings.Contains(d.Reason, "/SCTP") {
					t.Errorf("missing candidate port/protocol: %q", d.Reason)
				}
			}
			if tc.exhaustive {
				want := Denied
				for _, proto := range []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolUDP, corev1.ProtocolSCTP} {
					for p := int32(1); p <= 65535; p++ {
						explicit, _, _ := idx.Reaches(src, dst, &PortSpec{Port: p, Protocol: proto})
						if explicit == Allowed || (explicit == Unknown && want == Denied) {
							want = explicit
						}
					}
				}
				if v != want {
					t.Errorf("omitted port = %s, exhaustive explicit queries = %s", v, want)
				}
			}
		})
	}
}

func TestReaches_AnyPortNonIsolated(t *testing.T) {
	src := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "client"}}
	dst := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "server"}}
	out := policy("ns", "egress", selector("app", "client"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
		[]networkingv1.NetworkPolicyEgressRule{{Ports: tcpPort(80)}})
	in := policy("ns", "ingress", selector("app", "server"), []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{Ports: tcpPort(443)}}, nil)
	for _, policies := range [][]*networkingv1.NetworkPolicy{nil, {out}, {in}} {
		idx, _ := NewIndex(policies, nil)
		v, egress, ingress := idx.Reaches(src, dst, nil)
		if v != Allowed || egress.Verdict != Allowed || ingress.Verdict != Allowed {
			t.Errorf("non-isolated direction should allow the restricted direction's port: %v %v %v", v, egress, ingress)
		}
	}
}

func TestReaches_AnyPortAdditivePolicies(t *testing.T) {
	src := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "client"}}
	dst := Endpoint{Namespace: "ns", Labels: map[string]string{"app": "server"}}
	for _, separatePolicy := range []bool{false, true} {
		out := policy("ns", "egress", selector("app", "client"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
			[]networkingv1.NetworkPolicyEgressRule{{Ports: tcpPort(80)}})
		in := policy("ns", "ingress", selector("app", "server"), []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			[]networkingv1.NetworkPolicyIngressRule{{Ports: tcpPort(443)}}, nil)
		policies := []*networkingv1.NetworkPolicy{out, in}
		if separatePolicy {
			policies = append(policies, policy("ns", "later-egress", selector("app", "client"), []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
				[]networkingv1.NetworkPolicyEgressRule{{Ports: tcpPort(443)}}))
		} else {
			out.Spec.Egress = append(out.Spec.Egress, networkingv1.NetworkPolicyEgressRule{Ports: tcpPort(443)})
		}
		idx, _ := NewIndex(policies, nil)
		v, egress, ingress := idx.Reaches(src, dst, nil)
		if v != Allowed || !strings.Contains(egress.Reason, "443/TCP") || !strings.Contains(ingress.Reason, "443/TCP") {
			t.Errorf("separatePolicy=%v: expected shared 443/TCP, got %v %v %v", separatePolicy, v, egress, ingress)
		}
		if separatePolicy && egress.MatchedPolicy != "ns/later-egress" {
			t.Errorf("wrong egress policy: %s", egress.MatchedPolicy)
		}
	}
}
