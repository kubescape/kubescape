package networkpolicy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A dual-stack pod has one IPv4 and one IPv6 address (status.podIPs), and a
// connection between two pods uses a single IP family at both ends. These
// tests pin how ipBlock peers, which match addresses, compose with that.

var (
	ingressOnly = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	egressOnly  = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
)

func ipBlockExceptPeer(cidr string, except ...string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr, Except: except}}
}

// serverIngress isolates the server for ingress and admits peers.
func serverIngress(peers ...networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
	return policy("ns", "server-ingress", selector("app", "server"), ingressOnly,
		[]networkingv1.NetworkPolicyIngressRule{{From: peers}}, nil)
}

// clientEgress isolates the client for egress and admits peers.
func clientEgress(peers ...networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
	return policy("ns", "client-egress", selector("app", "client"), egressOnly, nil,
		[]networkingv1.NetworkPolicyEgressRule{{To: peers}})
}

func dualStackPod(name string, ips ...string) Endpoint {
	return Endpoint{Namespace: "ns", Name: name, Labels: map[string]string{"app": name}, IP: ips[0], IPs: ips}
}

func TestReaches_DualStackIPBlock(t *testing.T) {
	// IPv4 is the primary family of these two, as status.podIP reports it.
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")
	// The same pods on a cluster whose primary family is IPv6.
	client6 := dualStackPod("client", "fd00:10:244:1::2", "10.244.1.2")
	server6 := dualStackPod("server", "fd00:10:244:2::2", "10.244.2.2")
	// Single-stack pods.
	clientV4 := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}, IP: "10.244.1.2"}
	serverV4 := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}, IP: "10.244.2.2"}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
		want     Verdict
	}{
		{
			name:     "ingress ipBlock contains the IPv6 address of an IPv4-primary source",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      client, dst: server, want: Allowed,
		},
		{
			name:     "ingress ipBlock contains the IPv4 address of an IPv6-primary source",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"))},
			src:      client6, dst: server6, want: Allowed,
		},
		{
			name:     "egress ipBlock contains the IPv6 address of an IPv4-primary destination",
			policies: []*networkingv1.NetworkPolicy{clientEgress(ipBlockPeer("fd00:10:244::/56"))},
			src:      client, dst: server, want: Allowed,
		},
		{
			name:     "egress ipBlock contains the IPv4 address of an IPv6-primary destination",
			policies: []*networkingv1.NetworkPolicy{clientEgress(ipBlockPeer("0.0.0.0/0"))},
			src:      client6, dst: server6, want: Allowed,
		},
		{
			name:     "except excludes the source's IPv6 address and nothing admits its IPv4 one",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockExceptPeer("fd00:10:244::/56", "fd00:10:244:1::/64"))},
			src:      client, dst: server, want: Denied,
		},
		{
			name:     "except excludes another IPv6 subnet, not the source's",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockExceptPeer("fd00:10:244::/56", "fd00:10:244:9::/64"))},
			src:      client, dst: server, want: Allowed,
		},
		{
			name:     "except excludes the source's IPv4 address on an IPv6-primary cluster",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockExceptPeer("10.244.0.0/16", "10.244.1.0/24"))},
			src:      client6, dst: server6, want: Denied,
		},
		{
			name:     "no ipBlock contains either source address",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("192.168.0.0/16"), ipBlockPeer("2001:db8::/32"))},
			src:      client, dst: server, want: Denied,
		},
		{
			name: "egress admits only IPv4 and ingress admits only IPv6",
			policies: []*networkingv1.NetworkPolicy{
				clientEgress(ipBlockPeer("10.244.0.0/16")),
				serverIngress(ipBlockPeer("fd00:10:244::/56")),
			},
			src: client, dst: server, want: Denied,
		},
		{
			name: "egress admits only IPv6 and ingress admits only IPv4",
			policies: []*networkingv1.NetworkPolicy{
				clientEgress(ipBlockPeer("fd00:10:244::/56")),
				serverIngress(ipBlockPeer("10.244.0.0/16")),
			},
			src: client6, dst: server6, want: Denied,
		},
		{
			name: "egress and ingress both admit IPv6",
			policies: []*networkingv1.NetworkPolicy{
				clientEgress(ipBlockPeer("fd00:10:244::/56")),
				serverIngress(ipBlockPeer("fd00:10:244::/56")),
			},
			src: client, dst: server, want: Allowed,
		},
		{
			// The connection can only use IPv4, so the source's IPv6
			// address never reaches the server.
			name:     "ingress admits the source's IPv6 address but the destination is IPv4-only",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      client, dst: serverV4, want: Denied,
		},
		{
			name:     "ingress admits the IPv4 address of an IPv6-primary source and the destination is IPv4-only",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"))},
			src:      client6, dst: serverV4, want: Allowed,
		},
		{
			name:     "single-stack source in the ipBlock",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"))},
			src:      clientV4, dst: serverV4, want: Allowed,
		},
		{
			name:     "single-stack source outside the ipBlock",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      clientV4, dst: serverV4, want: Denied,
		},
		{
			name:     "single address given only through IPs",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"))},
			src:      Endpoint{Namespace: "ns", Name: "client", IPs: []string{"10.244.1.2"}}, dst: serverV4, want: Allowed,
		},
		{
			name:     "IPs repeats IP",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      Endpoint{Namespace: "ns", Name: "client", IP: "10.244.1.2", IPs: []string{"10.244.1.2"}}, dst: serverV4, want: Denied,
		},
		{
			name:     "an entry that is not an address is ignored next to a usable one",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"))},
			src:      Endpoint{Namespace: "ns", Name: "client", IP: "10.244.1.2", IPs: []string{"10.244.1.2", "", "not-an-ip"}}, dst: serverV4, want: Allowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, errs := NewIndex(tt.policies, nil)
			if len(errs) != 0 {
				t.Fatalf("NewIndex: %v", errs)
			}
			// A nil port and a concrete one take different paths through
			// Reaches; neither rule restricts ports, so they must agree.
			for _, port := range []*PortSpec{nil, portSpec(8080)} {
				if got, egress, ingress := idx.Reaches(tt.src, tt.dst, port); got != tt.want {
					t.Errorf("port %v: verdict = %v, want %v (egress: %s; ingress: %s)", port, got, tt.want, egress.Reason, ingress.Reason)
				}
			}
		})
	}
}

// A Denied that comes from the two directions admitting different IP
// families must say so, once: each direction, read alone, allows the
// connection.
func TestReaches_DualStackFamilyMismatchIsExplained(t *testing.T) {
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{
		clientEgress(ipBlockPeer("10.244.0.0/16")),
		serverIngress(ipBlockPeer("fd00:10:244::/56")),
	}, nil)
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")

	tests := []struct {
		name                    string
		port                    *PortSpec
		wantEgress, wantIngress string
	}{
		{
			name:        "port given",
			port:        portSpec(8080),
			wantEgress:  "egress considered independently: IPv4: matched a peer in this rule; rule has no port restriction; no IP family is allowed by both egress and ingress",
			wantIngress: "ingress considered independently: IPv6: matched a peer in this rule; rule has no port restriction; no IP family is allowed by both egress and ingress",
		},
		{
			name:        "any port",
			wantEgress:  "egress considered independently: IPv4: port 1/TCP: matched a peer in this rule; rule has no port restriction; no common IP family and port/protocol is possible across egress and ingress",
			wantIngress: "ingress considered independently: IPv6: port 1/TCP: matched a peer in this rule; rule has no port restriction; no common IP family and port/protocol is possible across egress and ingress",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, egress, ingress := idx.Reaches(client, server, tt.port)
			if v != Denied {
				t.Fatalf("verdict = %v, want Denied", v)
			}
			if egress.Verdict != Allowed || egress.Reason != tt.wantEgress {
				t.Errorf("egress = %v %q, want Allowed %q", egress.Verdict, egress.Reason, tt.wantEgress)
			}
			if ingress.Verdict != Allowed || ingress.Reason != tt.wantIngress {
				t.Errorf("ingress = %v %q, want Allowed %q", ingress.Verdict, ingress.Reason, tt.wantIngress)
			}
		})
	}
}

// Where no rule depends on an address, a dual-stack pair must get the very
// answer its single-stack twin gets: same verdict, same decisions, and no IP
// family named in a reason it had no part in.
func TestReaches_DualStackMatchesSingleStackWhenFamilyIsIrrelevant(t *testing.T) {
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")
	clientV4 := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}, IP: "10.244.1.2"}
	serverV4 := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}, IP: "10.244.2.2"}
	denyAll := policy("ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, nil, nil)
	egressOn := func(port int32) *networkingv1.NetworkPolicy {
		return policy("ns", "client-egress", selector("app", "client"), egressOnly, nil,
			[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{podSelectorPeer("app", "server")}, Ports: tcpPort(port)}})
	}
	ingressOn := func(ports []networkingv1.NetworkPolicyPort, peers ...networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
		return policy("ns", "server-ingress", selector("app", "server"), ingressOnly,
			[]networkingv1.NetworkPolicyIngressRule{{From: peers, Ports: ports}}, nil)
	}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		want     Verdict
	}{
		{name: "no policy", want: Allowed},
		{name: "default deny", policies: []*networkingv1.NetworkPolicy{denyAll}, want: Denied},
		{name: "podSelector peer matches", policies: []*networkingv1.NetworkPolicy{serverIngress(podSelectorPeer("app", "client"))}, want: Allowed},
		{name: "podSelector peer does not match", policies: []*networkingv1.NetworkPolicy{serverIngress(podSelectorPeer("app", "other"))}, want: Denied},
		{name: "uncollected namespace", policies: []*networkingv1.NetworkPolicy{serverIngress(namespaceSelectorPeer("team", "a"))}, want: Unknown},
		{name: "named port", policies: []*networkingv1.NetworkPolicy{ingressOn(namedPort("http"), podSelectorPeer("app", "client"))}, want: Unknown},
		{name: "egress and ingress allow different ports", policies: []*networkingv1.NetworkPolicy{egressOn(80), ingressOn(tcpPort(443), podSelectorPeer("app", "client"))}, want: Denied},
		// An ipBlock that admits the source in either family is not a
		// family-dependent answer either.
		{name: "one ipBlock per family, both admit the source", policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"), ipBlockPeer("fd00:10:244::/56"))}, want: Allowed},
	}
	for _, tt := range tests {
		for _, port := range []*PortSpec{nil, portSpec(8080)} {
			name := tt.name + "/any port"
			if port != nil {
				name = tt.name + "/port 8080"
			}
			t.Run(name, func(t *testing.T) {
				idx, _ := NewIndex(tt.policies, nil)
				wantV, wantEgress, wantIngress := idx.Reaches(clientV4, serverV4, port)
				if wantV != tt.want {
					t.Fatalf("single-stack verdict = %v, want %v", wantV, tt.want)
				}
				gotV, gotEgress, gotIngress := idx.Reaches(client, server, port)
				if gotV != wantV || gotEgress != wantEgress || gotIngress != wantIngress {
					t.Errorf("dual-stack differs from single-stack:\n got  %v egress=%+v ingress=%+v\n want %v egress=%+v ingress=%+v",
						gotV, gotEgress, gotIngress, wantV, wantEgress, wantIngress)
				}
				for _, d := range []Decision{gotEgress, gotIngress} {
					if strings.Contains(d.Reason, "IPv4") || strings.Contains(d.Reason, "IPv6") || strings.Contains(d.Reason, "IP family") {
						t.Errorf("reason %q names an IP family", d.Reason)
					}
				}
			})
		}
	}
}

// One family's verdict combines with the other's as Allowed over Unknown over
// Denied, whichever of the two is the pods' primary family. A named port
// makes a rule Unknown, so pairing it with an ipBlock of one family gives
// that family an Unknown verdict of its own.
func TestReaches_DualStackFamilyVerdictsCombine(t *testing.T) {
	v4Primary := [2]Endpoint{dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2"), dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")}
	v6Primary := [2]Endpoint{dualStackPod("client", "fd00:10:244:1::2", "10.244.1.2"), dualStackPod("server", "fd00:10:244:2::2", "10.244.2.2")}
	v4Block, v6Block := ipBlockPeer("10.244.0.0/16"), ipBlockPeer("fd00:10:244::/56")
	// ingress admits each listed family: on any port, or on a named one.
	ingress := func(anyPort, named []networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
		var rules []networkingv1.NetworkPolicyIngressRule
		if len(anyPort) > 0 {
			rules = append(rules, networkingv1.NetworkPolicyIngressRule{From: anyPort})
		}
		if len(named) > 0 {
			rules = append(rules, networkingv1.NetworkPolicyIngressRule{From: named, Ports: namedPort("http")})
		}
		return policy("ns", "server-ingress", selector("app", "server"), ingressOnly, rules, nil)
	}
	peers := func(p ...networkingv1.NetworkPolicyPeer) []networkingv1.NetworkPolicyPeer { return p }

	tests := []struct {
		name       string
		pods       [2]Endpoint
		policy     *networkingv1.NetworkPolicy
		want       Verdict
		wantFamily string
	}{
		{name: "IPv4 Unknown then IPv6 Allowed", pods: v4Primary, policy: ingress(peers(v6Block), peers(v4Block)), want: Allowed, wantFamily: "IPv6: "},
		{name: "IPv4 Allowed then IPv6 Unknown", pods: v4Primary, policy: ingress(peers(v4Block), peers(v6Block)), want: Allowed, wantFamily: "IPv4: "},
		{name: "IPv6 Unknown then IPv4 Allowed", pods: v6Primary, policy: ingress(peers(v4Block), peers(v6Block)), want: Allowed, wantFamily: "IPv4: "},
		{name: "IPv6 Allowed then IPv4 Unknown", pods: v6Primary, policy: ingress(peers(v6Block), peers(v4Block)), want: Allowed, wantFamily: "IPv6: "},
		{name: "IPv4 Unknown then IPv6 Denied", pods: v4Primary, policy: ingress(nil, peers(v4Block)), want: Unknown, wantFamily: "IPv4: "},
		{name: "IPv4 Denied then IPv6 Unknown", pods: v4Primary, policy: ingress(nil, peers(v6Block)), want: Unknown, wantFamily: "IPv6: "},
		{name: "IPv4 Allowed then IPv6 Denied", pods: v4Primary, policy: ingress(peers(v4Block), nil), want: Allowed, wantFamily: "IPv4: "},
		{name: "IPv4 Denied then IPv6 Allowed", pods: v4Primary, policy: ingress(peers(v6Block), nil), want: Allowed, wantFamily: "IPv6: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, _ := NewIndex([]*networkingv1.NetworkPolicy{tt.policy}, nil)
			got, _, ingress := idx.Reaches(tt.pods[0], tt.pods[1], portSpec(8080))
			if got != tt.want || ingress.Verdict != tt.want {
				t.Errorf("verdict = %v (ingress %v), want %v", got, ingress.Verdict, tt.want)
			}
			if !strings.HasPrefix(ingress.Reason, tt.wantFamily) {
				t.Errorf("ingress reason %q, want it to start with %q", ingress.Reason, tt.wantFamily)
			}
		})
	}
}

func TestReaches_DualStackAllowedNamesTheFamilyAndPolicy(t *testing.T) {
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))}, nil)
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")

	v, _, ingress := idx.Reaches(client, server, portSpec(8080))
	if v != Allowed {
		t.Fatalf("verdict = %v, want Allowed", v)
	}
	if ingress.MatchedPolicy != "ns/server-ingress" || !strings.HasPrefix(ingress.Reason, "IPv6: ") {
		t.Errorf("ingress = %q via %q, want the IPv6 match of ns/server-ingress", ingress.Reason, ingress.MatchedPolicy)
	}
}

// Without an address for the other end there is no family to pair, so an
// ipBlock that only some of a pod's addresses satisfy cannot be decided.
func TestReaches_DualStackUnknownAddresses(t *testing.T) {
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")
	noIPClient := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	noIPServer := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
		want     Verdict
	}{
		{
			name:     "source has no known address",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      noIPClient, dst: server, want: Unknown,
		},
		{
			name:     "destination has no known address and egress is by ipBlock",
			policies: []*networkingv1.NetworkPolicy{clientEgress(ipBlockPeer("fd00:10:244::/56"))},
			src:      client, dst: noIPServer, want: Unknown,
		},
		{
			name:     "neither has a known address",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      noIPClient, dst: noIPServer, want: Unknown,
		},
		{
			name:     "destination address unknown, ipBlock contains one source address of two",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))},
			src:      client, dst: noIPServer, want: Unknown,
		},
		{
			// Whichever family is used, one of the two peers admits it, but
			// peers are judged one at a time; Unknown is the safe answer.
			name:     "destination address unknown, each source address in a different ipBlock",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"), ipBlockPeer("10.244.0.0/16"))},
			src:      client, dst: noIPServer, want: Unknown,
		},
		{
			name:     "destination address unknown, one ipBlock contains every source address",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("0.0.0.0/0"))},
			src:      Endpoint{Namespace: "ns", Name: "client", IPs: []string{"10.244.1.2", "10.244.1.3"}}, dst: noIPServer, want: Allowed,
		},
		{
			name:     "destination address unknown, no ipBlock contains a source address",
			policies: []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("192.168.0.0/16"))},
			src:      client, dst: noIPServer, want: Denied,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, _ := NewIndex(tt.policies, nil)
			if got, egress, ingress := idx.Reaches(tt.src, tt.dst, portSpec(8080)); got != tt.want {
				t.Errorf("verdict = %v, want %v (egress: %s; ingress: %s)", got, tt.want, egress.Reason, ingress.Reason)
			}
		})
	}
}

// Everything that does not involve an ipBlock is independent of how many
// addresses a pod has.
func TestReaches_DualStackLeavesOtherSemanticsUnchanged(t *testing.T) {
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")
	hostServer := server
	hostServer.HostNetwork = true
	udp := corev1.ProtocolUDP
	denyAll := policy("ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, nil, nil)
	onPort := func(peer networkingv1.NetworkPolicyPeer, ports []networkingv1.NetworkPolicyPort) *networkingv1.NetworkPolicy {
		return policy("ns", "server-ingress", selector("app", "server"), ingressOnly,
			[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{peer}, Ports: ports}}, nil)
	}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
		port     *PortSpec
		want     Verdict
	}{
		{name: "no policy", src: client, dst: server, want: Allowed},
		{name: "default deny", policies: []*networkingv1.NetworkPolicy{denyAll}, src: client, dst: server, want: Denied},
		{name: "a pod reaches itself despite default deny", policies: []*networkingv1.NetworkPolicy{denyAll}, src: server, dst: server, want: Allowed},
		{name: "default deny on a hostNetwork destination", policies: []*networkingv1.NetworkPolicy{denyAll}, src: client, dst: hostServer, want: Unknown},
		{name: "podSelector peer matches", policies: []*networkingv1.NetworkPolicy{serverIngress(podSelectorPeer("app", "client"))}, src: client, dst: server, want: Allowed},
		{name: "podSelector peer does not match", policies: []*networkingv1.NetworkPolicy{serverIngress(podSelectorPeer("app", "other"))}, src: client, dst: server, want: Denied},
		{name: "empty namespaceSelector peer", policies: []*networkingv1.NetworkPolicy{serverIngress(emptyNamespaceSelectorPeer())}, src: client, dst: server, want: Allowed},
		{name: "uncollected namespace", policies: []*networkingv1.NetworkPolicy{serverIngress(namespaceSelectorPeer("team", "a"))}, src: client, dst: server, want: Unknown},
		{name: "ipBlock on the allowed port", policies: []*networkingv1.NetworkPolicy{onPort(ipBlockPeer("fd00:10:244::/56"), tcpPort(8080))}, src: client, dst: server, port: portSpec(8080), want: Allowed},
		{name: "ipBlock on another port", policies: []*networkingv1.NetworkPolicy{onPort(ipBlockPeer("fd00:10:244::/56"), tcpPort(8080))}, src: client, dst: server, port: portSpec(9090), want: Denied},
		{name: "ipBlock on another protocol", policies: []*networkingv1.NetworkPolicy{onPort(ipBlockPeer("fd00:10:244::/56"), tcpPort(8080))}, src: client, dst: server, port: &PortSpec{Protocol: udp, Port: 8080}, want: Denied},
		{name: "ipBlock on a named port", policies: []*networkingv1.NetworkPolicy{onPort(ipBlockPeer("fd00:10:244::/56"), namedPort("http"))}, src: client, dst: server, port: portSpec(8080), want: Unknown},
		{name: "ipBlock with any port queried", policies: []*networkingv1.NetworkPolicy{onPort(ipBlockPeer("fd00:10:244::/56"), tcpPort(8080))}, src: client, dst: server, want: Allowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, _ := NewIndex(tt.policies, nil)
			if got, egress, ingress := idx.Reaches(tt.src, tt.dst, tt.port); got != tt.want {
				t.Errorf("verdict = %v, want %v (egress: %s; ingress: %s)", got, tt.want, egress.Reason, ingress.Reason)
			}
		})
	}
}

// AllowsIngress and AllowsEgress answer for one direction only, with no
// second endpoint to fix the IP family.
func TestAllowsIngress_DualStackSourceMatchedByOneFamilyIsUnknown(t *testing.T) {
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("fd00:10:244::/56"))}, nil)
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	server := dualStackPod("server", "10.244.2.2", "fd00:10:244:2::2")

	if got := idx.AllowsIngress(client, server, nil).Verdict; got != Unknown {
		t.Errorf("verdict = %v, want Unknown", got)
	}
}

// The reason for that Unknown is that the address in use is unresolved, not
// that the pod's addresses are unknown.
func TestPeerListVerdict_PartialIPBlockMatchReason(t *testing.T) {
	idx, _ := NewIndex(nil, nil)
	client := dualStackPod("client", "10.244.1.2", "fd00:10:244:1::2")
	peers := []networkingv1.NetworkPolicyPeer{ipBlockPeer("fd00:10:244::/56")}

	v, reason := idx.peerListVerdict(peers, "ns", Endpoint{Namespace: "ns", Name: "server"}, client)
	if v != Unknown || !strings.Contains(reason, "some of the pod's addresses") {
		t.Errorf("dual-stack candidate: %v %q, want Unknown for a partial match", v, reason)
	}
	v, reason = idx.peerListVerdict(peers, "ns", Endpoint{Namespace: "ns", Name: "server"}, Endpoint{Namespace: "ns", Name: "client"})
	if v != Unknown || !strings.Contains(reason, "unknown IP") {
		t.Errorf("candidate without an address: %v %q, want Unknown for an unknown IP", v, reason)
	}
}

// Two pods whose known addresses share no IP family cannot open a connection
// to each other at all, so the two directions must not be judged separately
// -- each against an address the other end can never use -- and added up to
// Allowed. That is different from an address that is simply not known.
func TestReaches_NoCommonIPFamily(t *testing.T) {
	pod := func(name string, ips ...string) Endpoint {
		ep := Endpoint{Namespace: "ns", Name: name, Labels: map[string]string{"app": name}}
		if len(ips) > 0 {
			ep.IP, ep.IPs = ips[0], ips
		}
		return ep
	}
	const (
		v4ToV6 = "source has only IPv4 addresses and destination has only IPv6 addresses; with no IP family in common no connection between them is possible, whatever NetworkPolicy allows"
		v6ToV4 = "source has only IPv6 addresses and destination has only IPv4 addresses; with no IP family in common no connection between them is possible, whatever NetworkPolicy allows"
	)
	clientV4, clientV6 := pod("client", "10.244.1.2"), pod("client", "fd00:10:244:1::2")
	serverV4, serverV6 := pod("server", "10.244.2.2"), pod("server", "fd00:10:244:2::2")
	clientDual := pod("client", "10.244.1.2", "fd00:10:244:1::2")
	serverDual := pod("server", "fd00:10:244:2::2", "10.244.2.2")
	// Each direction, read alone, admits the other pod's only address.
	crossFamilyAllow := []*networkingv1.NetworkPolicy{
		clientEgress(ipBlockPeer("fd00:10:244::/56")),
		serverIngress(ipBlockPeer("10.244.0.0/16")),
	}
	selectorAllow := []*networkingv1.NetworkPolicy{
		clientEgress(podSelectorPeer("app", "server")),
		serverIngress(podSelectorPeer("app", "client")),
	}
	ingressByIPBlock := []*networkingv1.NetworkPolicy{serverIngress(ipBlockPeer("10.244.0.0/16"), ipBlockPeer("fd00:10:244::/56"))}
	egressByIPBlock := []*networkingv1.NetworkPolicy{clientEgress(ipBlockPeer("10.244.0.0/16"), ipBlockPeer("fd00:10:244::/56"))}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
		want     Verdict
		// wantReason, when set, is the reason both decisions must carry;
		// otherwise neither may claim the pods have no family in common.
		wantReason string
	}{
		{name: "IPv4-only to IPv6-only, no policy", src: clientV4, dst: serverV6, want: Denied, wantReason: v4ToV6},
		{name: "IPv6-only to IPv4-only, no policy", src: clientV6, dst: serverV4, want: Denied, wantReason: v6ToV4},
		{name: "IPv4-only to IPv6-only, each direction allows by ipBlock", policies: crossFamilyAllow, src: clientV4, dst: serverV6, want: Denied, wantReason: v4ToV6},
		{name: "IPv4-only to IPv6-only, each direction allows by selector", policies: selectorAllow, src: clientV4, dst: serverV6, want: Denied, wantReason: v4ToV6},
		{name: "IPv4-only to IPv6-only, addresses given through IPs alone", src: Endpoint{Namespace: "ns", Name: "client", IPs: []string{"10.244.1.2"}}, dst: Endpoint{Namespace: "ns", Name: "server", IPs: []string{"fd00:10:244:2::2"}}, want: Denied, wantReason: v4ToV6},

		{name: "source address unknown, no policy", src: pod("client"), dst: serverV6, want: Allowed},
		{name: "source address unknown, ingress by ipBlock", policies: ingressByIPBlock, src: pod("client"), dst: serverV6, want: Unknown},
		{name: "destination address unknown, no policy", src: clientV4, dst: pod("server"), want: Allowed},
		{name: "destination address unknown, egress by ipBlock", policies: egressByIPBlock, src: clientV4, dst: pod("server"), want: Unknown},
		{name: "neither address known, no policy", src: pod("client"), dst: pod("server"), want: Allowed},
		{name: "source address does not parse, no policy", src: pod("client", "not-an-ip"), dst: serverV6, want: Allowed},
		{name: "one of the source's addresses does not parse", src: pod("client", "10.244.1.2", "not-an-ip"), dst: serverV6, want: Allowed},

		{name: "dual-stack to IPv4-only, no policy", src: clientDual, dst: serverV4, want: Allowed},
		{name: "dual-stack to IPv6-only, no policy", src: clientDual, dst: serverV6, want: Allowed},
		{name: "IPv4-only to dual-stack, no policy", src: clientV4, dst: serverDual, want: Allowed},
		{name: "dual-stack to IPv4-only, ingress by ipBlock", policies: ingressByIPBlock, src: clientDual, dst: serverV4, want: Allowed},
		{name: "IPv4 to IPv4, no policy", src: clientV4, dst: serverV4, want: Allowed},
		{name: "IPv6 to IPv6, no policy", src: clientV6, dst: serverV6, want: Allowed},
		{name: "IPv4 to IPv4, ingress by ipBlock", policies: ingressByIPBlock, src: clientV4, dst: serverV4, want: Allowed},
		{name: "IPv6 to IPv6, egress by ipBlock", policies: egressByIPBlock, src: clientV6, dst: serverV6, want: Allowed},
		{name: "a pod reaches itself whatever its addresses", src: serverV6, dst: serverV6, want: Allowed},
	}
	for _, tt := range tests {
		for _, port := range []*PortSpec{nil, portSpec(8080)} {
			name := tt.name + "/any port"
			if port != nil {
				name = tt.name + "/port 8080"
			}
			t.Run(name, func(t *testing.T) {
				idx, _ := NewIndex(tt.policies, nil)
				got, egress, ingress := idx.Reaches(tt.src, tt.dst, port)
				if got != tt.want {
					t.Errorf("verdict = %v, want %v (egress: %s; ingress: %s)", got, tt.want, egress.Reason, ingress.Reason)
				}
				for dir, d := range map[string]Decision{"egress": egress, "ingress": ingress} {
					if tt.wantReason != "" {
						if d.Verdict != Denied || d.Reason != tt.wantReason {
							t.Errorf("%s = %v %q, want Denied %q", dir, d.Verdict, d.Reason, tt.wantReason)
						}
					} else if strings.Contains(d.Reason, "no IP family in common") {
						t.Errorf("%s reason %q claims the pods share no IP family", dir, d.Reason)
					}
				}
			})
		}
	}
}

// A hostNetwork pod reports its node's registered addresses, not everything
// the node's network has, so the same mismatch is not proof that it cannot
// connect -- and not grounds for the Allowed that judging each direction on
// its own would give.
func TestReaches_NoCommonIPFamilyWithHostNetworkIsUnknown(t *testing.T) {
	pod := func(name, ip string, hostNetwork bool) Endpoint {
		return Endpoint{Namespace: "ns", Name: name, Labels: map[string]string{"app": name}, IP: ip, IPs: []string{ip}, HostNetwork: hostNetwork}
	}
	crossFamilyAllow := []*networkingv1.NetworkPolicy{
		clientEgress(ipBlockPeer("fd00:10:244::/56")),
		serverIngress(ipBlockPeer("172.18.0.0/16")),
	}
	denyAll := []*networkingv1.NetworkPolicy{policy("ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}, nil, nil)}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
	}{
		{name: "hostNetwork source, no policy", src: pod("client", "172.18.0.5", true), dst: pod("server", "fd00:10:244:2::2", false)},
		{name: "hostNetwork destination, no policy", src: pod("client", "fd00:10:244:1::2", false), dst: pod("server", "172.18.0.5", true)},
		{name: "both on the host network, no policy", src: pod("client", "172.18.0.5", true), dst: pod("server", "fc00:f853:ccd:e793::7", true)},
		{name: "hostNetwork source, each direction allows by ipBlock", policies: crossFamilyAllow, src: pod("client", "172.18.0.5", true), dst: pod("server", "fd00:10:244:2::2", false)},
		{name: "hostNetwork source, default deny", policies: denyAll, src: pod("client", "172.18.0.5", true), dst: pod("server", "fd00:10:244:2::2", false)},
	}
	for _, tt := range tests {
		for _, port := range []*PortSpec{nil, portSpec(8080)} {
			name := tt.name + "/any port"
			if port != nil {
				name = tt.name + "/port 8080"
			}
			t.Run(name, func(t *testing.T) {
				idx, _ := NewIndex(tt.policies, nil)
				got, egress, ingress := idx.Reaches(tt.src, tt.dst, port)
				if got != Unknown {
					t.Errorf("verdict = %v, want Unknown (egress: %s; ingress: %s)", got, egress.Reason, ingress.Reason)
				}
				for dir, d := range map[string]Decision{"egress": egress, "ingress": ingress} {
					if d.Verdict != Unknown || !strings.Contains(d.Reason, "share no IP family") || !strings.Contains(d.Reason, "hostNetwork: true") {
						t.Errorf("%s = %v %q, want Unknown naming the family mismatch and the host network", dir, d.Verdict, d.Reason)
					}
				}
			})
		}
	}

	// With a family in common, or on the same Pod, nothing changes.
	idx, _ := NewIndex(nil, nil)
	if got, _, _ := idx.Reaches(pod("client", "172.18.0.5", true), pod("server", "10.244.2.2", false), portSpec(8080)); got != Allowed {
		t.Errorf("hostNetwork source with a common family: verdict = %v, want Allowed", got)
	}
	host := pod("server", "172.18.0.5", true)
	if got, _, _ := idx.Reaches(host, host, portSpec(8080)); got != Allowed {
		t.Errorf("hostNetwork pod to itself: verdict = %v, want Allowed", got)
	}
}
