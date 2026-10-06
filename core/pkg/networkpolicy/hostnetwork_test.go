package networkpolicy

import (
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var bothTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}

// The Kubernetes NetworkPolicy docs leave the behaviour for hostNetwork pods
// undefined, and name "ignore them" as the most common implementation. Every
// case here is one where the two permitted behaviours disagree, so neither
// Allowed nor Denied can be reported with confidence.
func TestReaches_HostNetworkPodIsUnknownWherePluginsDisagree(t *testing.T) {
	denyAll := policy("ns", "deny-all", metav1.LabelSelector{}, bothTypes, nil, nil)
	allowClientToServer := policy("ns", "allow-client", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(podSelectorPeer("app", "client"))}, nil)
	allowProdNamespace := policy("ns", "allow-prod", selector("app", "server"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(namespaceSelectorPeer("env", "prod"))}, nil)
	egressToServerOnly := policy("ns", "egress-to-server", selector("app", "client"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
		[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{podSelectorPeer("app", "server")}}})

	pod := func(name string, hostNetwork bool) Endpoint {
		return Endpoint{Namespace: "ns", Name: name, Labels: map[string]string{"app": name}, HostNetwork: hostNetwork}
	}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
	}{
		{
			// A plugin that ignores hostNetwork pods does not enforce the
			// policy that selects the destination.
			name:     "default-deny selects a hostNetwork destination",
			policies: []*networkingv1.NetworkPolicy{denyAll},
			src:      Endpoint{Namespace: "other", Name: "client"},
			dst:      pod("server", true),
		},
		{
			name:     "default-deny selects a hostNetwork source",
			policies: []*networkingv1.NetworkPolicy{denyAll},
			src:      pod("client", true),
			dst:      Endpoint{Namespace: "other", Name: "server"},
		},
		{
			// A plugin that ignores hostNetwork pods does not match the
			// source against a podSelector peer: it sees the node's address.
			name:     "podSelector peer matches a hostNetwork source by label",
			policies: []*networkingv1.NetworkPolicy{allowClientToServer},
			src:      pod("client", true),
			dst:      pod("server", false),
		},
		{
			name:     "namespaceSelector peer matches a hostNetwork source's namespace",
			policies: []*networkingv1.NetworkPolicy{allowProdNamespace},
			src:      pod("client", true),
			dst:      pod("server", false),
		},
		{
			// The source's traffic is its node's, which is always allowed to
			// the pods on that node whatever selects them.
			name:     "no peer matches a hostNetwork source",
			policies: []*networkingv1.NetworkPolicy{allowClientToServer},
			src:      pod("other", true),
			dst:      pod("server", false),
		},
		{
			name:     "podSelector egress peer matches a hostNetwork destination by label",
			policies: []*networkingv1.NetworkPolicy{egressToServerOnly},
			src:      pod("client", false),
			dst:      pod("server", true),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, errs := NewIndex(tt.policies, []NamespaceInfo{{Name: "ns", Labels: map[string]string{"env": "prod"}}})
			if len(errs) != 0 {
				t.Fatalf("unexpected index errors: %v", errs)
			}
			for _, port := range []*PortSpec{portSpec(80), nil} {
				v, egress, ingress := idx.Reaches(tt.src, tt.dst, port)
				if v != Unknown {
					t.Errorf("port %v: verdict = %v, want Unknown (egress: %q, ingress: %q)", port, v, egress.Reason, ingress.Reason)
				}
				if reasons := egress.Reason + ingress.Reason; !strings.Contains(reasons, "host network") {
					t.Errorf("port %v: no decision explains the host network caveat (egress: %q, ingress: %q)", port, egress.Reason, ingress.Reason)
				}
			}
		})
	}
}

// Where both permitted behaviours agree, a hostNetwork pod still gets a
// confident answer.
func TestReaches_HostNetworkPodKeepsVerdictsEveryPluginAgreesOn(t *testing.T) {
	hostServer := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}, HostNetwork: true}
	hostClient := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}, IP: "172.18.0.3", HostNetwork: true}
	client := Endpoint{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}
	server := Endpoint{Namespace: "ns", Name: "server", Labels: map[string]string{"app": "server"}}

	ingressTo := func(from ...networkingv1.NetworkPolicyPeer) *networkingv1.NetworkPolicy {
		return policy("ns", "server-ingress", selector("app", "server"),
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			[]networkingv1.NetworkPolicyIngressRule{ingressRule(from...)}, nil)
	}

	tests := []struct {
		name     string
		policies []*networkingv1.NetworkPolicy
		src, dst Endpoint
	}{
		{name: "no policy at all", src: client, dst: hostServer},
		{name: "a policy that allows the peer selects a hostNetwork destination", policies: []*networkingv1.NetworkPolicy{ingressTo(podSelectorPeer("app", "client"))}, src: client, dst: hostServer},
		{name: "rule without a peer restriction admits a hostNetwork source", policies: []*networkingv1.NetworkPolicy{ingressTo()}, src: hostClient, dst: server},
		{name: "ipBlock peer admits a hostNetwork source's node address", policies: []*networkingv1.NetworkPolicy{ingressTo(ipBlockPeer("172.18.0.0/16"))}, src: hostClient, dst: server},
		{name: "a hostNetwork pod reaches itself", policies: []*networkingv1.NetworkPolicy{policy("ns", "deny-all", metav1.LabelSelector{}, bothTypes, nil, nil)}, src: hostServer, dst: hostServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, _ := NewIndex(tt.policies, nil)
			for _, port := range []*PortSpec{portSpec(80), nil} {
				if v, egress, ingress := idx.Reaches(tt.src, tt.dst, port); v != Allowed {
					t.Errorf("port %v: verdict = %v, want Allowed (egress: %q, ingress: %q)", port, v, egress.Reason, ingress.Reason)
				}
			}
		})
	}
}

func TestIngressExposure_HostNetworkPodIsNotCountedAsRestricted(t *testing.T) {
	restrict := policy("ns", "restrict-web", selector("app", "web"),
		[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(podSelectorPeer("app", "client"))}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{restrict}, nil)

	podNetwork := Endpoint{Namespace: "ns", Name: "web", Labels: map[string]string{"app": "web"}}
	if got := idx.IngressExposure(podNetwork); got.Level != ExposureRestricted || got.MatchedPolicy != "ns/restrict-web" {
		t.Fatalf("pod-network endpoint: got %+v, want ExposureRestricted by ns/restrict-web", got)
	}

	hostNetwork := podNetwork
	hostNetwork.HostNetwork = true
	got := idx.IngressExposure(hostNetwork)
	if got.Level != ExposureOpen {
		t.Errorf("hostNetwork endpoint: Level = %v, want ExposureOpen", got.Level)
	}
	if got.MatchedPolicy != "" {
		t.Errorf("hostNetwork endpoint: MatchedPolicy = %q, want none: no policy is what leaves it open", got.MatchedPolicy)
	}
	if !strings.Contains(got.Reason, "host network") {
		t.Errorf("hostNetwork endpoint: Reason does not explain the caveat: %q", got.Reason)
	}
}

func TestEndpointFromResource_CarriesHostNetwork(t *testing.T) {
	pod := func(spec map[string]any) workloadinterface.IMetadata {
		return workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": "web", "namespace": "prod"},
			"spec":       spec,
		})
	}

	if !EndpointFromResource(pod(map[string]any{"hostNetwork": true})).HostNetwork {
		t.Error("expected spec.hostNetwork: true to carry through")
	}
	if EndpointFromResource(pod(map[string]any{"hostNetwork": false})).HostNetwork {
		t.Error("spec.hostNetwork: false must not be reported as host network")
	}
	if EndpointFromResource(pod(map[string]any{})).HostNetwork {
		t.Error("an unset spec.hostNetwork must not be reported as host network")
	}
}
