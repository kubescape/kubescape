package networkpolicy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func selector(kv ...string) metav1.LabelSelector {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return metav1.LabelSelector{MatchLabels: m}
}

func policy(namespace, name string, podSel metav1.LabelSelector, types []networkingv1.PolicyType, ingress []networkingv1.NetworkPolicyIngressRule, egress []networkingv1.NetworkPolicyEgressRule) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: podSel,
			PolicyTypes: types,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func TestPolicyTypesFor_Defaulting(t *testing.T) {
	tests := []struct {
		name        string
		types       []networkingv1.PolicyType
		egressRules []networkingv1.NetworkPolicyEgressRule
		wantIngress bool
		wantEgress  bool
	}{
		{
			name:        "no policyTypes, no egress rules: ingress only",
			types:       nil,
			egressRules: nil,
			wantIngress: true,
			wantEgress:  false,
		},
		{
			name:        "no policyTypes, has egress rules: both apply",
			types:       nil,
			egressRules: []networkingv1.NetworkPolicyEgressRule{{}},
			wantIngress: true,
			wantEgress:  true,
		},
		{
			name:        "explicit policyTypes: [Egress] only, even with a podSelector matching",
			types:       []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			egressRules: nil,
			wantIngress: false,
			wantEgress:  true,
		},
		{
			name:        "explicit policyTypes: [Ingress, Egress]",
			types:       []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			egressRules: nil,
			wantIngress: true,
			wantEgress:  true,
		},
		{
			name:        "explicit policyTypes: [Ingress] only, despite having egress rules",
			types:       []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			egressRules: []networkingv1.NetworkPolicyEgressRule{{}},
			wantIngress: true,
			wantEgress:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := policy("ns", "p", metav1.LabelSelector{}, tt.types, nil, tt.egressRules)
			ingress, egress := policyTypesFor(p)
			if ingress != tt.wantIngress {
				t.Errorf("ingress = %v, want %v", ingress, tt.wantIngress)
			}
			if egress != tt.wantEgress {
				t.Errorf("egress = %v, want %v", egress, tt.wantEgress)
			}
		})
	}
}

func TestIsIsolated_NoPolicySelectsPod(t *testing.T) {
	idx := NewIndex(nil, nil)
	pod := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	if idx.IsIsolated(pod, Ingress) {
		t.Error("a pod with zero policies in its namespace must not be isolated")
	}
	if idx.IsIsolated(pod, Egress) {
		t.Error("a pod with zero policies in its namespace must not be isolated")
	}
}

func TestIsIsolated_PolicyInAnotherNamespaceDoesNotIsolate(t *testing.T) {
	p := policy("other-ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	pod := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"app": "web"}}

	if idx.IsIsolated(pod, Ingress) {
		t.Error("a policy in a different namespace must never isolate a pod in this one")
	}
}

func TestIsIsolated_EmptyPodSelectorSelectsWholeNamespace(t *testing.T) {
	p := policy("ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil)
	idx := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
	pod := Endpoint{Namespace: "ns", Name: "app", Labels: map[string]string{"anything": "goes"}}

	if !idx.IsIsolated(pod, Ingress) {
		t.Error("an empty podSelector must select every pod in the namespace")
	}
}

func TestIsIsolated_MalformedPodSelectorSkipsThatPolicyOnly(t *testing.T) {
	good := policy("ns", "deny-all", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil)
	bad := policy("ns", "broken", metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "x", Operator: "NotARealOperator"}},
	}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil, nil)

	idx := NewIndex([]*networkingv1.NetworkPolicy{good, bad}, nil)
	pod := Endpoint{Namespace: "ns", Name: "app"}

	if !idx.IsIsolated(pod, Ingress) {
		t.Error("the well-formed policy must still isolate for ingress")
	}
	if idx.IsIsolated(pod, Egress) {
		t.Error("the malformed policy must be skipped, not treated as isolating for egress")
	}
}

func portSpec(port int32) *PortSpec {
	return &PortSpec{Protocol: corev1.ProtocolTCP, Port: port}
}

func tcpPort(port int32) []networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(port)
	return []networkingv1.NetworkPolicyPort{{Port: &p}}
}

func namedPort(name string) []networkingv1.NetworkPolicyPort {
	p := intstr.FromString(name)
	return []networkingv1.NetworkPolicyPort{{Port: &p}}
}
