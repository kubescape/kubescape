package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNamespaceNameReachability(t *testing.T) {
	for _, direction := range []Direction{Ingress, Egress} {
		t.Run(direction.String(), func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				namespaces    []NamespaceInfo
				peerNamespace string
				want          Verdict
			}{
				{name: "manifest namespace without labels", namespaces: []NamespaceInfo{{Name: "trusted"}}, peerNamespace: "trusted", want: Allowed},
				{name: "uncollected matching namespace", peerNamespace: "trusted", want: Allowed},
				{name: "uncollected other namespace", peerNamespace: "untrusted", want: Denied},
				{name: "manifest other namespace", namespaces: []NamespaceInfo{{Name: "untrusted"}}, peerNamespace: "untrusted", want: Denied},
				{name: "immutable name overrides inconsistent input", namespaces: []NamespaceInfo{{Name: "untrusted", Labels: map[string]string{corev1.LabelMetadataName: "trusted"}}}, peerNamespace: "untrusted", want: Denied},
			} {
				t.Run(tc.name, func(t *testing.T) {
					selected := Endpoint{Namespace: "app", Name: "server"}
					peer := Endpoint{Namespace: tc.peerNamespace, Name: "client"}
					nsSelector := metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "trusted"}}
					p := policy("app", "allow-trusted", metav1.LabelSelector{}, nil, nil, nil)
					peers := []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &nsSelector}}
					src, dst := peer, selected
					if direction == Ingress {
						p.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
						p.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{From: peers}}
					} else {
						src, dst = selected, peer
						p.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
						p.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{To: peers}}
					}
					idx, errs := NewIndex([]*networkingv1.NetworkPolicy{p}, tc.namespaces)
					require.Empty(t, errs)
					v, _, _ := idx.Reaches(src, dst, &PortSpec{Port: 443})
					require.Equal(t, tc.want, v)
				})
			}
		})
	}
}

func TestNamespaceNameWithUnknownAdditionalLabels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		namespace  string
		namespaces []NamespaceInfo
		want       Verdict
	}{
		{name: "matching name still needs team label", namespace: "trusted", want: Unknown},
		{name: "wrong name is conclusive despite missing labels", namespace: "other", want: Denied},
		{name: "known team matches", namespace: "trusted", namespaces: []NamespaceInfo{{Name: "trusted", Labels: map[string]string{"team": "platform"}}}, want: Allowed},
		{name: "known team differs", namespace: "trusted", namespaces: []NamespaceInfo{{Name: "trusted", Labels: map[string]string{"team": "payments"}}}, want: Denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "trusted", "team": "platform"}}
			p := policy("app", "allow", metav1.LabelSelector{}, nil,
				[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &ns}}}}, nil)
			idx, errs := NewIndex([]*networkingv1.NetworkPolicy{p}, tc.namespaces)
			require.Empty(t, errs)
			v, _, _ := idx.Reaches(Endpoint{Namespace: tc.namespace, Name: "client"}, Endpoint{Namespace: "app", Name: "server"}, &PortSpec{Port: 80})
			require.Equal(t, tc.want, v)
		})
	}
}
