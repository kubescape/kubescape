package networkpolicy

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func expressionSelector(expressions ...metav1.LabelSelectorRequirement) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: expressions}
}

func requirement(key string, op metav1.LabelSelectorOperator, values ...string) metav1.LabelSelectorRequirement {
	return metav1.LabelSelectorRequirement{Key: key, Operator: op, Values: values}
}

// namespaceSelectorCases are the selector shapes the open-namespace check has
// to tell apart. open says whether a namespace with no labels of its own,
// which anyone allowed to create namespaces can make, is matched.
var namespaceSelectorCases = []struct {
	name     string
	selector *metav1.LabelSelector
	open     bool
}{
	{
		name:     "Exists on the automatic name label matches every namespace",
		selector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpExists)),
		open:     true,
	},
	{
		name:     "NotIn on the name label matches every namespace it does not list",
		selector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpNotIn, "kube-system")),
		open:     true,
	},
	{
		name:     "NotIn listing the probe name still matches another new namespace",
		selector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpNotIn, "new-namespace", "new-namespace-1")),
		open:     true,
	},
	{
		name:     "NotIn on a custom label matches namespaces without that label",
		selector: expressionSelector(requirement("team", metav1.LabelSelectorOpNotIn, "untrusted")),
		open:     true,
	},
	{
		name:     "DoesNotExist on a custom label matches namespaces without that label",
		selector: expressionSelector(requirement("quarantine", metav1.LabelSelectorOpDoesNotExist)),
		open:     true,
	},
	{
		name: "several requirements an unlabeled namespace satisfies",
		selector: expressionSelector(
			requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpNotIn, "kube-system", "kube-public"),
			requirement("quarantine", metav1.LabelSelectorOpDoesNotExist),
		),
		open: true,
	},
	{
		name:     "matchLabels on a custom label needs a label someone added",
		selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}},
		open:     false,
	},
	{
		name:     "matchLabels on the name label names one namespace",
		selector: &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: "monitoring"}},
		open:     false,
	},
	{
		name:     "In on the name label names specific namespaces",
		selector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpIn, "monitoring", "ingress")),
		open:     false,
	},
	{
		name:     "Exists on a custom label needs a label someone added",
		selector: expressionSelector(requirement("team", metav1.LabelSelectorOpExists)),
		open:     false,
	},
	{
		name:     "DoesNotExist on the name label matches no namespace",
		selector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpDoesNotExist)),
		open:     false,
	},
	{
		name: "an open requirement ANDed with a closed one is closed",
		selector: &metav1.LabelSelector{
			MatchLabels:      map[string]string{"team": "payments"},
			MatchExpressions: []metav1.LabelSelectorRequirement{requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpNotIn, "kube-system")},
		},
		open: false,
	},
}

func TestIngressExposure_NamespaceSelectorThatAdmitsNewNamespaces(t *testing.T) {
	for _, tc := range namespaceSelectorCases {
		t.Run(tc.name, func(t *testing.T) {
			p := policy("prod", "allow-namespaces", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				[]networkingv1.NetworkPolicyIngressRule{ingressRule(networkingv1.NetworkPolicyPeer{NamespaceSelector: tc.selector})}, nil)
			idx, errs := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)
			if len(errs) != 0 {
				t.Fatalf("NewIndex errors: %v", errs)
			}

			exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api", Labels: map[string]string{"app": "api"}})

			want := ExposureRestricted
			if tc.open {
				want = ExposureAnyNamespace
			}
			if exposure.Level != want {
				t.Fatalf("Level = %v, want %v (reason %q)", exposure.Level, want, exposure.Reason)
			}
			if exposure.MatchedPolicy != "prod/allow-namespaces" {
				t.Errorf("MatchedPolicy = %q, want prod/allow-namespaces", exposure.MatchedPolicy)
			}
		})
	}
}

// TestIngressExposure_OpenNamespaceSelectorAgreesWithReaches checks the
// classification against the matcher Reaches uses: a pod in a namespace that
// carries only its automatic name label is let in exactly when the selector
// was classified as admitting any namespace.
func TestIngressExposure_OpenNamespaceSelectorAgreesWithReaches(t *testing.T) {
	for _, tc := range namespaceSelectorCases {
		t.Run(tc.name, func(t *testing.T) {
			p := policy("prod", "allow-namespaces", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				[]networkingv1.NetworkPolicyIngressRule{ingressRule(networkingv1.NetworkPolicyPeer{NamespaceSelector: tc.selector})}, nil)
			namespaces := []NamespaceInfo{
				{Name: "prod", Labels: map[string]string{corev1.LabelMetadataName: "prod"}},
				{Name: "scratch-42", Labels: map[string]string{corev1.LabelMetadataName: "scratch-42"}},
			}
			idx, errs := NewIndex([]*networkingv1.NetworkPolicy{p}, namespaces)
			if len(errs) != 0 {
				t.Fatalf("NewIndex errors: %v", errs)
			}
			src := Endpoint{Namespace: "scratch-42", Name: "client", Labels: map[string]string{"app": "client"}}
			dst := Endpoint{Namespace: "prod", Name: "api", Labels: map[string]string{"app": "api"}}

			decision := idx.AllowsIngress(src, dst, portSpec(8080))
			classifiedOpen := idx.IngressExposure(dst).Level == ExposureAnyNamespace
			if (decision.Verdict == Allowed) != classifiedOpen {
				t.Fatalf("AllowsIngress from a new namespace = %v, but IngressExposure classified the selector open=%v", decision.Verdict, classifiedOpen)
			}
		})
	}
}

func TestIngressExposure_OpenNamespaceSelectorReasonNamesTheSelector(t *testing.T) {
	sel := expressionSelector(requirement("team", metav1.LabelSelectorOpNotIn, "untrusted"))
	p := policy("prod", "allow-trusted-teams", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(networkingv1.NetworkPolicyPeer{NamespaceSelector: sel})}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api"})

	if !strings.Contains(exposure.Reason, "team notin (untrusted)") {
		t.Errorf("Reason = %q, want it to quote the selector", exposure.Reason)
	}
	if !strings.Contains(exposure.Reason, "newly created namespace") {
		t.Errorf("Reason = %q, want it to explain that new namespaces are admitted", exposure.Reason)
	}
}

func TestIngressExposure_EmptyNamespaceSelectorKeepsItsReason(t *testing.T) {
	p := policy("prod", "allow-any-ns", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(emptyNamespaceSelectorPeer())}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api"})

	if exposure.Level != ExposureAnyNamespace || exposure.Reason != "namespaceSelector is empty, matching every namespace" {
		t.Errorf("got %+v, want the empty-selector classification unchanged", exposure)
	}
}

func TestIngressExposure_OpenNamespaceSelectorWithPodSelectorIsAnyNamespace(t *testing.T) {
	// The podSelector narrows which pods count, but any namespace's owner can
	// label their own pods to match it, as with an empty namespaceSelector.
	podSel := selector("role", "frontend")
	peer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpExists)),
		PodSelector:       &podSel,
	}
	p := policy("prod", "allow-frontends", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{ingressRule(peer)}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api"})

	if exposure.Level != ExposureAnyNamespace {
		t.Errorf("Level = %v, want ExposureAnyNamespace", exposure.Level)
	}
}

func TestIngressExposure_OpenNamespaceSelectorWidensAScopedPeerInTheSameRule(t *testing.T) {
	rule := ingressRule(
		namespaceSelectorPeer("team", "payments"),
		networkingv1.NetworkPolicyPeer{NamespaceSelector: expressionSelector(requirement("quarantine", metav1.LabelSelectorOpDoesNotExist))},
	)
	p := policy("prod", "mixed", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{rule}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api"})

	if exposure.Level != ExposureAnyNamespace {
		t.Errorf("Level = %v, want ExposureAnyNamespace", exposure.Level)
	}
}

func TestIngressExposure_IPBlockStillOutranksAnOpenNamespaceSelector(t *testing.T) {
	rule := ingressRule(
		networkingv1.NetworkPolicyPeer{NamespaceSelector: expressionSelector(requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpExists))},
		ipBlockPeer("203.0.113.0/24"),
	)
	p := policy("prod", "mixed", metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{rule}, nil)
	idx, _ := NewIndex([]*networkingv1.NetworkPolicy{p}, nil)

	exposure := idx.IngressExposure(Endpoint{Namespace: "prod", Name: "api"})

	if exposure.Level != ExposureExternalCIDR {
		t.Errorf("Level = %v, want ExposureExternalCIDR", exposure.Level)
	}
}

func TestAdmitsUnlabeledNamespace_UnselectableSelector(t *testing.T) {
	if admitsUnlabeledNamespace(labels.Nothing()) {
		t.Error("a selector that matches nothing must not be classified as admitting new namespaces")
	}
}

func TestUnlistedNamespaceName_SkipsListedNames(t *testing.T) {
	sel, err := metav1.LabelSelectorAsSelector(expressionSelector(
		requirement(corev1.LabelMetadataName, metav1.LabelSelectorOpNotIn, "new-namespace", "new-namespace-1", "new-namespace-2"),
	))
	if err != nil {
		t.Fatalf("LabelSelectorAsSelector: %v", err)
	}
	requirements, _ := sel.Requirements()

	if got := unlistedNamespaceName(requirements); got != "new-namespace-3" {
		t.Errorf("unlistedNamespaceName = %q, want new-namespace-3", got)
	}
}
