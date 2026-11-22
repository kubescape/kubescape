package webhookcoverage

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/rules"
)

// resourceOverride mirrors the apiserver's own wrapper that re-runs the rules
// against an equivalent resource: only the resource changes; the operation,
// subresource and namespace of the request stay.
type resourceOverride struct {
	admission.Attributes
	resource schema.GroupVersionResource
}

func (a resourceOverride) GetResource() schema.GroupVersionResource { return a.resource }

// TestEquivalentNeverFalselyRejectsAnyEquivalentResource stands in for an
// apiserver registry this package cannot see. For many rules and requests, and
// for equivalent resources of any group, version and plural name, whenever the
// apiserver's own rule predicate would match through such a resource the
// package must not report NotMatched. Under Exact it must follow the direct
// match alone.
func TestEquivalentNeverFalselyRejectsAnyEquivalentResource(t *testing.T) {
	all := admissionregistrationv1.OperationAll
	ruleSets := map[string][]admissionregistrationv1.RuleWithOperations{
		"pods create":        {podRule(create)},
		"pods/exec connect":  {rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, connect)},
		"pods/*":             {rule([]string{""}, []string{"v1"}, []string{"pods/*"}, all)},
		"all":                {rule([]string{"*"}, []string{"*"}, []string{"*"}, all)},
		"all with sub":       {rule([]string{"*"}, []string{"*"}, []string{"*/*"}, all)},
		"deployments apps":   {rule([]string{"apps"}, []string{"v1"}, []string{"deployments"}, create, update)},
		"ingress ext":        {rule([]string{"extensions"}, []string{"v1beta1"}, []string{"ingresses"}, all)},
		"namespaced secrets": {scoped(rule([]string{""}, []string{"v1"}, []string{"secrets"}, all), admissionregistrationv1.NamespacedScope)},
		"cluster nodes":      {scoped(rule([]string{""}, []string{"v1"}, []string{"nodes"}, all), admissionregistrationv1.ClusterScope)},
		"namespaces":         {rule([]string{""}, []string{"v1"}, []string{"namespaces"}, all)},
		"two rules":          {podRule(update), rule([]string{"apps"}, []string{"v1"}, []string{"deployments/scale"}, update)},
		"namespaced all":     {scoped(rule([]string{"*"}, []string{"*"}, []string{"*"}, all), admissionregistrationv1.NamespacedScope)},
		"cluster all":        {scoped(rule([]string{"*"}, []string{"*"}, []string{"*"}, all), admissionregistrationv1.ClusterScope)},
		"cluster pods":       {scoped(podRule(create), admissionregistrationv1.ClusterScope)},
	}

	var equivalents []schema.GroupVersionResource
	for _, g := range []string{"", "apps", "extensions", "networking.k8s.io", "example.io"} {
		for _, v := range []string{"v1", "v1beta1", "v2"} {
			for _, r := range []string{"pods", "deployments", "secrets", "nodes", "namespaces", "ingresses", "things"} {
				equivalents = append(equivalents, schema.GroupVersionResource{Group: g, Version: v, Resource: r})
			}
		}
	}
	requests := map[string]Request{
		"pods create":       {Version: "v1", Resource: "pods", Kind: "Pod", Operation: create, Name: "p", Namespace: "ns1", ObjectLabelsKnown: true},
		"pods update":       {Version: "v1", Resource: "pods", Kind: "Pod", Operation: update, Name: "p", Namespace: "ns1", ObjectLabelsKnown: true, OldObjectLabelsKnown: true},
		"pods/exec connect": {Version: "v1", Resource: "pods", Subresource: "exec", Kind: "Pod", Operation: connect, Name: "p", Namespace: "ns1"},
		"pods/status":       {Version: "v1", Resource: "pods", Subresource: "status", Kind: "Pod", Operation: update, Name: "p", Namespace: "ns1", ObjectLabelsKnown: true, OldObjectLabelsKnown: true},
		"deployments/scale": {Group: "apps", Version: "v1beta1", Resource: "deployments", Subresource: "scale", Kind: "Scale", Operation: update, Name: "d", Namespace: "ns1", ObjectLabelsKnown: true, OldObjectLabelsKnown: true},
		"deployment create": {Group: "extensions", Version: "v1beta1", Resource: "deployments", Kind: "Deployment", Operation: create, Name: "d", Namespace: "ns1", ObjectLabelsKnown: true},
		"node create":       {Version: "v1", Resource: "nodes", Kind: "Node", Operation: create, Name: "n", ClusterScoped: true, ObjectLabelsKnown: true},
		"node delete":       {Version: "v1", Resource: "nodes", Kind: "Node", Operation: deleteO, Name: "n", ClusterScoped: true, OldObjectLabelsKnown: true},
		"namespace create":  {Version: "v1", Resource: "namespaces", Kind: "Namespace", Operation: create, Name: "ns2", ObjectLabelsKnown: true},
		"things create":     {Group: "example.io", Version: "v2", Resource: "things", Kind: "Thing", Operation: create, Name: "t", Namespace: "ns1", ObjectLabelsKnown: true},
		"namespace unknown": {Version: "v1", Resource: "secrets", Kind: "Secret", Operation: create, Name: "s", ObjectLabelsKnown: true},
	}

	checked, viaEquivalent := 0, 0
	for rsName, rs := range ruleSets {
		for _, policy := range []*admissionregistrationv1.MatchPolicyType{nil, equivalent(), exact()} {
			idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: rs, MatchPolicy: policy})
			for reqName, req := range requests {
				got := verdict(t, idx, req)
				r, ok := newRequest(req)
				require.True(t, ok)

				direct := false
				for _, rule := range rs {
					direct = direct || (&rules.Matcher{Rule: rule, Attr: r.attr}).Matches()
				}
				equivalentHit := false
				for _, gvr := range equivalents {
					for _, rule := range rs {
						if (&rules.Matcher{Rule: rule, Attr: resourceOverride{r.attr, gvr}}).Matches() {
							equivalentHit = true
						}
					}
				}

				label := fmt.Sprintf("rules=%s policy=%v request=%s", rsName, policy, reqName)
				checked++
				switch {
				case direct:
					require.Equal(t, Matched, got.Verdict, label)
				case policy != nil && *policy == admissionregistrationv1.Exact:
					require.Equal(t, NotMatched, got.Verdict, label)
				case equivalentHit:
					viaEquivalent++
					require.NotEqual(t, NotMatched, got.Verdict, "%s: an equivalent resource would match", label)
				}
			}
		}
	}
	require.NotZero(t, checked)
	require.NotZero(t, viaEquivalent, "the grid must include cases that only an equivalent resource could match")
	t.Logf("checked %d combinations, %d reachable only through an equivalent resource", checked, viaEquivalent)
}

// An equivalent resource keeps the request's namespace, so the scope check can
// still reject a request whatever resource the apiserver's registry offers. The
// only exception is the core Namespace, which the scope predicate treats as
// cluster-scoped. Each expectation is checked against the apiserver predicate
// run over candidate resources, including the core Namespace.
func TestEquivalentKeepsDefiniteScopeExclusions(t *testing.T) {
	all := admissionregistrationv1.OperationAll
	wildcard := rule([]string{"*"}, []string{"*"}, []string{"*"}, all)
	namespaced := scoped(wildcard, admissionregistrationv1.NamespacedScope)
	cluster := scoped(wildcard, admissionregistrationv1.ClusterScope)
	clusterNamespaces := scoped(rule([]string{""}, []string{"v1"}, []string{"namespaces"}, all), admissionregistrationv1.ClusterScope)
	clusterPods := scoped(rule([]string{""}, []string{"v1"}, []string{"pods"}, all), admissionregistrationv1.ClusterScope)

	node := Request{Version: "v1", Resource: "nodes", Kind: "Node", Operation: create, Name: "n", ClusterScoped: true, ObjectLabelsKnown: true}
	pod := Request{Version: "v1", Resource: "pods", Kind: "Pod", Operation: create, Name: "p", Namespace: "ns1", ObjectLabelsKnown: true}
	tests := []struct {
		name string
		rule admissionregistrationv1.RuleWithOperations
		req  Request
		want Verdict
	}{
		{"cluster-scoped request, namespaced-only wildcard rule", namespaced, node, NotMatched},
		{"cluster-scoped request, cluster wildcard rule", cluster, node, Matched},
		{"namespaced request, namespaced wildcard rule", namespaced, pod, Matched},
		{"namespaced request, cluster wildcard rule: only the core Namespace passes", cluster, pod, Indeterminate},
		{"namespaced request, cluster rule for namespaces: the core Namespace passes", clusterNamespaces, pod, Indeterminate},
		{"namespaced request, cluster rule for pods: nothing passes", clusterPods, pod, NotMatched},
	}
	var candidates []schema.GroupVersionResource
	for _, g := range []string{"", "apps", "example.io"} {
		for _, v := range []string{"v1", "v1beta1"} {
			for _, r := range []string{"pods", "nodes", "namespaces", "deployments", "things"} {
				candidates = append(candidates, schema.GroupVersionResource{Group: g, Version: v, Resource: r})
			}
		}
	}
	for _, tt := range tests {
		for _, policy := range []*admissionregistrationv1.MatchPolicyType{nil, equivalent()} {
			t.Run(fmt.Sprintf("%s/explicit=%v", tt.name, policy != nil), func(t *testing.T) {
				idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{tt.rule}, MatchPolicy: policy})
				got := verdict(t, idx, tt.req)
				r, ok := newRequest(tt.req)
				require.True(t, ok)

				direct := (&rules.Matcher{Rule: tt.rule, Attr: r.attr}).Matches()
				viaEquivalent := false
				for _, gvr := range candidates {
					viaEquivalent = viaEquivalent || (&rules.Matcher{Rule: tt.rule, Attr: resourceOverride{r.attr, gvr}}).Matches()
				}
				switch tt.want {
				case Matched:
					require.True(t, direct, "the apiserver predicate matches the request itself")
					require.Equal(t, Matched, got.Verdict)
				case Indeterminate:
					require.False(t, direct)
					require.True(t, viaEquivalent, "the apiserver predicate matches through some equivalent resource")
					require.Equal(t, Indeterminate, got.Verdict)
					require.Equal(t, []Reason{ReasonEquivalentResources}, got.Reasons)
				case NotMatched:
					require.False(t, direct)
					require.False(t, viaEquivalent, "the apiserver predicate matches no equivalent resource")
					require.Equal(t, NotMatched, got.Verdict)
					require.Equal(t, []Reason{ReasonRulesDoNotMatch}, got.Reasons)
				}
			})
		}
	}
}
