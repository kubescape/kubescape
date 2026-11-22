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
