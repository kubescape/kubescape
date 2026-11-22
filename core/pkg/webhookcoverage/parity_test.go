package webhookcoverage

import (
	"testing"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	apiwebhook "k8s.io/apiserver/pkg/admission/plugin/webhook"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/namespace"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/object"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/predicates/rules"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

// apiserverCalls decides whether the API server would call hook for attr, by
// running the apiserver's own predicates in the order generic.Webhook's
// ShouldCallHook and Dispatch apply them. Equivalent resources are not
// registered, so Equivalent matchPolicy adds nothing here.
func apiserverCalls(t *testing.T, ns *namespace.Matcher, hook apiwebhook.WebhookAccessor, attr admission.Attributes) bool {
	t.Helper()
	if rules.IsExemptAdmissionConfigurationResource(attr) {
		return false
	}
	nsMatch, nsErr := ns.MatchNamespaceSelector(hook, attr)
	require.Nil(t, nsErr)
	if !nsMatch {
		return false
	}
	objMatch, objErr := (&object.Matcher{}).MatchObjectSelector(hook, attr)
	require.Nil(t, objErr)
	if !objMatch {
		return false
	}
	for _, r := range hook.GetRules() {
		if (&rules.Matcher{Rule: r, Attr: attr}).Matches() {
			return true
		}
	}
	return false
}

func labelled(l map[string]string) runtime.Object {
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Labels: l}}
}

// TestParityWithAPIServerMatchers runs a grid of synthetic requests and
// webhooks through both this package and the apiserver predicates. With
// complete information the result must never be Indeterminate (except for
// matchConditions, which the grid leaves out), and must agree with the
// apiserver.
func TestParityWithAPIServerMatchers(t *testing.T) {
	nsLabels := map[string]string{"env": "prod"}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, name := range []string{"ns1", "existing"} {
		require.NoError(t, indexer.Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: nsLabels}}))
	}
	nsMatcher := &namespace.Matcher{NamespaceLister: corelisters.NewNamespaceLister(indexer), Client: fake.NewClientset()}

	all := rule([]string{"*"}, []string{"*"}, []string{"*", "*/*"}, admissionregistrationv1.OperationAll)
	ruleSets := map[string][]admissionregistrationv1.RuleWithOperations{
		"all":          {all},
		"pods create":  {podRule(create)},
		"pods update":  {podRule(update, deleteO)},
		"pods/exec":    {rule([]string{""}, []string{"v1"}, []string{"pods/exec"}, connect)},
		"pods/*":       {rule([]string{""}, []string{"v1"}, []string{"pods/*"}, admissionregistrationv1.OperationAll)},
		"namespaces":   {rule([]string{""}, []string{"v1"}, []string{"namespaces"}, admissionregistrationv1.OperationAll)},
		"apps":         {rule([]string{"apps"}, []string{"*"}, []string{"deployments"}, create, update)},
		"namespaced":   {scoped(all, admissionregistrationv1.NamespacedScope)},
		"cluster":      {scoped(all, admissionregistrationv1.ClusterScope)},
		"webhook cfgs": {rule([]string{"admissionregistration.k8s.io"}, []string{"v1"}, []string{"*"}, admissionregistrationv1.OperationAll)},
	}
	selectors := map[string]*metav1.LabelSelector{
		"none":         nil,
		"in":           selector("app", metav1.LabelSelectorOpIn, "web"),
		"notin":        selector("app", metav1.LabelSelectorOpNotIn, "web"),
		"doesnotexist": selector("app", metav1.LabelSelectorOpDoesNotExist),
		"env prod":     selector("env", metav1.LabelSelectorOpIn, "prod"),
		"env notin":    selector("env", metav1.LabelSelectorOpNotIn, "prod"),
	}

	type target struct {
		group, version, resource, kind, subresource, namespace, name string
	}
	targets := []target{
		{"", "v1", "pods", "Pod", "", "ns1", "web"},
		{"", "v1", "pods", "Pod", "exec", "ns1", "web"},
		{"", "v1", "pods", "Pod", "status", "ns1", "web"},
		{"apps", "v1", "deployments", "Deployment", "", "ns1", "web"},
		{"", "v1", "nodes", "Node", "", "", "node1"},
		{"", "v1", "namespaces", "Namespace", "", "", "existing"},
		{"admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", "", "", "cfg"},
		{"admissionregistration.k8s.io", "v1", "mutatingadmissionpolicies", "MutatingAdmissionPolicy", "", "", "pol"},
	}
	labelSets := []map[string]string{nil, {"app": "web"}, {"app": "db"}, {"env": "prod"}}

	cases := 0
	for rsName, rs := range ruleSets {
		for nsSelName, nsSel := range selectors {
			for objSelName, objSel := range selectors {
				hook := admissionregistrationv1.ValidatingWebhook{
					Name: "hook", Rules: rs, MatchPolicy: exact(), NamespaceSelector: nsSel, ObjectSelector: objSel,
				}
				idx := validatingIndex(hook)
				// The API server defaults unset selectors to the empty selector
				// before any webhook reaches the matchers.
				defaulted := hook
				if defaulted.NamespaceSelector == nil {
					defaulted.NamespaceSelector = &metav1.LabelSelector{}
				}
				if defaulted.ObjectSelector == nil {
					defaulted.ObjectSelector = &metav1.LabelSelector{}
				}
				accessor := apiwebhook.NewValidatingWebhookAccessor("uid", "cfg", &defaulted)

				for _, tg := range targets {
					for _, op := range []admissionregistrationv1.OperationType{create, update, deleteO, connect} {
						for _, newL := range labelSets {
							for _, oldL := range labelSets {
								cases++
								gvr := schema.GroupVersionResource{Group: tg.group, Version: tg.version, Resource: tg.resource}
								attrNS := tg.namespace
								if tg.resource == "namespaces" {
									attrNS = tg.name
								}
								// What the apiserver admits for each operation.
								var obj, old runtime.Object
								switch op {
								case create:
									obj = labelled(newL)
								case update:
									obj, old = labelled(newL), labelled(oldL)
								case deleteO:
									old = labelled(oldL)
								case connect:
									obj = &corev1.PodExecOptions{}
								}
								attr := admission.NewAttributesRecord(obj, old,
									schema.GroupVersionKind{Group: tg.group, Version: tg.version, Kind: tg.kind},
									attrNS, tg.name, gvr, tg.subresource, admission.Operation(op), nil, false, nil)

								want := apiserverCalls(t, nsMatcher, accessor, attr)

								got := idx.Matches(Request{
									Group: tg.group, Version: tg.version, Resource: tg.resource, Kind: tg.kind,
									Subresource: tg.subresource, Operation: op, Name: tg.name, Namespace: tg.namespace,
									ClusterScoped: tg.namespace == "" && tg.resource != "namespaces",
									ObjectLabels:  newL, ObjectLabelsKnown: true,
									OldObjectLabels: oldL, OldObjectLabelsKnown: true,
									NamespaceLabels: nsLabels, NamespaceLabelsKnown: true,
								})[0]

								wantVerdict := NotMatched
								if want {
									wantVerdict = Matched
								}
								require.Equalf(t, wantVerdict, got.Verdict,
									"rules=%s nsSel=%s objSel=%s target=%+v op=%s new=%v old=%v reasons=%v",
									rsName, nsSelName, objSelName, tg, op, newL, oldL, got.Reasons)
							}
						}
					}
				}
			}
		}
	}
	t.Logf("compared %d synthetic requests", cases)
	require.NotZero(t, cases)
}

// TestEquivalentMatchPolicyNeverFalselyRejects registers equivalent resources in
// the apiserver's own registry and checks that whenever Equivalent matchPolicy
// makes the apiserver call a webhook through an equivalent resource, this
// package reports Indeterminate rather than NotMatched.
func TestEquivalentMatchPolicyNeverFalselyRejects(t *testing.T) {
	registry := runtime.NewEquivalentResourceRegistry()
	appsV1 := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	extV1beta1 := schema.GroupVersionResource{Group: "apps", Version: "v1beta1", Resource: "deployments"}
	registry.RegisterKindFor(appsV1, "", schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	registry.RegisterKindFor(extV1beta1, "", schema.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "Deployment"})

	r := rule([]string{"apps"}, []string{"v1"}, []string{"deployments"}, create)
	idx := validatingIndex(admissionregistrationv1.ValidatingWebhook{Rules: []admissionregistrationv1.RuleWithOperations{r}})

	attr := admission.NewAttributesRecord(labelled(nil), nil, schema.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "Deployment"},
		"ns1", "web", extV1beta1, "", admission.Create, nil, false, nil)
	require.False(t, (&rules.Matcher{Rule: r, Attr: attr}).Matches(), "the literal request is outside the rule")

	viaEquivalent := false
	for _, eq := range registry.EquivalentResourcesFor(extV1beta1, "") {
		if eq == extV1beta1 {
			continue
		}
		equivalentAttr := admission.NewAttributesRecord(labelled(nil), nil, schema.GroupVersionKind{Group: eq.Group, Version: eq.Version, Kind: "Deployment"},
			"ns1", "web", eq, "", admission.Create, nil, false, nil)
		viaEquivalent = viaEquivalent || (&rules.Matcher{Rule: r, Attr: equivalentAttr}).Matches()
	}
	require.True(t, viaEquivalent, "the apiserver would call the webhook through apps/v1 (same group, other version)")

	got := verdict(t, idx, podRequest(func(req *Request) {
		req.Group, req.Version, req.Resource, req.Kind = "apps", "v1beta1", "deployments", "Deployment"
	}))
	require.Equal(t, Indeterminate, got.Verdict)
	require.Equal(t, []Reason{ReasonEquivalentResources}, got.Reasons)
}
