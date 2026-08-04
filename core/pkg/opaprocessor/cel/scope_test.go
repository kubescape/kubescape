package cel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rule(groups, versions, resources []string) admissionregistrationv1.NamedRuleWithOperations {
	return admissionregistrationv1.NamedRuleWithOperations{
		RuleWithOperations: admissionregistrationv1.RuleWithOperations{
			Rule: admissionregistrationv1.Rule{
				APIGroups:   groups,
				APIVersions: versions,
				Resources:   resources,
			},
		},
	}
}

func vapWithConstraints(rules ...admissionregistrationv1.NamedRuleWithOperations) *VAP {
	return &VAP{matchConstraints: &admissionregistrationv1.MatchResources{ResourceRules: rules}}
}

func obj(apiVersion, kind string) map[string]any {
	return map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": "x"}}
}

func TestVAPAppliesTo(t *testing.T) {
	// A C-0017-shaped constraint: core pods + apps workloads + batch jobs.
	pods := rule([]string{""}, []string{"v1"}, []string{"pods"})
	workloads := rule([]string{"apps"}, []string{"v1"}, []string{"deployments", "replicasets", "daemonsets", "statefulsets"})
	jobs := rule([]string{"batch"}, []string{"v1"}, []string{"jobs", "cronjobs"})
	v := vapWithConstraints(pods, workloads, jobs)

	cases := []struct {
		name       string
		apiVersion string
		kind       string
		want       bool
	}{
		{"pod matches core/pods", "v1", "Pod", true},
		{"deployment matches apps/deployments", "apps/v1", "Deployment", true},
		{"cronjob matches batch/cronjobs", "batch/v1", "CronJob", true},
		{"configmap is out of scope", "v1", "ConfigMap", false},
		{"deployment in wrong group is out of scope", "v1", "Deployment", false},
		{"pod in wrong version is out of scope", "v2", "Pod", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v.appliesTo(obj(tc.apiVersion, tc.kind)))
		})
	}
}

func TestVAPAppliesToWildcards(t *testing.T) {
	any := vapWithConstraints(rule([]string{"*"}, []string{"*"}, []string{"*"}))
	assert.True(t, any.appliesTo(obj("v1", "Pod")))
	assert.True(t, any.appliesTo(obj("apps/v1", "Deployment")))
	assert.True(t, any.appliesTo(obj("networking.k8s.io/v1", "NetworkPolicy")))
}

func TestVAPAppliesToNoConstraintsEvaluates(t *testing.T) {
	// Missing matchConstraints is a malformed-policy edge; fall back to
	// evaluating rather than silently skipping everything.
	v := &VAP{}
	assert.True(t, v.appliesTo(obj("v1", "Pod")))
}

// canonicalKinds maps a matchConstraints resource to the Kind the scanner feeds
// for it. The one silent-failure mode of appliesTo is UnsafeGuessKindToResource
// mis-guessing a plural (irregular kind or a CRD), which would quietly drop a
// resource the control should evaluate. This table is the ground truth the guess
// is checked against.
var canonicalKinds = map[string]string{
	"clusterroles":    "ClusterRole",
	"configmaps":      "ConfigMap",
	"cronjobs":        "CronJob",
	"daemonsets":      "DaemonSet",
	"deployments":     "Deployment",
	"jobs":            "Job",
	"pods":            "Pod",
	"replicasets":     "ReplicaSet",
	"roles":           "Role",
	"serviceaccounts": "ServiceAccount",
	"services":        "Service",
	"statefulsets":    "StatefulSet",
}

// TestVAPAppliesToCoversEveryBundleKind walks every policy in the embedded bundle
// and asserts appliesTo accepts an object of the Kind each constrained resource
// stands for. It is driven by the bundle, so a `make sync-vap` that introduces a
// policy for a new kind fails here (unknown resource -> add it to canonicalKinds)
// rather than silently dropping that kind at scan time once the guess is wrong.
func TestVAPAppliesToCoversEveryBundleKind(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, catalog.byName, "bundle parsed to no policies")

	for name, vap := range catalog.byName {
		if vap.matchConstraints == nil {
			continue
		}
		for _, rr := range vap.matchConstraints.ResourceRules {
			// A resource rule is a cross-product: every apiGroup x apiVersion x
			// resource it lists is in scope. Check all of them, so a rule that
			// ever lists more than one group or version is fully covered rather
			// than asserted on one arbitrary combination.
			for _, group := range defaultIfEmpty(rr.APIGroups, "") {
				if group == "*" {
					group = ""
				}
				for _, version := range defaultIfEmpty(rr.APIVersions, "v1") {
					if version == "*" {
						version = "v1"
					}
					apiVersion := version
					if group != "" {
						apiVersion = group + "/" + version
					}
					for _, res := range rr.Resources {
						if res == "*" || strings.Contains(res, "/") {
							continue // wildcard or subresource: not a scanned top-level kind
						}
						kind, ok := canonicalKinds[res]
						require.Truef(t, ok, "policy %q constrains resource %q with no canonical Kind in the test; add it to canonicalKinds and confirm UnsafeGuessKindToResource maps that Kind back to %q", name, res, res)
						assert.Truef(t, vap.appliesTo(obj(apiVersion, kind)),
							"policy %q constrains %q but appliesTo rejects a %s %s; UnsafeGuessKindToResource likely mis-guessed the plural", name, res, apiVersion, kind)
					}
				}
			}
		}
	}
}

// defaultIfEmpty keeps the loop above total: a rule that omits apiGroups or
// apiVersions still yields one combination to assert on.
func defaultIfEmpty(xs []string, fallback string) []string {
	if len(xs) > 0 {
		return xs
	}
	return []string{fallback}
}

func TestVAPAppliesToExcludeRules(t *testing.T) {
	v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
		ResourceRules:        []admissionregistrationv1.NamedRuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"pods", "configmaps"})},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{rule([]string{""}, []string{"v1"}, []string{"configmaps"})},
	}}
	assert.True(t, v.appliesTo(obj("v1", "Pod")))
	assert.False(t, v.appliesTo(obj("v1", "ConfigMap")), "excluded resource must not apply")
}

// withOps returns a copy of the rule constrained to the given operations.
func withOps(r admissionregistrationv1.NamedRuleWithOperations, ops ...admissionregistrationv1.OperationType) admissionregistrationv1.NamedRuleWithOperations {
	r.Operations = ops
	return r
}

// TestVAPAppliesToOperations pins the operation side of rule matching: the scan
// models every resource as a CREATE, so a rule that fires only on other
// operations must not match — at admission that policy would never be handed
// the object we are scanning.
func TestVAPAppliesToOperations(t *testing.T) {
	pods := rule([]string{""}, []string{"v1"}, []string{"pods"})

	cases := []struct {
		name string
		ops  []admissionregistrationv1.OperationType
		want bool
	}{
		{"CREATE matches", []admissionregistrationv1.OperationType{admissionregistrationv1.Create}, true},
		{"CREATE and UPDATE matches (the bundle's shape)", []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}, true},
		{"wildcard matches", []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll}, true},
		{"UPDATE-only does not match a modeled CREATE", []admissionregistrationv1.OperationType{admissionregistrationv1.Update}, false},
		{"DELETE-only does not match a modeled CREATE", []admissionregistrationv1.OperationType{admissionregistrationv1.Delete}, false},
		{"no operations (malformed) falls back to matching", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := vapWithConstraints(withOps(pods, tc.ops...))
			assert.Equal(t, tc.want, v.appliesTo(obj("v1", "Pod")))
		})
	}

	t.Run("an exclusion scoped to UPDATE does not exempt the modeled CREATE", func(t *testing.T) {
		v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
			ResourceRules:        []admissionregistrationv1.NamedRuleWithOperations{withOps(pods, admissionregistrationv1.Create)},
			ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{withOps(pods, admissionregistrationv1.Update)},
		}}
		assert.True(t, v.appliesTo(obj("v1", "Pod")), "the exclusion only covers UPDATE, so the CREATE we model is still matched")
	})
}

// TestBundleControlRulesAllMatchModeledCreate is the safety case for honoring
// operations, and it is the assertion the kind sweep cannot make: that sweep
// skips subresources, which is exactly where the bundle's non-CREATE rules
// live. Every controlId-bearing policy must have rules the modeled CREATE
// matches, otherwise that control silently loses those resources at scan time
// (an exclusion is only Debug-logged, so there is no signal in the output). A
// `make sync-vap` introducing an UPDATE-only control fails here instead.
func TestBundleControlRulesAllMatchModeledCreate(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, catalog.byControl)

	for id, vap := range catalog.byControl {
		if vap.matchConstraints == nil {
			continue
		}
		for _, rr := range vap.matchConstraints.ResourceRules {
			assert.Truef(t, matchesOperation(rr.Operations),
				"control %q has a rule scoped to %v, which the modeled CREATE will not match; that control silently loses those resources", id, rr.Operations)
		}
	}
}

// TestBundleUsesNoUnevaluatedScoping records the other half of the safety case:
// the scoping knobs this package evaluates or refuses are all unused by the
// vendored bundle today, so none of it changes a shipped control's behaviour.
// When a sync does introduce one, this test is the notice that the handling
// stopped being theoretical and wants checking against a real policy.
func TestBundleUsesNoUnevaluatedScoping(t *testing.T) {
	catalog, err := getVAPCatalog()
	require.NoError(t, err)

	for name, vap := range catalog.byName {
		if vap.matchConstraints == nil {
			continue
		}
		assert.Falsef(t, selectorNarrows(vap.matchConstraints.NamespaceSelector),
			"policy %q now uses a namespaceSelector: loadVAP refuses it, so confirm a control-wide skip is the outcome you want", name)
		assert.Falsef(t, selectorNarrows(vap.matchConstraints.ObjectSelector),
			"policy %q now uses an objectSelector: appliesTo evaluates it against the object's labels, so confirm that matches the policy's intent", name)

		rules := append(append([]admissionregistrationv1.NamedRuleWithOperations{}, vap.matchConstraints.ResourceRules...), vap.matchConstraints.ExcludeResourceRules...)
		for _, rr := range rules {
			assert.Emptyf(t, rr.ResourceNames,
				"policy %q now uses resourceNames: appliesTo matches it against metadata.name, so confirm the scanned manifests carry the names it expects", name)
		}
	}
}

func TestVAPAppliesToObjectSelector(t *testing.T) {
	pods := rule([]string{""}, []string{"v1"}, []string{"pods"})
	labelled := func(labels map[string]any) map[string]any {
		o := obj("v1", "Pod")
		o["metadata"].(map[string]any)["labels"] = labels
		return o
	}

	t.Run("matchLabels narrows to the labelled object", func(t *testing.T) {
		v := vapWithConstraints(pods)
		v.matchConstraints.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}

		assert.True(t, v.appliesTo(labelled(map[string]any{"app": "web"})))
		assert.False(t, v.appliesTo(labelled(map[string]any{"app": "db"})), "a non-matching label must put the object out of scope")
		assert.False(t, v.appliesTo(obj("v1", "Pod")), "an unlabelled object cannot satisfy matchLabels")
	})

	t.Run("matchExpressions are honored", func(t *testing.T) {
		v := vapWithConstraints(pods)
		v.matchConstraints.ObjectSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "skip", Operator: metav1.LabelSelectorOpDoesNotExist}},
		}

		assert.True(t, v.appliesTo(obj("v1", "Pod")))
		assert.False(t, v.appliesTo(labelled(map[string]any{"skip": "true"})), "an object carrying the exempting label must be out of scope")
	})

	t.Run("nil and empty selectors match everything", func(t *testing.T) {
		// The nil case is the one that bites: LabelSelectorAsSelector maps nil to
		// "match nothing", the opposite of what an omitted selector means.
		v := vapWithConstraints(pods)
		assert.True(t, v.appliesTo(obj("v1", "Pod")), "an omitted objectSelector must not narrow anything")

		v.matchConstraints.ObjectSelector = &metav1.LabelSelector{}
		assert.True(t, v.appliesTo(obj("v1", "Pod")))
		assert.True(t, v.appliesTo(labelled(map[string]any{"app": "web"})))
	})
}

// TestVAPAppliesToResourceNames covers the third narrowing knob on a resource
// rule. Ignoring it would evaluate every object of the kind against a policy
// admission only ever hands one named object, which is a false violation on
// objects admission exempts.
func TestVAPAppliesToResourceNames(t *testing.T) {
	named := func(resourceNames ...string) admissionregistrationv1.NamedRuleWithOperations {
		r := rule([]string{""}, []string{"v1"}, []string{"pods"})
		r.ResourceNames = resourceNames
		return r
	}
	podNamed := func(name string) map[string]any {
		o := obj("v1", "Pod")
		o["metadata"].(map[string]any)["name"] = name
		return o
	}

	t.Run("only the named resource is in scope", func(t *testing.T) {
		v := vapWithConstraints(named("coredns"))
		assert.True(t, v.appliesTo(podNamed("coredns")))
		assert.False(t, v.appliesTo(podNamed("nginx")), "a rule naming one pod must not pull in every pod")
	})

	t.Run("an empty resourceNames list matches every name", func(t *testing.T) {
		v := vapWithConstraints(named())
		assert.True(t, v.appliesTo(podNamed("anything")))
	})

	t.Run("a named exclusion exempts only that resource", func(t *testing.T) {
		v := &VAP{matchConstraints: &admissionregistrationv1.MatchResources{
			ResourceRules:        []admissionregistrationv1.NamedRuleWithOperations{named()},
			ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{named("kube-proxy")},
		}}
		assert.False(t, v.appliesTo(podNamed("kube-proxy")))
		assert.True(t, v.appliesTo(podNamed("nginx")))
	})

	t.Run("a generateName-only manifest does not match a named rule", func(t *testing.T) {
		// Admission sees no name either at that point, so it would not match.
		o := obj("v1", "Pod")
		delete(o["metadata"].(map[string]any), "name")
		assert.False(t, vapWithConstraints(named("coredns")).appliesTo(o))
	})
}
