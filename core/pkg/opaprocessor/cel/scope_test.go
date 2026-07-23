package cel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
	"pods":            "Pod",
	"deployments":     "Deployment",
	"replicasets":     "ReplicaSet",
	"daemonsets":      "DaemonSet",
	"statefulsets":    "StatefulSet",
	"jobs":            "Job",
	"cronjobs":        "CronJob",
	"serviceaccounts": "ServiceAccount",
	"services":        "Service",
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
