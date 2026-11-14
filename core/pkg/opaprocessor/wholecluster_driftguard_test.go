package opaprocessor

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Drift guard for the whole-cluster classification (see #2871, #3144, #3150).
//
// A control that resolves a reference into another namespace has to be
// evaluated against the whole cluster; if it is missing from
// wholeClusterControlIDsFallback (or the library's requiresWholeClusterInput
// attribute) streaming silently evaluates it per namespace and reports false
// results.
//
// Whether a Rego rule really joins across namespaces cannot be decided
// mechanically: "metadata.namespace" is read by same-namespace joins and by
// plain default-namespace checks alike. So the guard is a review gate rather
// than a classifier. It selects the controls that *could* need whole-cluster
// input with a structural check on the parsed Rego, and requires each one to
// be either covered or explicitly recorded below as reviewed and
// same-namespace. A new candidate fails the test until someone decides which.

// sameNamespaceReviewed lists controls of the pinned regolibrary that look like
// candidates but were reviewed and only join objects within one namespace (or
// merely test a namespace name). Add an entry only after reading the rule.
var sameNamespaceReviewed = map[string]string{
	"C-0030": "network policy matched to workload via is_same_namespace",
	"C-0061": "checks the literal 'default' namespace of each object",
	"C-0212": "checks the literal 'default' namespace of each object",
	"C-0255": "workload and Secret joined via is_same_namespace",
	"C-0256": "workload, Service and Ingress joined within one namespace",
	"C-0257": "workload and PVC joined via is_same_namespace",
	"C-0258": "workload and ConfigMap joined via is_same_namespace",
	"C-0260": "network policy and workload joined via is_same_namespace",
	"C-0274": "workload and Service joined via is_same_namespace",
	"C-0293": "Service and workload joined in the Service's own namespace",
	"C-0298": "Ingress backend resolved in the Ingress's own namespace",
	"C-0299": "NetworkPolicy podSelector resolved in its own namespace",
	"C-0300": "HPA scaleTargetRef resolved in the HPA's own namespace",
}

// regoReadsNamespaceField reports whether the Rego module reads a namespace
// that is not plainly "input.metadata.namespace" of one object: either a
// "<x>.namespace" reference whose parent is not "metadata", or an
// object.get(<x>, "namespace", ...) lookup. Both are how rules obtain the
// namespace of a referenced object (backendRef.namespace, subject.namespace,
// a namespace argument) or compare the namespaces of two objects.
func regoReadsNamespaceField(t *testing.T, name, src string) bool {
	t.Helper()
	module, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		var v0Err error
		module, v0Err = ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV0})
		require.NoError(t, v0Err, "parse %s (tried v1: %v, v0: %v)", name, err, v0Err)
	}

	found := false
	ast.WalkRefs(module, func(ref ast.Ref) bool {
		if n := len(ref); n >= 2 && isString(ref[n-1], "namespace") && !isString(ref[n-2], "metadata") {
			found = true
		}
		return found
	})
	ast.WalkTerms(module, func(term *ast.Term) bool {
		if call, ok := term.Value.(ast.Call); ok && len(call) == 4 &&
			call[0].String() == "object.get" && isString(call[2], "namespace") {
			found = true
		}
		return found
	})
	return found
}

func isString(term *ast.Term, want string) bool {
	s, ok := term.Value.(ast.String)
	return ok && string(s) == want
}

// ruleIsCrossNamespaceCandidate is true for a rule that is not already handled
// by a resourcesAggregator and reads a namespace field as described above. The
// number of matched kinds is deliberately not part of the test: a rule that
// matches a single kind can still resolve another object of that kind through a
// namespace reference (a Widget naming the namespace of a target Widget), and
// namespace-partitioned streaming splits those objects just the same.
func ruleIsCrossNamespaceCandidate(t *testing.T, rule *reporthandling.PolicyRule) bool {
	t.Helper()
	if rule == nil {
		return false
	}
	if rule.RuleLanguage != "" && rule.RuleLanguage != reporthandling.RegoLanguage && rule.RuleLanguage != reporthandling.RegoLanguage2 {
		return false
	}
	if _, aggregated := rule.Attributes["resourcesAggregator"]; aggregated {
		return false
	}
	return regoReadsNamespaceField(t, rule.Name, rule.Rule)
}

// uncoveredCandidates returns, sorted, the candidate control IDs that are
// neither whole-cluster controls nor recorded as reviewed. Duplicate candidates
// are deduplicated.
func uncoveredCandidates(candidates []string, wholeCluster func(string) bool, reviewed map[string]string) []string {
	seen := make(map[string]struct{})
	var uncovered []string
	for _, id := range candidates {
		if _, ok := reviewed[id]; ok || wholeCluster(id) {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uncovered = append(uncovered, id)
	}
	sort.Strings(uncovered)
	return uncovered
}

// TestWholeClusterClassification_PinnedLibraryHasNoUnreviewedCandidates fails
// when the pinned regolibrary contains a control that may resolve references
// across namespaces and is neither deferred to whole-cluster evaluation nor
// reviewed as same-namespace.
func TestWholeClusterClassification_PinnedLibraryHasNoUnreviewedCandidates(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(regolibraryDir(t), "controls", "C-*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	controls := map[string]*reporthandling.Control{}
	var candidates []string
	for _, file := range files {
		control := loadLibraryControl(t, filepath.Base(file))
		controls[control.ControlID] = &control
		for i := range control.Rules {
			if ruleIsCrossNamespaceCandidate(t, &control.Rules[i]) {
				candidates = append(candidates, control.ControlID)
				break
			}
		}
	}
	require.NotEmpty(t, candidates, "the guard found no candidates; the detector is broken")

	uncovered := uncoveredCandidates(candidates,
		func(id string) bool { return controlRequiresWholeClusterInput(controls[id]) },
		sameNamespaceReviewed)

	var report []string
	for _, id := range uncovered {
		report = append(report, fmt.Sprintf("%s (%s)", id, controls[id].Name))
	}
	assert.Empty(t, uncovered, "controls may resolve references across namespaces but are not evaluated against the whole cluster: %s.\n"+
		"Read their rules. If they join across namespaces, add the ID to wholeClusterControlIDsFallback (or set the requiresWholeClusterInput "+
		"attribute in regolibrary); if they stay within one namespace, add it to sameNamespaceReviewed with the reason.",
		strings.Join(report, ", "))

	// Known whole-cluster controls must still be detected, or the detector no
	// longer sees the rules it exists for.
	for _, id := range []string{"C-0261", "C-0266", "C-0267", "C-0272", "C-0302"} {
		assert.Contains(t, candidates, id, "detector no longer recognises %s as a cross-namespace candidate", id)
		assert.True(t, controlRequiresWholeClusterInput(controls[id]), "%s must be a whole-cluster control", id)
	}

	// Stale controls must not linger in sameNamespaceReviewed.
	for id := range sameNamespaceReviewed {
		assert.Contains(t, controls, id, "control %s in sameNamespaceReviewed does not exist in pinned regolibrary", id)
	}
}

// TestWholeClusterClassification_DetectorBehaviour exercises the detector and
// the coverage check on small synthetic rules, including a control that is
// deliberately left uncovered.
func TestWholeClusterClassification_DetectorBehaviour(t *testing.T) {
	const crossRef = `package armo_builtins
import rego.v1
deny contains msga if {
	route := input[_]
	ref := route.spec.rules[_].backendRefs[_]
	ns := object.get(ref, "namespace", "default")
	svc := input[_]
	svc.metadata.namespace == ns
	msga := {}
}`
	const sameNamespaceOnly = `package armo_builtins
import rego.v1
deny contains msga if {
	pod := input[_]
	pod.metadata.namespace == "default"
	msga := {}
}`
	const sameKindCrossRef = `package armo_builtins
import rego.v1
deny contains msga if {
	widget := input[_]
	widget.kind == "Widget"
	target := input[_]
	target.kind == "Widget"
	target.metadata.namespace == widget.spec.target.namespace
	target.metadata.name == widget.spec.target.name
	msga := {}
}`
	match := func(kinds ...string) []reporthandling.RuleMatchObjects {
		return []reporthandling.RuleMatchObjects{{Resources: kinds}}
	}

	tests := []struct {
		name string
		rule reporthandling.PolicyRule
		want bool
	}{
		{"namespace from a reference field across two kinds", reporthandling.PolicyRule{Rule: crossRef, Match: match("HTTPRoute", "Service")}, true},
		{"metadata.namespace only", reporthandling.PolicyRule{Rule: sameNamespaceOnly, Match: match("Pod", "Service")}, false},
		{"namespace from a reference field within a single kind", reporthandling.PolicyRule{Rule: sameKindCrossRef, Match: match("Widget")}, true},
		{"namespace from a reference field, one kind per match entry", reporthandling.PolicyRule{
			Rule:  crossRef,
			Match: []reporthandling.RuleMatchObjects{{Resources: []string{"HTTPRoute"}}, {Resources: []string{"Service"}}},
		}, true},
		{"metadata.namespace only, single kind", reporthandling.PolicyRule{Rule: sameNamespaceOnly, Match: match("Pod")}, false},
		{"already aggregated", reporthandling.PolicyRule{
			PortalBase: armotypes.PortalBase{
				Attributes: map[string]interface{}{"resourcesAggregator": "x"},
			},
			Rule:  crossRef,
			Match: match("HTTPRoute", "Service"),
		}, false},
		{"cel rule is skipped", reporthandling.PolicyRule{
			RuleLanguage: reporthandling.CELLanguage,
			Rule:         "object.spec.replicas > 1",
			Match:        match("Deployment"),
		}, false},
		{"rego v0 syntax without rego.v1", reporthandling.PolicyRule{
			Rule: `package armo_builtins
default allow = false
allow {
	ref := input[_].spec.rules[_].backendRefs[_]
	ns := ref.namespace
	ns == "default"
}`,
			Match: match("HTTPRoute"),
		}, true},
		{"rego lowercase language tag is evaluated", reporthandling.PolicyRule{
			RuleLanguage: reporthandling.RegoLanguage2,
			Rule:         crossRef,
			Match:        match("HTTPRoute", "Service"),
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ruleIsCrossNamespaceCandidate(t, &tt.rule))
		})
	}

	// "C-UNCOVERED" is neither whole-cluster nor reviewed: it must be reported, and duplicate candidates deduplicated.
	wholeCluster := func(id string) bool { return id == "C-COVERED" }
	got := uncoveredCandidates([]string{"C-UNCOVERED", "C-UNCOVERED", "C-COVERED", "C-REVIEWED"}, wholeCluster, map[string]string{"C-REVIEWED": "same namespace"})
	assert.Equal(t, []string{"C-UNCOVERED"}, got)
}
