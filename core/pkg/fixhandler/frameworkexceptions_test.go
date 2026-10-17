package fixhandler

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frameworkExceptedRule is a failed rule with a fix whose finding is excepted
// by a framework-scoped exception, the way a v0.0.315+ report records it: the
// rule and control keep their raw failed status and the exception is attached
// to the rule.
func frameworkExceptedRule(framework, controlID, path, value string) resourcesresults.ResourceAssociatedRule {
	rule := failedRuleWithFix(path, value)
	rule.Exception = []armotypes.PostureExceptionPolicy{{
		PortalBase:      armotypes.PortalBase{Name: "exception-for-" + framework},
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: framework, ControlID: controlID}},
	}}
	return rule
}

func frameworkSummaries(frameworks map[string][]string) []reportsummary.FrameworkSummary {
	var summaries []reportsummary.FrameworkSummary
	for name, controlIDs := range frameworks {
		controls := reportsummary.ControlSummaries{}
		for _, id := range controlIDs {
			controls[id] = reportsummary.ControlSummary{ControlID: id}
		}
		summaries = append(summaries, reportsummary.FrameworkSummary{Name: name, Controls: controls})
	}
	return summaries
}

func TestFix_FrameworkScopedExceptionSuppressesFlaggedControl(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "pod.yaml", "apiVersion: v1\nkind: Pod\n")
	rel, err := filepath.Rel(dir, manifest)
	require.NoError(t, err)
	res := buildResource(t, dir, rel, "Pod", "hn-pod", 0)

	const (
		hostNetwork = "C-0041"
		immutableFS = "C-0017"
	)
	newResults := func(withException bool) []resourcesresults.Result {
		hostNetworkRule := failedRuleWithFix("spec.hostNetwork", "false")
		if withException {
			hostNetworkRule = frameworkExceptedRule("NSA", hostNetwork, "spec.hostNetwork", "false")
		}
		return []resourcesresults.Result{{
			ResourceID:  res.GetID(),
			RawResource: res,
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				failedControl(hostNetwork, "HostNetwork access", hostNetworkRule),
				failedControl(immutableFS, "Immutable container filesystem",
					failedRuleWithFix("spec.containers[0].securityContext.readOnlyRootFilesystem", "true")),
			},
		}}
	}

	tests := []struct {
		name          string
		frameworks    map[string][]string
		exception     bool
		wantFixed     int
		wantFlagged   int
		wantFixedByID []string
	}{
		{
			name:          "exception for the scanned framework suppresses its control only",
			frameworks:    map[string][]string{"NSA": {hostNetwork, immutableFS}},
			exception:     true,
			wantFixed:     1,
			wantFlagged:   1,
			wantFixedByID: []string{immutableFS},
		},
		{
			name:          "exception for a framework that was not scanned suppresses nothing",
			frameworks:    map[string][]string{"MITRE": {hostNetwork, immutableFS}},
			exception:     true,
			wantFixed:     2,
			wantFlagged:   2,
			wantFixedByID: []string{hostNetwork, immutableFS},
		},
		{
			name:          "control also evaluated by an unexcepted framework stays flagged",
			frameworks:    map[string][]string{"NSA": {hostNetwork, immutableFS}, "MITRE": {hostNetwork, immutableFS}},
			exception:     true,
			wantFixed:     2,
			wantFlagged:   2,
			wantFixedByID: []string{hostNetwork, immutableFS},
		},
		{
			name:          "control the unexcepted framework does not evaluate is suppressed",
			frameworks:    map[string][]string{"NSA": {hostNetwork, immutableFS}, "MITRE": {immutableFS}},
			exception:     true,
			wantFixed:     1,
			wantFlagged:   1,
			wantFixedByID: []string{immutableFS},
		},
		{
			name:          "without exceptions everything is flagged",
			frameworks:    map[string][]string{"NSA": {hostNetwork, immutableFS}},
			wantFixed:     2,
			wantFlagged:   2,
			wantFixedByID: []string{hostNetwork, immutableFS},
		},
		{
			name:          "report without framework context keeps the finding",
			exception:     true,
			wantFixed:     2,
			wantFlagged:   2,
			wantFixedByID: []string{hostNetwork, immutableFS},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerForResources(dir, newResults(tt.exception), nil, false)
			h.reportObj.SummaryDetails.Frameworks = frameworkSummaries(tt.frameworks)

			selected, total := h.controlSelectionCounts()
			assert.Equal(t, tt.wantFlagged, total, "flagged control instances")
			assert.Equal(t, tt.wantFlagged, selected)

			rtf := h.PrepareResourcesToFix(context.Background())
			require.Len(t, rtf, 1)
			assert.Equal(t, tt.wantFixed, h.FixedControlsCount())
			fixed := make([]string, 0)
			for _, c := range h.fixedControls {
				fixed = append(fixed, c.ControlID)
			}
			assert.ElementsMatch(t, tt.wantFixedByID, fixed)
			assert.Empty(t, h.UnfixedControls())

			planned := false
			for expression := range rtf[0].YamlExpressions {
				if strings.Contains(expression, "hostNetwork") {
					planned = true
				}
			}
			assert.Equal(t, containsString(tt.wantFixedByID, hostNetwork), planned, "a suppressed finding must not produce a fix")
		})
	}
}

func TestFix_ResourceWhoseOnlyFindingIsExceptedIsNotFixed(t *testing.T) {
	dir := t.TempDir()
	manifest := writeManifest(t, dir, "pod.yaml", "apiVersion: v1\nkind: Pod\n")
	rel, err := filepath.Rel(dir, manifest)
	require.NoError(t, err)
	res := buildResource(t, dir, rel, "Pod", "hn-pod", 0)

	h := newHandlerForResources(dir, []resourcesresults.Result{{
		ResourceID:  res.GetID(),
		RawResource: res,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			failedControl("C-0041", "HostNetwork access", frameworkExceptedRule("NSA", "C-0041", "spec.hostNetwork", "false")),
		},
	}}, nil, false)
	h.reportObj.SummaryDetails.Frameworks = frameworkSummaries(map[string][]string{"NSA": {"C-0041"}})

	selected, total := h.controlSelectionCounts()
	assert.Zero(t, total)
	assert.Zero(t, selected)
	assert.Empty(t, h.PrepareResourcesToFix(context.Background()))
	assert.Zero(t, h.FixedControlsCount())
	assert.Empty(t, h.UnfixedControls())
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
