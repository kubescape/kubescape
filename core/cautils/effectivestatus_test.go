package cautils

import (
	"encoding/json"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedEffectiveStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		names  []string
		scope  string
		failed bool
	}{
		{"no context", nil, "NSA", true},
		{"single", []string{"NSA"}, "NSA", false},
		{"partial", []string{"NSA", "MITRE"}, "NSA", true},
		{"reverse", []string{"MITRE", "NSA"}, "NSA", true},
		{"global", []string{"NSA", "MITRE"}, "", false},
		{"case insensitive", []string{"NSA"}, "nsa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary := reportsummary.SummaryDetails{}
			for _, name := range tc.names {
				summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}})
			}
			// An unrelated framework must not become part of C-0034's view.
			summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: "other", Controls: reportsummary.ControlSummaries{"C-0286": {ControlID: "C-0286"}}})
			rule := resourcesresults.ResourceAssociatedRule{Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tc.scope, ControlID: "C-0034", RuleName: "R1"}}}}}
			result := resourcesresults.Result{AssociatedControls: []resourcesresults.ResourceAssociatedControl{{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{rule}}}}
			before, err := json.Marshal(result)
			require.NoError(t, err)
			for i := 0; i < 2; i++ {
				assert.Equal(t, tc.failed, ResourceStatus(&summary, &result).IsFailed())
				lists := ControlIDsByStatus(&summary, &result)
				assert.Equal(t, 1, lists.Len())
				assert.Equal(t, tc.failed, lists.Failed() == 1)
				assert.Equal(t, !tc.failed, lists.Passed() == 1)
				status := ControlStatus(&summary, &result.AssociatedControls[0])
				assert.Equal(t, tc.failed, status.IsFailed())
				if !tc.failed {
					assert.Equal(t, apis.SubStatusException, status.GetSubStatus())
				}
				assert.Equal(t, tc.failed, RuleStatus(&summary, "C-0034", &result.AssociatedControls[0].ResourceAssociatedRules[0]).IsFailed())
				after, err := json.Marshal(result)
				require.NoError(t, err)
				assert.JSONEq(t, string(before), string(after))
				require.NoError(t, json.Unmarshal(after, &result))
			}
			result.AssociatedControls[0].ResourceAssociatedRules = append(result.AssociatedControls[0].ResourceAssociatedRules, resourcesresults.ResourceAssociatedRule{Name: "R2", Status: apis.StatusFailed})
			assert.True(t, ControlStatus(&summary, &result.AssociatedControls[0]).IsFailed(), "unexcepted rule remains failed")
		})
	}
}

func TestFrameworkScopedLegacyTupleCorrelation(t *testing.T) {
	summary := reportsummary.SummaryDetails{Frameworks: []reportsummary.FrameworkSummary{{Name: "MITRE", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}}}}
	rule := resourcesresults.ResourceAssociatedRule{Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}, {FrameworkName: "MITRE", ControlID: "C-other", RuleName: "R1"}, {FrameworkName: "MITRE", ControlID: "C-0034", RuleName: "R2"}}}}}
	assert.True(t, RuleStatus(&summary, "C-0034", &rule).IsFailed())
	control := resourcesresults.ResourceAssociatedControl{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{rule}}
	assert.True(t, ControlStatus(&summary, &control).IsFailed())
}

func TestFrameworkScopedUnchangedCachedControl(t *testing.T) {
	for _, sub := range []apis.ScanningSubStatus{apis.SubStatusManualReview, apis.SubStatusRequiresReview, apis.SubStatusConfiguration} {
		control := resourcesresults.ResourceAssociatedControl{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: sub}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "R1", Status: apis.StatusFailed}}}
		status := ControlStatus(nil, &control)
		assert.True(t, status.IsSkipped())
		assert.Equal(t, sub, status.GetSubStatus())
	}
}

func TestFrameworkScopedPreservesIncompleteEvaluation(t *testing.T) {
	rule := resourcesresults.ResourceAssociatedRule{Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{{PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-0034", RuleName: "R1"}}}}}
	for _, sub := range []apis.ScanningSubStatus{apis.SubStatusNotEvaluated, apis.SubStatusIncompleteCoverage, apis.SubStatusUnknown} {
		control := resourcesresults.ResourceAssociatedControl{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: sub}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{rule}}
		status := ControlStatus(nil, &control)
		assert.True(t, status.IsSkipped())
		assert.Equal(t, sub, status.GetSubStatus())
	}
}
