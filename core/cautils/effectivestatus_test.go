package cautils

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

func frameworkExceptionFor(framework, controlID string, actions ...armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
	return armotypes.PostureExceptionPolicy{
		PortalBase:      armotypes.PortalBase{Name: "exception-for-" + framework},
		Actions:         actions,
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: framework, ControlID: controlID}},
	}
}

func summaryWith(frameworks map[string][]string) *reportsummary.SummaryDetails {
	summary := &reportsummary.SummaryDetails{}
	for name, ids := range frameworks {
		controls := reportsummary.ControlSummaries{}
		for _, id := range ids {
			controls[id] = reportsummary.ControlSummary{ControlID: id}
		}
		summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: controls})
	}
	return summary
}

func controlWith(controlID string, rules ...resourcesresults.ResourceAssociatedRule) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID:               controlID,
		Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: rules,
	}
}

func failedRule(name string, exceptions ...armotypes.PostureExceptionPolicy) resourcesresults.ResourceAssociatedRule {
	return resourcesresults.ResourceAssociatedRule{Name: name, Status: apis.StatusFailed, Exception: exceptions}
}

func TestControlFilters(t *testing.T) {
	summary := summaryWith(map[string][]string{"NSA": {"C-1", "C-2"}, "MITRE": {"C-2"}})

	require.Equal(t, []string{"NSA"}, ControlFilters(summary, "C-1").FrameworkNames)
	require.ElementsMatch(t, []string{"NSA", "MITRE"}, ControlFilters(summary, "C-2").FrameworkNames)
	require.Empty(t, ControlFilters(summary, "C-3").FrameworkNames, "a control no framework lists has no framework context")
	require.Empty(t, ControlFilters(nil, "C-1").FrameworkNames)
}

func TestControlStatus(t *testing.T) {
	summary := summaryWith(map[string][]string{"NSA": {"C-1"}, "MITRE": {"C-1"}})
	excepted := func(framework string) resourcesresults.ResourceAssociatedControl {
		return controlWith("C-1", failedRule("r", frameworkExceptionFor(framework, "C-1", armotypes.Disable)))
	}

	t.Run("excepted in every scanned framework", func(t *testing.T) {
		only := summaryWith(map[string][]string{"NSA": {"C-1"}})
		control := excepted("NSA")
		status := ControlStatus(only, &control)
		require.True(t, status.IsPassed())
		require.Equal(t, apis.SubStatusException, status.GetSubStatus())
		require.Equal(t, apis.StatusFailed, control.Status.InnerStatus, "the recorded status is not rewritten")
	})
	t.Run("excepted in one of two frameworks", func(t *testing.T) {
		control := excepted("NSA")
		require.True(t, ControlStatus(summary, &control).IsFailed())
	})
	t.Run("exception for an unscanned framework", func(t *testing.T) {
		control := excepted("CIS")
		require.True(t, ControlStatus(summary, &control).IsFailed())
	})
	t.Run("exception for another control", func(t *testing.T) {
		control := controlWith("C-1", failedRule("r", frameworkExceptionFor("NSA", "C-2", armotypes.Disable)))
		require.True(t, ControlStatus(summaryWith(map[string][]string{"NSA": {"C-1"}}), &control).IsFailed())
	})
	t.Run("alertOnly exception acknowledges but does not suppress", func(t *testing.T) {
		control := controlWith("C-1", failedRule("r", frameworkExceptionFor("NSA", "C-1", armotypes.AlertOnly)))
		require.True(t, ControlStatus(summaryWith(map[string][]string{"NSA": {"C-1"}}), &control).IsFailed())
	})
	t.Run("without exceptions the recorded status is kept as is", func(t *testing.T) {
		for _, recorded := range []apis.StatusInfo{
			{InnerStatus: apis.StatusPassed},
			{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusNotEvaluated, InnerInfo: "timed out"},
			{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview},
			{InnerStatus: apis.StatusFailed},
		} {
			control := controlWith("C-1", failedRule("r"))
			control.Status = recorded
			status := ControlStatus(summary, &control)
			require.Equal(t, recorded.InnerStatus, status.Status())
			require.Equal(t, recorded.SubStatus, status.GetSubStatus())
			require.Equal(t, recorded.InnerInfo, status.Info())
		}
	})
	t.Run("one excepted rule among two failing rules", func(t *testing.T) {
		only := summaryWith(map[string][]string{"NSA": {"C-1"}})
		control := controlWith("C-1", failedRule("a", frameworkExceptionFor("NSA", "C-1", armotypes.Disable)), failedRule("b"))
		require.True(t, ControlStatus(only, &control).IsFailed())
		failing := FailedRules(only, control)
		require.Len(t, failing.ResourceAssociatedRules, 1)
		require.Equal(t, "b", failing.ResourceAssociatedRules[0].Name)
		require.Len(t, control.ResourceAssociatedRules, 2, "the control passed in is not modified")
	})
}

func TestRuleStatus(t *testing.T) {
	rule := failedRule("r", frameworkExceptionFor("NSA", "C-1", armotypes.Disable))
	require.True(t, RuleStatus(summaryWith(map[string][]string{"NSA": {"C-1"}}), "C-1", &rule).IsPassed())
	require.True(t, RuleStatus(summaryWith(map[string][]string{"MITRE": {"C-1"}}), "C-1", &rule).IsFailed())
	require.True(t, RuleStatus(nil, "C-1", &rule).IsFailed(), "without framework context a framework-scoped exception does not apply")
	require.Equal(t, apis.StatusFailed, rule.Status)
}

func TestResourceStatusAndControlIDsByStatus(t *testing.T) {
	summary := summaryWith(map[string][]string{"NSA": {"C-1", "C-2"}})
	result := resourcesresults.Result{AssociatedControls: []resourcesresults.ResourceAssociatedControl{
		controlWith("C-1", failedRule("a", frameworkExceptionFor("NSA", "C-1", armotypes.Disable))),
		controlWith("C-2", failedRule("b")),
	}}

	require.True(t, ResourceStatus(summary, &result).IsFailed())
	ids := ControlIDsByStatus(summary, &result)
	require.Equal(t, []string{"C-1"}, ids.GetItems(apis.StatusPassed))
	require.Equal(t, []string{"C-2"}, ids.GetItems(apis.StatusFailed))

	result.AssociatedControls = result.AssociatedControls[:1]
	status := ResourceStatus(summary, &result)
	require.True(t, status.IsPassed())
	require.Equal(t, apis.SubStatusException, status.GetSubStatus())
	require.True(t, ResourceStatus(&reportsummary.SummaryDetails{}, &result).IsFailed())
}

func TestSettleControlStatus(t *testing.T) {
	summary := summaryWith(map[string][]string{"NSA": {"C-1"}})

	control := controlWith("C-1", failedRule("a", frameworkExceptionFor("NSA", "C-1", armotypes.Disable)))
	SettleControlStatus(summary, &control)
	require.Equal(t, apis.StatusPassed, control.Status.InnerStatus)
	require.Equal(t, apis.SubStatusException, control.Status.SubStatus)
	require.Equal(t, apis.StatusFailed, control.ResourceAssociatedRules[0].Status, "rules keep the raw evaluation")
	require.Len(t, control.ResourceAssociatedRules[0].Exception, 1)

	other := controlWith("C-1", failedRule("a", frameworkExceptionFor("MITRE", "C-1", armotypes.Disable)))
	SettleControlStatus(summary, &other)
	require.Equal(t, apis.StatusFailed, other.Status.InnerStatus)

	plain := controlWith("C-1", failedRule("a"))
	SettleControlStatus(summary, &plain)
	require.Equal(t, apis.StatusInfo{InnerStatus: apis.StatusFailed}, plain.Status)
}
