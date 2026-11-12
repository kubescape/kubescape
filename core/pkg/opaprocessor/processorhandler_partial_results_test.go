package opaprocessor

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A broken rule no longer fails the scan: the control is reported as not
// evaluated, with the rule's error as the reason, and the rest of the session
// is finalized as usual.
func TestProcessRulesListener_BrokenRuleSkipsControlWithReason(t *testing.T) {
	session, control := brokenRuleSession()
	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	err := processor.ProcessRulesListener(context.Background(), nil)

	require.NoError(t, err)
	controlSummary := session.Report.SummaryDetails.Controls[control.ControlID]
	assert.Equal(t, apis.StatusSkipped, controlSummary.GetStatus().Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, controlSummary.GetStatus().GetSubStatus())
	assert.Contains(t, controlSummary.GetStatus().Info(), "broken-rule")
	require.Len(t, session.ScanCoverage.NotEvaluatedControls, 1)
	assert.Equal(t, control.ControlID, session.ScanCoverage.NotEvaluatedControls[0].ControlID)
	assert.Equal(t, 1, session.ScanCoverage.TotalControls)
	assert.Equal(t, 0, session.ScanCoverage.EvaluatedControls)
}

// ProcessRulesListener deliberately finalizes the eager session even when the
// scan fails. Kubescape.Scan relies on this invariant before exposing the
// session alongside the processing error.
func TestProcessRulesListener_FinalizesPartialResultsBeforeReturningError(t *testing.T) {
	session, control := brokenRuleSession()
	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := processor.ProcessRulesListener(ctx, nil)

	require.ErrorIs(t, err, context.Canceled)
	_, inSummary := session.Report.SummaryDetails.Controls[control.ControlID]
	assert.True(t, inSummary, "the summary must be built before the error is returned")
	assert.Equal(t, 1, session.ScanCoverage.TotalControls)
}

func brokenRuleSession() (*cautils.OPASessionObj, reporthandling.Control) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "pod",
			"namespace": "default",
		},
	})
	rule := reporthandling.PolicyRule{
		Rule:         "package armo_builtins\nthis is not valid rego at all {{{",
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"Pod"},
		}},
	}
	rule.Name = "broken-rule"
	control := reporthandling.Control{ControlID: "C-BROKEN", BaseScore: 5, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "broken-control"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "broken-framework"

	session := cautils.NewOPASessionObjMock()
	session.Policies = []reporthandling.Framework{framework}
	session.K8SResources = cautils.K8SResources{"/v1/pods": {pod.GetID()}}
	session.AllResources[pod.GetID()] = pod
	return session, control
}
