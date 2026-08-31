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

// ProcessRulesListener deliberately finalizes the eager session even when a
// rule fails. Kubescape.Scan relies on this invariant before exposing the
// session alongside the processing error.
func TestProcessRulesListener_FinalizesPartialResultsBeforeReturningError(t *testing.T) {
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
	processor := NewOPAProcessor(session, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)

	err := processor.ProcessRulesListener(context.Background(), nil)

	require.ErrorContains(t, err, "broken-rule")
	require.Len(t, session.ResourcesResult, 1)
	controlSummary := session.Report.SummaryDetails.Controls[control.ControlID]
	assert.Equal(t, apis.StatusSkipped, controlSummary.GetStatus().Status())
	assert.Equal(t, 1, session.Report.SummaryDetails.NumberOfResources().Skipped())
	assert.Equal(t, 1, session.ScanCoverage.TotalControls)
}
