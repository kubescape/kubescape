package opaprocessor

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/kubescape/v3/core/pkg/score"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingRule is a genuinely CPU-bound Rego rule: it iterates the cartesian
// product of two large arrays (10^10 combinations), with no I/O or custom
// builtins involved. This proves that a context deadline interrupts
// evaluation mid-computation (topdown checks for cancellation on every
// expression evaluation), not just at an external blocking point.
const blockingRule = `package armo_builtins

deny[msga] {
	a := numbers.range(1, 100000)
	b := numbers.range(1, 100000)
	x := a[_]
	y := b[_]
	x + y == -1
	msga := {
		"alertMessage": "should never be reached",
		"packagename": "armo_builtins",
		"alertScore": 1,
		"fixPaths": [],
		"failedPaths": [],
		"alertObject": {"k8sApiObjects": [input[_]]}
	}
}
`

// TestProcess_ControlTimeout verifies that when ControlTimeout is set, a
// control whose Rego evaluation never returns on its own is interrupted,
// the overall scan still completes, and the timed-out control is recorded
// in InfoMap as skipped/not-evaluated rather than stalling the scan.
func TestProcess_ControlTimeout(t *testing.T) {
	deployment := mocks.MockDevelopmentWithHostpath()

	k8sResources := make(cautils.K8SResources)
	k8sResources["apps/v1/deployments"] = workloadinterface.ListMetaIDs([]workloadinterface.IMetadata{deployment})

	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.K8SResources = k8sResources
	opaSessionObj.AllResources[deployment.GetID()] = deployment
	opaSessionObj.InfoMap = make(map[string]apis.StatusInfo)

	const controlID = "C-TEST-TIMEOUT"
	policies := &cautils.Policies{
		Controls: map[string]reporthandling.Control{
			controlID: {
				PortalBase: armotypes.PortalBase{
					Name: "blocking control",
				},
				ControlID: controlID,
				Rules: []reporthandling.PolicyRule{
					{
						PortalBase: armotypes.PortalBase{
							Name:       "blocking-rule",
							Attributes: map[string]interface{}{},
						},
						Rule: blockingRule,
						Match: []reporthandling.RuleMatchObjects{
							{
								APIGroups:   []string{"apps"},
								APIVersions: []string{"v1"},
								Resources:   []string{"Deployment"},
							},
						},
						RuleQuery:    "armo_builtins",
						RuleLanguage: reporthandling.RegoLanguage,
					},
				},
			},
		},
	}

	opap := NewOPAProcessor(opaSessionObj, resources.NewRegoDependenciesDataMock(), "test", "", "", false, nil)
	opap.AllPolicies = policies
	opap.ControlTimeout = 100 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		done <- opap.Process(context.Background(), policies, nil)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Process did not return: per-control timeout did not interrupt the blocking rule")
	}

	reason, ok := opap.TimedOutControls[controlID]
	require.True(t, ok, "expected timed-out control to be recorded in TimedOutControls")
	assert.Contains(t, reason, "timed out")

	assert.Empty(t, opap.ResourcesResult, "timed-out control must not contribute resources to ResourcesResult")

	// mirrors the rebuild step performed by ProcessRulesListener after Process returns
	coverage := cautils.BuildScanCoverage(opaSessionObj.InfoMap, opaSessionObj.ResourceToControlsMap, opap.TimedOutControls, opaSessionObj.PartialGVRFailures, opaSessionObj.PolicyDegradations)
	require.Len(t, coverage.NotEvaluatedControls, 1)
	notEvaluated := coverage.NotEvaluatedControls[0]
	assert.Equal(t, controlID, notEvaluated.ControlID)
	assert.Contains(t, notEvaluated.Reason, "timed out")

	// Verify timed-out control is Skipped (not Passed) in SummaryDetails and excluded from compliance score.
	// Simulate the ProcessRulesListener steps that follow Process().
	framework := reporthandling.Framework{
		Controls: []reporthandling.Control{policies.Controls[controlID]},
	}
	opap.Policies = []reporthandling.Framework{framework}
	ConvertFrameworksToSummaryDetails(&opaSessionObj.Report.SummaryDetails, opap.Policies, policies)
	opap.updateResults(context.Background())
	opap.markTimedOutControlsSkipped()

	ctrl := opaSessionObj.Report.SummaryDetails.Controls[controlID]
	assert.NotEqual(t, apis.StatusPassed, ctrl.GetStatus().Status(), "timed-out control must not show as Passed in SummaryDetails")
	assert.Equal(t, apis.StatusSkipped, ctrl.GetStatus().Status(), "timed-out control must be Skipped in SummaryDetails")

	scorewrapper := score.NewScoreWrapper(opaSessionObj)
	require.NoError(t, scorewrapper.Calculate(score.EPostureReportV2))
	opap.reweightComplianceScores()
	assert.Zero(t, opaSessionObj.Report.SummaryDetails.ComplianceScore, "timed-out control must not inflate overall compliance score")
}
