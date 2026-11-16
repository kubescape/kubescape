package opaprocessor

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A control that timed out after earlier scopes gave it passing verdicts keeps a
// partial compliance score, and reweightComplianceScores counts it as 0 (#2424). A
// severity filter that keeps every control must leave the scores where the
// reweighting put them, not count the partial score back in.
func TestSeverityFilterKeepsTheReweightingOfATimedOutControl(t *testing.T) {
	hundred := float32(100)
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0001": {ControlID: "C-0001", ScoreFactor: 7, ComplianceScore: &hundred,
			StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed}},
		"C-0002": {ControlID: "C-0002", ScoreFactor: 7, ComplianceScore: &hundred,
			StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusNotEvaluated}},
	}
	session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{{
		Name: "fw",
		Controls: reportsummary.ControlSummaries{
			"C-0001": session.Report.SummaryDetails.Controls["C-0001"],
			"C-0002": session.Report.SummaryDetails.Controls["C-0002"],
		},
	}}
	opap := &OPAProcessor{OPASessionObj: session, TimedOutControls: map[string]string{"C-0002": "timed out"}}
	opap.reweightComplianceScores()
	require.Equal(t, float32(50), session.Report.SummaryDetails.ComplianceScore)
	require.Equal(t, float32(50), session.Report.SummaryDetails.Frameworks[0].ComplianceScore)

	resultshandling.ApplySeverityFilters(session, "low", "") // both controls are high
	require.Len(t, session.Report.SummaryDetails.Controls, 2)
	assert.Equal(t, float32(50), session.Report.SummaryDetails.ComplianceScore, "cluster score")
	assert.Equal(t, float32(50), session.Report.SummaryDetails.Frameworks[0].ComplianceScore, "framework score")
}
