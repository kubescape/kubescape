package score

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	cautils "github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A framework whose controls were all skipped (for example because their
// resources could not be collected) cannot be scored. The scan must still get
// scores for the other frameworks and compliance scores for every control,
// because the namespace summaries and the reports read them afterwards.
func TestCalculateKeepsScoringAfterUnscorableFramework(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "web", "namespace": "default"},
	})
	opaSessionObj := cautils.NewOPASessionObjMock()
	opaSessionObj.AllResources[pod.GetID()] = pod

	var failed helpersv1.AllLists
	failed.Append(apis.StatusFailed, pod.GetID())
	failing := reportsummary.ControlSummary{
		Name:        "failing",
		ControlID:   "C-0001",
		ScoreFactor: 7,
		ResourceIDs: failed,
	}
	var passed helpersv1.AllLists
	passed.Append(apis.StatusPassed, pod.GetID())
	passing := reportsummary.ControlSummary{
		Name:        "passing",
		ControlID:   "C-0003",
		ScoreFactor: 7,
		ResourceIDs: passed,
	}
	skipped := reportsummary.ControlSummary{Name: "skipped", ControlID: "C-0002"}
	skipped.SetStatus(&apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusConfiguration})

	report := opaSessionObj.Report
	report.SummaryDetails.Controls = reportsummary.ControlSummaries{
		"C-0001": failing,
		"C-0002": skipped,
		"C-0003": passing,
	}
	report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
		{Name: "skipped-only", Controls: reportsummary.ControlSummaries{"C-0002": skipped}},
		{Name: "scorable", Controls: reportsummary.ControlSummaries{"C-0001": failing, "C-0003": passing}},
	}

	err := NewScoreWrapper(opaSessionObj).Calculate(EPostureReportV2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "skipped-only")

	frameworks := report.SummaryDetails.Frameworks
	assert.Equal(t, float32(0), frameworks[0].Score)
	assert.Equal(t, float32(50), frameworks[1].Score)
	assert.Equal(t, float32(50), frameworks[1].ComplianceScore)
	assert.Equal(t, float32(50), report.SummaryDetails.Score)

	failingSummary := report.SummaryDetails.Controls["C-0001"]
	require.NotNil(t, failingSummary.ComplianceScore, "failing control has no compliance score")
	assert.Equal(t, float32(0), failingSummary.GetComplianceScore())
	passingSummary := report.SummaryDetails.Controls["C-0003"]
	require.NotNil(t, passingSummary.ComplianceScore, "passing control has no compliance score")
	assert.Equal(t, float32(100), passingSummary.GetComplianceScore())

	// The scan builds the namespace summaries from these compliance scores
	// right after scoring. A control without a score would count as 100 there.
	summaries := cautils.BuildNamespaceSummariesFromCatalog(report.SummaryDetails.Controls, opaSessionObj.GetCatalog())
	require.Len(t, summaries, 1)
	assert.Equal(t, "default", summaries[0].Namespace)
	// failing 0, skipped 0, passing 100
	assert.InDelta(t, 100.0/3, summaries[0].ComplianceScore, 0.0001)
}
