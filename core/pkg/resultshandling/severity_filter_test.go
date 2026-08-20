package resultshandling

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	scoreLow      = float32(2)
	scoreMedium   = float32(5)
	scoreHigh     = float32(7)
	scoreCritical = float32(9)
)

func makeSessionWithControls(controls map[string]reportsummary.ControlSummary) *cautils.OPASessionObj {
	s := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
	}
	s.Report.SummaryDetails.Controls = controls
	return s
}

func makeControl(id string, scoreFactor float32) reportsummary.ControlSummary {
	return reportsummary.ControlSummary{
		ControlID:   id,
		ScoreFactor: scoreFactor,
	}
}

func makeResult(resourceID string, controlIDs ...string) resourcesresults.Result {
	r := resourcesresults.Result{ResourceID: resourceID}
	for _, id := range controlIDs {
		r.AssociatedControls = append(r.AssociatedControls, resourcesresults.ResourceAssociatedControl{
			ControlID: id,
		})
	}
	return r
}

// makeCompliantControl builds a control with an explicit per-control compliance
// score (nil ComplianceScore makes GetComplianceScore() return -1).
func makeCompliantControl(id string, scoreFactor float32, compliance float32) reportsummary.ControlSummary {
	c := makeControl(id, scoreFactor)
	c.ComplianceScore = &compliance
	return c
}

func makeFailedControl(id string, scoreFactor float32) reportsummary.ControlSummary {
	c := makeControl(id, scoreFactor)
	c.StatusInfo = apis.StatusInfo{InnerStatus: apis.StatusFailed}
	return c
}

func TestApplySeverityFilters_NilSessionObj(t *testing.T) {
	ApplySeverityFilters(nil, "high", "")
}

func TestApplySeverityFilters_NilReport(t *testing.T) {
	ApplySeverityFilters(&cautils.OPASessionObj{}, "high", "")
}

func TestApplySeverityFilters_BothEmpty(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-0001": makeControl("C-0001", scoreLow),
		"C-0002": makeControl("C-0002", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "", "")
	assert.Len(t, s.Report.SummaryDetails.Controls, 2)
}

func TestApplySeverityFilters_MinHigh_KeepsHighAndCritical(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeControl("C-low", scoreLow),
		"C-medium":   makeControl("C-medium", scoreMedium),
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "high", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 2)
	_, hasHigh := s.Report.SummaryDetails.Controls["C-high"]
	_, hasCritical := s.Report.SummaryDetails.Controls["C-critical"]
	assert.True(t, hasHigh)
	assert.True(t, hasCritical)
}

func TestApplySeverityFilters_MinMedium_DropsLow(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeControl("C-low", scoreLow),
		"C-medium":   makeControl("C-medium", scoreMedium),
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "medium", "")

	assert.Len(t, s.Report.SummaryDetails.Controls, 3)
	_, hasLow := s.Report.SummaryDetails.Controls["C-low"]
	assert.False(t, hasLow)
}

func TestApplySeverityFilters_MaxMedium_DropsHighAndCritical(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeControl("C-low", scoreLow),
		"C-medium":   makeControl("C-medium", scoreMedium),
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "", "medium")

	assert.Len(t, s.Report.SummaryDetails.Controls, 2)
	_, hasHigh := s.Report.SummaryDetails.Controls["C-high"]
	_, hasCritical := s.Report.SummaryDetails.Controls["C-critical"]
	assert.False(t, hasHigh)
	assert.False(t, hasCritical)
}

func TestApplySeverityFilters_RangeHighToHigh_KeepsOnlyHigh(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeControl("C-low", scoreLow),
		"C-medium":   makeControl("C-medium", scoreMedium),
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "high", "high")

	require.Len(t, s.Report.SummaryDetails.Controls, 1)
	_, hasHigh := s.Report.SummaryDetails.Controls["C-high"]
	assert.True(t, hasHigh)
}

func TestApplySeverityFilters_ResultsFilteredAlongWithControls(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":  makeControl("C-low", scoreLow),
		"C-high": makeControl("C-high", scoreHigh),
	}
	s := makeSessionWithControls(controls)
	s.ResourcesResult = map[string]resourcesresults.Result{
		"resource-1": makeResult("resource-1", "C-low", "C-high"),
		"resource-2": makeResult("resource-2", "C-low"),
	}
	ApplySeverityFilters(s, "high", "")

	require.Len(t, s.ResourcesResult, 2)
	assert.Len(t, s.ResourcesResult["resource-1"].AssociatedControls, 1)
	assert.Equal(t, "C-high", s.ResourcesResult["resource-1"].AssociatedControls[0].GetID())
	assert.Len(t, s.ResourcesResult["resource-2"].AssociatedControls, 0)
}

func TestApplySeverityFilters_CaseInsensitive(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "HIGH", "CRITICAL")
	assert.Len(t, s.Report.SummaryDetails.Controls, 2)
}

func TestApplySeverityFilters_WhitespaceInSeverity(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-high": makeControl("C-high", scoreHigh),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "  high  ", "")
	assert.Len(t, s.Report.SummaryDetails.Controls, 1)
}

func TestApplySeverityFilters_UnknownSeverityExcluded_WhenMinSet(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-unknown": {ControlID: "C-unknown", ScoreFactor: 0},
		"C-high":    makeControl("C-high", scoreHigh),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "low", "")

	_, hasUnknown := s.Report.SummaryDetails.Controls["C-unknown"]
	_, hasHigh := s.Report.SummaryDetails.Controls["C-high"]
	assert.False(t, hasUnknown)
	assert.True(t, hasHigh)
}

func TestApplySeverityFilters_EmptyControls(t *testing.T) {
	s := makeSessionWithControls(map[string]reportsummary.ControlSummary{})
	ApplySeverityFilters(s, "high", "")
	assert.Len(t, s.Report.SummaryDetails.Controls, 0)
}

func TestApplySeverityFilters_AllRetained(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-high":     makeControl("C-high", scoreHigh),
		"C-critical": makeControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "high", "critical")
	assert.Len(t, s.Report.SummaryDetails.Controls, 2)
}

func TestSeverityRankFromString(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"critical", 4},
		{"Critical", 4},
		{"CRITICAL", 4},
		{"high", 3},
		{"High", 3},
		{"medium", 2},
		{"low", 1},
		{"", 0},
		{"unknown", 0},
		{"bogus", 0},
		{"  high  ", 3},
	}
	for _, tt := range tests {
		t.Run(tt.sev, func(t *testing.T) {
			assert.Equal(t, tt.want, severityRankFromString(tt.sev))
		})
	}
}

func TestApplySeverityFilters_NilControlsMap(t *testing.T) {
	s := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
	}
	ApplySeverityFilters(s, "high", "")
	assert.Nil(t, s.Report.SummaryDetails.Controls)
}

func TestApplySeverityFilters_UnknownSeverityExcluded_WhenMaxOnly(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-unknown": {ControlID: "C-unknown", ScoreFactor: 0},
		"C-medium":  makeControl("C-medium", scoreMedium),
		"C-low":     makeControl("C-low", scoreLow),
	}
	s := makeSessionWithControls(controls)
	ApplySeverityFilters(s, "", "medium")

	_, hasUnknown := s.Report.SummaryDetails.Controls["C-unknown"]
	_, hasMedium := s.Report.SummaryDetails.Controls["C-medium"]
	_, hasLow := s.Report.SummaryDetails.Controls["C-low"]
	assert.False(t, hasUnknown)
	assert.True(t, hasMedium)
	assert.True(t, hasLow)
}

func TestApplySeverityFilters_RecomputesComplianceScore(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeCompliantControl("C-low", scoreLow, 100),
		"C-medium":   makeCompliantControl("C-medium", scoreMedium, 60),
		"C-critical": makeCompliantControl("C-critical", scoreCritical, 10),
	}
	s := makeSessionWithControls(controls)
	s.Report.SummaryDetails.ComplianceScore = 56.7 // stale full-set value

	ApplySeverityFilters(s, "critical", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 1)
	assert.Equal(t, float32(10), s.Report.SummaryDetails.ComplianceScore)
}

func TestApplySeverityFilters_DoesNotRecomputeRiskScore(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      {ControlID: "C-low", ScoreFactor: scoreLow, Score: 90},
		"C-medium":   {ControlID: "C-medium", ScoreFactor: scoreMedium, Score: 50},
		"C-critical": {ControlID: "C-critical", ScoreFactor: scoreCritical, Score: 20},
	}
	s := makeSessionWithControls(controls)
	s.Report.SummaryDetails.Score = 53.3

	ApplySeverityFilters(s, "critical", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 1)
	// The risk score is a WCS-weighted aggregate whose weights are not available
	// at filter time; a plain average would not reproduce it, so it is left as-is.
	assert.Equal(t, float32(53.3), s.Report.SummaryDetails.Score)
}

func TestApplySeverityFilters_RecomputesFrameworkComplianceScores(t *testing.T) {
	low := makeCompliantControl("C-low", scoreLow, 100)
	high := makeCompliantControl("C-high", scoreHigh, 25)
	controls := map[string]reportsummary.ControlSummary{
		"C-low":  low,
		"C-high": high,
	}
	s := makeSessionWithControls(controls)
	s.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{
		{
			Name: "framework-a",
			Controls: reportsummary.ControlSummaries{
				"C-low":  low,
				"C-high": high,
			},
			ComplianceScore: 62.5,
		},
		{
			Name: "framework-b",
			Controls: reportsummary.ControlSummaries{
				"C-low": low,
			},
			ComplianceScore: 100,
		},
	}

	ApplySeverityFilters(s, "high", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 1)
	assert.Equal(t, float32(25), s.Report.SummaryDetails.Frameworks[0].ComplianceScore,
		"framework score must be recomputed over retained framework controls")
	assert.Equal(t, float32(0), s.Report.SummaryDetails.Frameworks[1].ComplianceScore,
		"framework with no retained controls must score 0")
}

func TestApplySeverityFilters_RecomputesControlsSeverityCounters(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeFailedControl("C-low", scoreLow),
		"C-medium":   makeFailedControl("C-medium", scoreMedium),
		"C-high":     makeFailedControl("C-high", scoreHigh),
		"C-critical": makeFailedControl("C-critical", scoreCritical),
		"C-passed":   makeControl("C-passed", scoreMedium),
	}
	s := makeSessionWithControls(controls)
	s.Report.SummaryDetails.ControlsSeverityCounters = reportsummary.SeverityCounters{CriticalSeverityCounter: 9}

	ApplySeverityFilters(s, "high", "")

	got := s.Report.SummaryDetails.ControlsSeverityCounters
	assert.Equal(t, 0, got.LowSeverityCounter)
	assert.Equal(t, 0, got.MediumSeverityCounter)
	assert.Equal(t, 1, got.HighSeverityCounter)
	assert.Equal(t, 1, got.CriticalSeverityCounter)
}

func TestApplySeverityFilters_RecomputesResourcesSeverityCounters(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low":      makeFailedControl("C-low", scoreLow),
		"C-high":     makeFailedControl("C-high", scoreHigh),
		"C-critical": makeFailedControl("C-critical", scoreCritical),
	}
	s := makeSessionWithControls(controls)
	s.ResourcesResult = map[string]resourcesresults.Result{
		"resource-1": {
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-low", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
				{ControlID: "C-high", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
				{ControlID: "C-critical", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
			},
		},
		"resource-2": {
			AssociatedControls: []resourcesresults.ResourceAssociatedControl{
				{ControlID: "C-high", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
			},
		},
	}
	s.Report.SummaryDetails.ResourcesSeverityCounters = reportsummary.SeverityCounters{LowSeverityCounter: 7}

	ApplySeverityFilters(s, "high", "")

	// resource-1 keeps C-high + C-critical (2 x 1), resource-2 keeps C-high (1 x 1).
	got := s.Report.SummaryDetails.ResourcesSeverityCounters
	assert.Equal(t, 0, got.LowSeverityCounter)
	assert.Equal(t, 0, got.MediumSeverityCounter)
	assert.Equal(t, 2, got.HighSeverityCounter)
	assert.Equal(t, 1, got.CriticalSeverityCounter)
}

func TestApplySeverityFilters_ZeroRetainedZeroesComplianceScoreAndCounters(t *testing.T) {
	controls := map[string]reportsummary.ControlSummary{
		"C-low": makeCompliantControl("C-low", scoreLow, 100),
	}
	s := makeSessionWithControls(controls)
	s.Report.SummaryDetails.ComplianceScore = 100
	s.Report.SummaryDetails.Score = 100
	s.Report.SummaryDetails.ControlsSeverityCounters = reportsummary.SeverityCounters{LowSeverityCounter: 3}

	ApplySeverityFilters(s, "critical", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 0)
	assert.Equal(t, float32(0), s.Report.SummaryDetails.ComplianceScore)
	assert.Equal(t, reportsummary.SeverityCounters{}, s.Report.SummaryDetails.ControlsSeverityCounters)
	assert.Equal(t, reportsummary.SeverityCounters{}, s.Report.SummaryDetails.ResourcesSeverityCounters)
	// The risk score is not recomputed at filter time; it is left unchanged.
	assert.Equal(t, float32(100), s.Report.SummaryDetails.Score)
}
