package resultshandling

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
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
	s.Report.Results = []resourcesresults.Result{
		makeResult("resource-1", "C-low", "C-high"),
		makeResult("resource-2", "C-low"),
	}
	ApplySeverityFilters(s, "high", "")

	require.Len(t, s.Report.Results, 2)
	assert.Len(t, s.Report.Results[0].AssociatedControls, 1)
	assert.Equal(t, "C-high", s.Report.Results[0].AssociatedControls[0].GetID())
	assert.Len(t, s.Report.Results[1].AssociatedControls, 0)
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
