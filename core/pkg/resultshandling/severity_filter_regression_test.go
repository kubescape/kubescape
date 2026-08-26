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

// TestApplySeverityFilters_FiltersRealPerResourceFindings pins the bug: the scan
// pipeline never populates Report.Results, so filtering it is a no-op. Findings
// live in ResourcesResult, which every printer reads (directly or through
// FinalizeResults), and must be filtered alongside SummaryDetails.Controls.
func TestApplySeverityFilters_FiltersRealPerResourceFindings(t *testing.T) {
	s := &cautils.OPASessionObj{
		Report: &reporthandlingv2.PostureReport{},
		ResourcesResult: map[string]resourcesresults.Result{
			"res-1": {
				ResourceID: "res-1",
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{ControlID: "C-low"},
					{ControlID: "C-critical"},
				},
			},
		},
	}
	s.Report.SummaryDetails.Controls = map[string]reportsummary.ControlSummary{
		"C-low":      makeControl("C-low", scoreLow),
		"C-critical": makeControl("C-critical", scoreCritical),
	}

	// Production shape: the pipeline builds Report.Results only inside FinalizeResults.
	require.Nil(t, s.Report.Results)

	ApplySeverityFilters(s, "critical", "")

	require.Len(t, s.Report.SummaryDetails.Controls, 1)

	got := s.ResourcesResult["res-1"].AssociatedControls
	ids := make([]string, 0, len(got))
	for _, c := range got {
		ids = append(ids, c.GetID())
	}
	assert.Equal(t, []string{"C-critical"}, ids,
		"per-resource findings must be filtered too, otherwise results reference controls absent from the summary")
}
