package cautils

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportV2ToV1(t *testing.T) {
	tests := []struct {
		name                string
		session             *OPASessionObj
		wantFrameworkNames  []string
		wantFrameworkScores []float32
	}{
		{
			name: "summary controls without frameworks create default framework",
			session: &OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Score: 77,
						Controls: reportsummary.ControlSummaries{
							"C-001": reportsummary.ControlSummary{
								ControlID:   "C-001",
								Name:        "control one",
								Score:       88,
								ScoreFactor: 5,
								Description: "description",
								Remediation: "remediation",
							},
						},
					},
				},
			},
			wantFrameworkNames:  []string{""},
			wantFrameworkScores: []float32{77},
		},
		{
			name: "framework summaries preserve names and scores",
			session: &OPASessionObj{
				Report: &reporthandlingv2.PostureReport{
					SummaryDetails: reportsummary.SummaryDetails{
						Frameworks: []reportsummary.FrameworkSummary{
							{Name: "NSA", Score: 90},
							{Name: "MITRE", Score: 55},
						},
					},
				},
			},
			wantFrameworkNames:  []string{"NSA", "MITRE"},
			wantFrameworkScores: []float32{90, 55},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReportV2ToV1(tt.session)

			require.NotNil(t, got)
			require.Len(t, got.FrameworkReports, len(tt.wantFrameworkNames))
			for i := range tt.wantFrameworkNames {
				assert.Equal(t, tt.wantFrameworkNames[i], got.FrameworkReports[i].Name)
				assert.Equal(t, tt.wantFrameworkScores[i], got.FrameworkReports[i].Score)
			}
		})
	}
}
