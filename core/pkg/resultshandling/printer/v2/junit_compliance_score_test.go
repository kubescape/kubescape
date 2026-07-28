package printer

import (
	"testing"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListTestsSuiteUsesComplianceScores(t *testing.T) {
	tests := []struct {
		name    string
		summary reportsummary.SummaryDetails
		want    map[string]string
	}{
		{
			name: "control scan uses overall compliance instead of risk",
			summary: reportsummary.SummaryDetails{
				Score:           12.25,
				ComplianceScore: 87.75,
			},
			want: map[string]string{"kubescape": "87.75"},
		},
		{
			name: "framework scan uses each framework compliance instead of risk or summary",
			summary: reportsummary.SummaryDetails{
				Score:           1,
				ComplianceScore: 99,
				Frameworks: []reportsummary.FrameworkSummary{
					{Name: "NSA", Score: 10, ComplianceScore: 90},
					{Name: "MITRE", Score: 80, ComplianceScore: 20},
				},
			},
			want: map[string]string{
				"NSA":   "90.00",
				"MITRE": "20.00",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := cautils.NewOPASessionObjMock()
			results.Report.SummaryDetails = tt.summary

			suites := listTestsSuite(results)

			require.Len(t, suites, len(tt.want))
			for _, suite := range suites {
				require.Len(t, suite.Properties, 1)
				assert.Equal(t, JUnitProperty{
					Name:  "complianceScore",
					Value: tt.want[suite.Name],
				}, suite.Properties[0])
			}
		})
	}
}
