package configurationprinter

import (
	"fmt"
	"testing"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCounters struct {
	failed, skipped, passed, excluded int
}

func (m mockCounters) Failed() int   { return m.failed }
func (m mockCounters) Skipped() int  { return m.skipped }
func (m mockCounters) Passed() int   { return m.passed }
func (m mockCounters) Excluded() int { return m.excluded }
func (m mockCounters) All() int      { return m.failed + m.skipped + m.passed }

func TestControlCountersForSummary(t *testing.T) {
	tests := []struct {
		name       string
		counters   mockCounters
		wantAll    string
		wantPassed string
		wantFailed string
		wantSkip   string
	}{
		{
			name:       "all zero",
			counters:   mockCounters{},
			wantAll:    "0",
			wantPassed: "0",
			wantFailed: "0",
			wantSkip:   "0",
		},
		{
			name:       "only failed",
			counters:   mockCounters{failed: 3},
			wantAll:    "3",
			wantPassed: "0",
			wantFailed: "3",
			wantSkip:   "0",
		},
		{
			name:       "only passed",
			counters:   mockCounters{passed: 5},
			wantAll:    "5",
			wantPassed: "5",
			wantFailed: "0",
			wantSkip:   "0",
		},
		{
			name:       "only skipped",
			counters:   mockCounters{skipped: 2},
			wantAll:    "2",
			wantPassed: "0",
			wantFailed: "0",
			wantSkip:   "2",
		},
		{
			name:       "failed and passed",
			counters:   mockCounters{failed: 4, passed: 6},
			wantAll:    "10",
			wantPassed: "6",
			wantFailed: "4",
			wantSkip:   "0",
		},
		{
			name:       "all three non-zero",
			counters:   mockCounters{failed: 2, passed: 5, skipped: 1},
			wantAll:    "8",
			wantPassed: "5",
			wantFailed: "2",
			wantSkip:   "1",
		},
		{
			name:       "large numbers",
			counters:   mockCounters{failed: 100, passed: 200, skipped: 50},
			wantAll:    "350",
			wantPassed: "200",
			wantFailed: "100",
			wantSkip:   "50",
		},
		{
			name:       "with excluded — excluded does not count toward All",
			counters:   mockCounters{failed: 1, passed: 2, excluded: 3},
			wantAll:    "3",
			wantPassed: "2",
			wantFailed: "1",
			wantSkip:   "0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := ControlCountersForSummary(tt.counters)
			require.Len(t, rows, 4, "expected exactly 4 rows")

			assert.Equal(t, "Controls", rows[0][0])
			assert.Equal(t, tt.wantAll, rows[0][1])

			assert.Equal(t, "Passed", rows[1][0])
			assert.Equal(t, tt.wantPassed, rows[1][1])

			assert.Equal(t, "Failed", rows[2][0])
			assert.Equal(t, tt.wantFailed, rows[2][1])

			assert.Equal(t, "Action Required", rows[3][0])
			assert.Equal(t, tt.wantSkip, rows[3][1])
		})
	}
}

func TestGetControlTableHeaders_Short(t *testing.T) {
	headers := GetControlTableHeaders(true)
	require.Len(t, headers, 1, "short mode should produce a single-column header")
	assert.Equal(t, "Controls", headers[0])
}

func TestGetControlTableHeaders_Full(t *testing.T) {
	headers := GetControlTableHeaders(false)
	require.Len(t, headers, _summaryRowLen, "full mode should produce %d columns", _summaryRowLen)
	assert.Equal(t, "Severity", headers[summaryColumnSeverity])
	assert.Equal(t, "Control name", headers[summaryColumnName])
	assert.Equal(t, "Failed resources", headers[summaryColumnCounterFailed])
	assert.Equal(t, "All Resources", headers[summaryColumnCounterAll])
	assert.Equal(t, "Compliance score", headers[summaryColumnComplianceScore])
}

func TestGetControlTableHeaders_ShortVsFullDiffer(t *testing.T) {
	short := GetControlTableHeaders(true)
	full := GetControlTableHeaders(false)
	assert.NotEqual(t, len(short), len(full), "short and full headers should have different column counts")
}

func TestGetColumnsAlignments(t *testing.T) {
	cols := GetColumnsAlignments()
	require.Len(t, cols, 5, "expected exactly 5 column configs")

	colMap := make(map[int]text.Align)
	for _, c := range cols {
		colMap[c.Number] = c.Align
	}

	assert.Equal(t, text.AlignCenter, colMap[summaryColumnSeverity+1], "severity column should be center-aligned")
	assert.Equal(t, text.AlignLeft, colMap[summaryColumnName+1], "name column should be left-aligned")
	assert.Equal(t, text.AlignCenter, colMap[summaryColumnCounterFailed+1], "failed column should be center-aligned")
	assert.Equal(t, text.AlignCenter, colMap[summaryColumnCounterAll+1], "all-resources column should be center-aligned")
	assert.Equal(t, text.AlignCenter, colMap[summaryColumnComplianceScore+1], "compliance column should be center-aligned")
}

func TestGenerateFooter_Short(t *testing.T) {
	tests := []struct {
		name            string
		complianceScore float32
		wantContains    []string
	}{
		{
			name:            "zero compliance",
			complianceScore: 0,
			wantContains:    []string{"Compliance-Score", "0.00%"},
		},
		{
			name:            "full compliance",
			complianceScore: 100,
			wantContains:    []string{"Compliance-Score", "100.00%"},
		},
		{
			name:            "partial compliance",
			complianceScore: 67.5,
			wantContains:    []string{"Compliance-Score", "67.50%"},
		},
		{
			name:            "contains resource summary label",
			complianceScore: 50,
			wantContains:    []string{"Resource Summary", "Failed Resources", "All Resources"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := reportsummary.SummaryDetails{ComplianceScore: tt.complianceScore}
			row := GenerateFooter(&sd, true)
			require.Len(t, row, 1, "short footer should have exactly 1 column")
			content := fmt.Sprintf("%v", row[0])
			for _, want := range tt.wantContains {
				assert.Contains(t, content, want)
			}
		})
	}
}

func TestGenerateFooter_Full(t *testing.T) {
	tests := []struct {
		name                string
		complianceScore     float32
		wantComplianceScore string
	}{
		{
			name:                "zero",
			complianceScore:     0,
			wantComplianceScore: "0.00%",
		},
		{
			name:                "full",
			complianceScore:     100,
			wantComplianceScore: "100.00%",
		},
		{
			name:                "partial",
			complianceScore:     75.25,
			wantComplianceScore: "75.25%",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd := reportsummary.SummaryDetails{ComplianceScore: tt.complianceScore}
			row := GenerateFooter(&sd, false)
			require.Len(t, row, _summaryRowLen, "full footer should have %d columns", _summaryRowLen)
			assert.Equal(t, "Resource Summary", row[summaryColumnName])
			assert.Equal(t, " ", row[summaryColumnSeverity])
			assert.Equal(t, tt.wantComplianceScore, row[summaryColumnComplianceScore])
		})
	}
}

func TestGenerateFooter_ShortVsFullDiffer(t *testing.T) {
	sd := reportsummary.SummaryDetails{ComplianceScore: 50}
	short := GenerateFooter(&sd, true)
	full := GenerateFooter(&sd, false)
	assert.NotEqual(t, len(short), len(full), "short and full footers should have different column counts")
}
