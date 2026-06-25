package diff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempReport(t *testing.T, r scanReport) string {
	t.Helper()
	data, err := json.Marshal(r)
	require.NoError(t, err)
	f, err := os.CreateTemp(t.TempDir(), "report-*.json")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func makeReport(entries ...resultEntry) scanReport {
	return scanReport{Results: entries}
}

func makeResult(resourceID string, controls ...controlEntry) resultEntry {
	return resultEntry{ResourceID: resourceID, AssociatedControls: controls}
}

func makeControl(id, name, status string) controlEntry {
	return controlEntry{ControlID: id, Name: name, Status: statusInfo{InnerStatus: status}}
}

func TestCompute_NewFailure(t *testing.T) {
	sum := summaryDetails{Controls: map[string]controlSummary{"C-001": {ScoreFactor: 7.0}}}
	base := scanReport{
		Results:        []resultEntry{makeResult("res1", makeControl("C-001", "Control 1", "passed"))},
		SummaryDetails: sum,
	}
	head := scanReport{
		Results:        []resultEntry{makeResult("res1", makeControl("C-001", "Control 1", "failed"))},
		SummaryDetails: sum,
	}

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Len(t, cs.New, 1)
	assert.Empty(t, cs.Resolved)
	assert.Empty(t, cs.Unchanged)
	assert.Equal(t, "C-001", cs.New[0].ControlID)
	assert.Equal(t, "High", cs.New[0].Severity)
}

func TestCompute_Resolved(t *testing.T) {
	base := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed")))
	head := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "passed")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Len(t, cs.Resolved, 1)
	assert.Empty(t, cs.Unchanged)
}

func TestCompute_Unchanged(t *testing.T) {
	base := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed")))
	head := makeReport(makeResult("res1", makeControl("C-001", "Control 1", "failed")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Empty(t, cs.Resolved)
	assert.Len(t, cs.Unchanged, 1)
}

func TestCompute_NewResourceInHead(t *testing.T) {
	// resource not in base at all but failing in head
	base := makeReport()
	head := makeReport(makeResult("res-new", makeControl("C-002", "Control 2", "failed")))

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Len(t, cs.New, 1)
	assert.Equal(t, "res-new", cs.New[0].ResourceID)
	// new-to-head failures have no base counterpart: BaseStatus is "absent", symmetric with HeadStatus
	assert.Equal(t, "absent", cs.New[0].BaseStatus)
}

func TestCompute_RemovedResourceFromBase(t *testing.T) {
	// resource was failing in base but absent in head
	base := makeReport(makeResult("res-old", makeControl("C-001", "Control 1", "failed")))
	head := makeReport()

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	assert.Empty(t, cs.New)
	assert.Len(t, cs.Resolved, 1)
	assert.Equal(t, "absent", cs.Resolved[0].HeadStatus)
}

func TestCompute_MissingFile(t *testing.T) {
	_, err := Compute(filepath.Join(t.TempDir(), "missing.json"), filepath.Join(t.TempDir(), "also-missing.json"))
	assert.Error(t, err)
}

func TestFilterBySeverity(t *testing.T) {
	changes := []ControlChange{
		{ControlID: "C-001", Severity: "Critical"},
		{ControlID: "C-002", Severity: "High"},
		{ControlID: "C-003", Severity: "Medium"},
		{ControlID: "C-004", Severity: "Low"},
	}

	result := FilterBySeverity(changes, "High")
	assert.Len(t, result, 2)
	assert.Equal(t, "Critical", result[0].Severity)
	assert.Equal(t, "High", result[1].Severity)

	result = FilterBySeverity(changes, "")
	assert.Len(t, result, 4)

	result = FilterBySeverity(changes, "Critical")
	assert.Len(t, result, 1)
}

func TestCompute_SeverityFromSummaryDetails(t *testing.T) {
	tests := []struct {
		name        string
		scoreFactor float32
		wantSev     string
	}{
		{"critical", 9.5, "Critical"},
		{"high", 7.0, "High"},
		{"medium", 5.0, "Medium"},
		{"low", 2.0, "Low"},
		{"unknown_zero", 0, "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := summaryDetails{Controls: map[string]controlSummary{
				"C-001": {ScoreFactor: tt.scoreFactor},
			}}
			head := scanReport{
				Results:        []resultEntry{makeResult("res1", makeControl("C-001", "Control 1", "failed"))},
				SummaryDetails: sum,
			}
			base := scanReport{}

			cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
			require.NoError(t, err)
			require.Len(t, cs.New, 1)
			assert.Equal(t, tt.wantSev, cs.New[0].Severity)
		})
	}
}

func TestCompute_SeverityStringFromCurrentReport(t *testing.T) {
	sum := summaryDetails{Controls: map[string]controlSummary{
		"C-001": {ScoreFactor: 9.5, Severity: "Critical"},
	}}
	head := scanReport{
		Results:        []resultEntry{makeResult("res1", makeControl("C-001", "Control 1", "failed"))},
		SummaryDetails: sum,
	}
	base := scanReport{}

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	require.Len(t, cs.New, 1)
	assert.Equal(t, "Critical", cs.New[0].Severity)
}

func TestFilterBySeverity_BelowThresholdReturnsEmpty(t *testing.T) {
	changes := []ControlChange{
		{ControlID: "C-001", Severity: "Low"},
		{ControlID: "C-002", Severity: "Medium"},
	}

	result := FilterBySeverity(changes, "High")
	assert.Empty(t, result)
}

func TestFilterBySeverity_CIGate(t *testing.T) {
	sum := summaryDetails{Controls: map[string]controlSummary{
		"C-HIGH":     {ScoreFactor: 7.0},
		"C-CRITICAL": {ScoreFactor: 9.5},
		"C-MEDIUM":   {ScoreFactor: 5.0},
		"C-LOW":      {ScoreFactor: 2.0},
	}}
	head := scanReport{
		Results: []resultEntry{
			makeResult("res1",
				makeControl("C-HIGH", "High Control", "failed"),
				makeControl("C-CRITICAL", "Critical Control", "failed"),
				makeControl("C-MEDIUM", "Medium Control", "failed"),
				makeControl("C-LOW", "Low Control", "failed"),
			),
		},
		SummaryDetails: sum,
	}
	base := scanReport{}

	cs, err := Compute(writeTempReport(t, base), writeTempReport(t, head))
	require.NoError(t, err)
	require.Len(t, cs.New, 4)

	gate := FilterBySeverity(cs.New, "high")
	assert.Len(t, gate, 2)

	controlIDs := make([]string, len(gate))
	for i, c := range gate {
		controlIDs[i] = c.ControlID
	}
	assert.ElementsMatch(t, []string{"C-HIGH", "C-CRITICAL"}, controlIDs)
}
