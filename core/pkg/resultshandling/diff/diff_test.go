package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTempReport(t *testing.T, r scanReport) string {
	t.Helper()
	if r.Results == nil {
		r.Results = []resultEntry{}
	}
	if r.SummaryDetails.Controls == nil {
		r.SummaryDetails.Controls = map[string]controlSummary{}
	}
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
	return scanReport{
		Results: entries,
		SummaryDetails: summaryDetails{
			Controls: map[string]controlSummary{},
		},
	}
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

func writeRawReport(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestComputeRejectsInvalidReportShapes(t *testing.T) {
	valid := writeTempReport(t, makeReport())
	tests := []struct {
		name    string
		report  string
		wantErr string
	}{
		{
			name:    "empty object",
			report:  `{}`,
			wantErr: "missing required results field",
		},
		{
			name:    "JSON array",
			report:  `[]`,
			wantErr: "expected a JSON object",
		},
		{
			name:    "SARIF document",
			report:  `{"version":"2.1.0","runs":[]}`,
			wantErr: "missing required results field",
		},
		{
			name:    "results are null",
			report:  `{"results":null,"summaryDetails":{"controls":{}}}`,
			wantErr: "results must be an array",
		},
		{
			name:    "results have wrong type",
			report:  `{"results":{},"summaryDetails":{"controls":{}}}`,
			wantErr: "invalid report results",
		},
		{
			name:    "missing summary",
			report:  `{"results":[]}`,
			wantErr: "missing required summaryDetails field",
		},
		{
			name:    "summary is null",
			report:  `{"results":[],"summaryDetails":null}`,
			wantErr: "summaryDetails must be an object",
		},
		{
			name:    "summary controls are missing",
			report:  `{"results":[],"summaryDetails":{}}`,
			wantErr: "missing required controls field",
		},
		{
			name:    "summary controls have wrong type",
			report:  `{"results":[],"summaryDetails":{"controls":[]}}`,
			wantErr: "invalid report summaryDetails.controls",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compute(writeRawReport(t, test.report), valid)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestComputeRejectsAmbiguousResultEntries(t *testing.T) {
	valid := writeTempReport(t, makeReport())
	tests := []struct {
		name    string
		report  scanReport
		wantErr string
	}{
		{
			name:    "empty resource ID",
			report:  makeReport(makeResult("", makeControl("C-001", "Control", "failed"))),
			wantErr: "resourceID is empty",
		},
		{
			name:    "empty control ID",
			report:  makeReport(makeResult("resource", makeControl("", "Control", "failed"))),
			wantErr: "controlID is empty",
		},
		{
			name:    "empty status",
			report:  makeReport(makeResult("resource", makeControl("C-001", "Control", ""))),
			wantErr: "status.status is empty",
		},
		{
			name: "duplicate resource control pair",
			report: makeReport(
				makeResult("resource", makeControl("C-001", "Control", "passed")),
				makeResult("resource", makeControl("C-001", "Control", "failed")),
			),
			wantErr: "duplicate resource and control pair",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compute(writeTempReport(t, test.report), valid)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestComputeAcceptsEmptyKubescapeReports(t *testing.T) {
	base := writeTempReport(t, makeReport())
	head := writeTempReport(t, makeReport())

	changes, err := Compute(base, head)
	require.NoError(t, err)
	assert.Empty(t, changes.New)
	assert.Empty(t, changes.Resolved)
	assert.Empty(t, changes.Unchanged)
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

func TestPrintYAML(t *testing.T) {
	cs := &ChangeSet{
		New: []ControlChange{
			{
				ResourceID:  "path-123/api/v1/Pod/demo",
				ControlID:   "C-0057",
				ControlName: "Privileged container",
				BaseStatus:  "",
				HeadStatus:  "failed",
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, PrintYAML(&buf, cs))
	yamlStr := buf.String()

	assert.Contains(t, yamlStr, "resourceID: path-123/api/v1/Pod/demo")
	assert.Contains(t, yamlStr, "controlID: C-0057")
	assert.Contains(t, yamlStr, "controlName: Privileged container")
}

func TestCompute_OutputOrderIsDeterministic(t *testing.T) {
	const controlsPerResource = 13
	resourceIDs := []string{"path-1/api/v1/Pod/alpha", "path-2/api/v1/Pod/bravo"}
	scoreFactors := []float32{9.5, 7.0, 5.0, 2.0}

	controlSummaries := make(map[string]controlSummary, controlsPerResource)
	baseResults := make([]resultEntry, 0, len(resourceIDs))
	headResults := make([]resultEntry, 0, len(resourceIDs))

	for _, resourceID := range resourceIDs {
		baseControls := make([]controlEntry, 0, controlsPerResource)
		headControls := make([]controlEntry, 0, controlsPerResource)

		for i := 0; i < controlsPerResource; i++ {
			controlID := fmt.Sprintf("C-%03d", i)
			controlName := "Control " + controlID
			controlSummaries[controlID] = controlSummary{ScoreFactor: scoreFactors[i%len(scoreFactors)]}

			baseStatus, headStatus := "failed", "failed"
			switch i % 3 {
			case 1:
				baseStatus, headStatus = "passed", "failed"
			case 2:
				baseStatus, headStatus = "failed", "passed"
			}

			baseControls = append(baseControls, makeControl(controlID, controlName, baseStatus))
			headControls = append(headControls, makeControl(controlID, controlName, headStatus))
		}

		baseResults = append(baseResults, makeResult(resourceID, baseControls...))
		headResults = append(headResults, makeResult(resourceID, headControls...))
	}

	summary := summaryDetails{Controls: controlSummaries}
	baseFile := writeTempReport(t, scanReport{Results: baseResults, SummaryDetails: summary})
	headFile := writeTempReport(t, scanReport{Results: headResults, SummaryDetails: summary})

	first, err := Compute(baseFile, headFile)
	require.NoError(t, err)

	buckets := []struct {
		name    string
		changes []ControlChange
		want    [][3]string
	}{
		{"New", first.New, [][3]string{
			{"Critical", "path-1/api/v1/Pod/alpha", "C-004"},
			{"Critical", "path-2/api/v1/Pod/bravo", "C-004"},
			{"High", "path-1/api/v1/Pod/alpha", "C-001"},
			{"High", "path-2/api/v1/Pod/bravo", "C-001"},
			{"Medium", "path-1/api/v1/Pod/alpha", "C-010"},
			{"Medium", "path-2/api/v1/Pod/bravo", "C-010"},
			{"Low", "path-1/api/v1/Pod/alpha", "C-007"},
			{"Low", "path-2/api/v1/Pod/bravo", "C-007"},
		}},
		{"Resolved", first.Resolved, [][3]string{
			{"Critical", "path-1/api/v1/Pod/alpha", "C-008"},
			{"Critical", "path-2/api/v1/Pod/bravo", "C-008"},
			{"High", "path-1/api/v1/Pod/alpha", "C-005"},
			{"High", "path-2/api/v1/Pod/bravo", "C-005"},
			{"Medium", "path-1/api/v1/Pod/alpha", "C-002"},
			{"Medium", "path-2/api/v1/Pod/bravo", "C-002"},
			{"Low", "path-1/api/v1/Pod/alpha", "C-011"},
			{"Low", "path-2/api/v1/Pod/bravo", "C-011"},
		}},
		{"Unchanged", first.Unchanged, [][3]string{
			{"Critical", "path-1/api/v1/Pod/alpha", "C-000"},
			{"Critical", "path-1/api/v1/Pod/alpha", "C-012"},
			{"Critical", "path-2/api/v1/Pod/bravo", "C-000"},
			{"Critical", "path-2/api/v1/Pod/bravo", "C-012"},
			{"High", "path-1/api/v1/Pod/alpha", "C-009"},
			{"High", "path-2/api/v1/Pod/bravo", "C-009"},
			{"Medium", "path-1/api/v1/Pod/alpha", "C-006"},
			{"Medium", "path-2/api/v1/Pod/bravo", "C-006"},
			{"Low", "path-1/api/v1/Pod/alpha", "C-003"},
			{"Low", "path-2/api/v1/Pod/bravo", "C-003"},
		}},
	}
	for _, bucket := range buckets {
		require.Len(t, bucket.changes, len(bucket.want), bucket.name)
		for i, want := range bucket.want {
			require.Equal(t, want, [3]string{bucket.changes[i].Severity, bucket.changes[i].ResourceID, bucket.changes[i].ControlID}, "%s[%d]", bucket.name, i)
		}
	}

	for run := 2; run <= 5; run++ {
		got, err := Compute(baseFile, headFile)
		require.NoError(t, err)
		require.Equal(t, first.New, got.New, "New ordered differently on run %d for identical inputs", run)
		require.Equal(t, first.Resolved, got.Resolved, "Resolved ordered differently on run %d for identical inputs", run)
		require.Equal(t, first.Unchanged, got.Unchanged, "Unchanged ordered differently on run %d for identical inputs", run)
	}
}
