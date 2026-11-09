package diff

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func marshalReport(t *testing.T, r scanReport) []byte {
	t.Helper()
	if r.Results == nil {
		r.Results = []resultEntry{}
	}
	if r.SummaryDetails.Controls == nil {
		r.SummaryDetails.Controls = map[string]controlSummary{}
	}
	data, err := json.Marshal(r)
	require.NoError(t, err)
	return data
}

func TestComputeFromJSONMatchesComputeWithOptions(t *testing.T) {
	summary := summaryDetails{Controls: map[string]controlSummary{"C-001": {ScoreFactor: 7.0}, "C-002": {ScoreFactor: 3.0}}}
	base := scanReport{
		Results: []resultEntry{
			makeResult("res1", makeControl("C-001", "Control 1", "failed"), makeControl("C-002", "Control 2", "passed")),
		},
		SummaryDetails: summary,
	}
	head := scanReport{
		Results: []resultEntry{
			makeResult("res1", makeControl("C-001", "Control 1", "passed"), makeControl("C-002", "Control 2", "failed")),
		},
		SummaryDetails: summary,
	}

	for _, granularity := range []Granularity{"", GranularityEvidence, GranularityControl} {
		options := Options{Granularity: granularity}
		want, err := ComputeWithOptions(writeTempReport(t, base), writeTempReport(t, head), options)
		require.NoError(t, err)

		got, err := ComputeFromJSON(marshalReport(t, base), marshalReport(t, head), options)
		require.NoError(t, err)

		assert.Equal(t, want, got, "granularity %q", granularity)
		assert.Len(t, got.Resolved, 1)
		assert.Len(t, got.New, 1)
	}
}

func TestComputeFromJSONRejectsWhatLoadReportRejects(t *testing.T) {
	valid := marshalReport(t, makeReport())
	for _, tt := range []struct {
		name   string
		report string
	}{
		{"empty", ``},
		{"not an object", `[]`},
		{"missing results", `{"summaryDetails":{"controls":{}}}`},
		{"null results", `{"results":null,"summaryDetails":{"controls":{}}}`},
		{"missing summary", `{"results":[]}`},
		{"empty resource id", `{"results":[{"resourceID":"","controls":[]}],"summaryDetails":{"controls":{}}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ComputeFromJSON([]byte(tt.report), valid, Options{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "loading base report")

			_, err = ComputeFromJSON(valid, []byte(tt.report), Options{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "loading head report")

			path := writeRawReport(t, tt.report)
			_, fileErr := ComputeWithOptions(path, writeTempReport(t, makeReport()), Options{})
			require.Error(t, fileErr, "the file path must reject the same input")
		})
	}
}

func TestComputeFromJSONRejectsInvalidGranularity(t *testing.T) {
	valid := marshalReport(t, makeReport())
	_, err := ComputeFromJSON(valid, valid, Options{Granularity: "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid diff granularity")
}

func TestComputeFromJSONRejectsOversizedReport(t *testing.T) {
	valid := marshalReport(t, makeReport())
	oversized := []byte(strings.Repeat(" ", maxReportSize+1))

	_, err := ComputeFromJSON(oversized, valid, Options{})
	require.ErrorIs(t, err, errReportTooLarge)
	_, err = ComputeFromJSON(valid, oversized, Options{})
	require.ErrorIs(t, err, errReportTooLarge)
}

func TestComputeFromJSONDoesNotTouchTheFilesystem(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	valid := marshalReport(t, makeReport())
	_, err := ComputeFromJSON(valid, valid, Options{})
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
