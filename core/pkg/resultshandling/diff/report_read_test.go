package diff

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalPostureReport = `{"results":[],"summaryDetails":{"controls":{}}}`

// paddedReport writes a valid posture report followed by whitespace so the
// file is exactly size bytes.
func paddedReport(t *testing.T, size int) string {
	t.Helper()
	content := append([]byte(minimalPostureReport), bytes.Repeat([]byte(" "), size-len(minimalPostureReport))...)
	path := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

func TestReadReportRejectsDirectory(t *testing.T) {
	_, err := readReport(t.TempDir())
	require.ErrorIs(t, err, errReportNotRegular)
}

func TestReadReportEnforcesSizeLimit(t *testing.T) {
	data, err := readReport(paddedReport(t, maxReportSize))
	require.NoError(t, err)
	assert.Len(t, data, maxReportSize)

	_, err = readReport(paddedReport(t, maxReportSize+1))
	require.ErrorIs(t, err, errReportTooLarge)
}

func TestLoadersUseBoundedRead(t *testing.T) {
	oversized := paddedReport(t, maxReportSize+1)

	_, err := loadReport(oversized)
	require.ErrorIs(t, err, errReportTooLarge)

	_, err = loadVulnerabilityReport(oversized)
	require.ErrorIs(t, err, errReportTooLarge)

	// The deciding key sits beyond the limit, so it is never reached.
	late := filepath.Join(t.TempDir(), "late.json")
	content := append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), maxReportSize)...)
	content = append(content, []byte(`","results":[]}`)...)
	require.NoError(t, os.WriteFile(late, content, 0o600))
	assert.Equal(t, UnreadableReport, ReportKindOf(late))

	report, err := loadReport(paddedReport(t, maxReportSize))
	require.NoError(t, err)
	assert.Empty(t, report.Results)
}

func TestCompareReportsKeepsMixedKindsAndRejectsDirectory(t *testing.T) {
	posture := writeRawReport(t, minimalPostureReport)
	vulnerability := writeJSONReport(t, imageDocument("app:1"))

	_, _, _, err := CompareReports(posture, vulnerability, Options{})
	require.ErrorIs(t, err, ErrMixedReportKinds)

	_, _, _, err = CompareReports(posture, t.TempDir(), Options{})
	require.ErrorIs(t, err, errReportNotRegular)
}
