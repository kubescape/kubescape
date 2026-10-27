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

	// An oversized report is unreadable even when its deciding key comes first.
	early := filepath.Join(t.TempDir(), "early.json")
	content := append([]byte(`{"results":[],"pad":"`), bytes.Repeat([]byte("a"), maxReportSize)...)
	content = append(content, []byte(`"}`)...)
	require.NoError(t, os.WriteFile(early, content, 0o600))
	assert.Equal(t, UnreadableReport, ReportKindOf(early))

	report, err := loadReport(paddedReport(t, maxReportSize))
	require.NoError(t, err)
	assert.Empty(t, report.Results)
}

func TestCompareReportsKeepsMixedKindsAndRejectsDirectory(t *testing.T) {
	posture := writeRawReport(t, minimalPostureReport)
	vulnerability := writeJSONReport(t, imageDocument("app:1"))

	_, _, _, err := CompareReports(posture, vulnerability, Options{})
	require.ErrorIs(t, err, ErrMixedReportKinds)

	kind, _, _, err := CompareReports(posture, t.TempDir(), Options{})
	require.ErrorIs(t, err, errReportNotRegular)
	assert.Equal(t, PostureReport, kind)

	kind, _, _, err = CompareReports(vulnerability, t.TempDir(), Options{})
	require.ErrorIs(t, err, errReportNotRegular)
	assert.Equal(t, VulnerabilityReport, kind)
	assert.Contains(t, err.Error(), "loading head report")

	kind, _, _, err = CompareReports(t.TempDir(), vulnerability, Options{})
	require.ErrorIs(t, err, errReportNotRegular)
	assert.Equal(t, VulnerabilityReport, kind)
	assert.Contains(t, err.Error(), "loading base report")
}

func TestCompareReportsVulnerabilityWithUnreadableFile(t *testing.T) {
	vulnerability := writeJSONReport(t, imageDocument("app:1"))
	missing := filepath.Join(t.TempDir(), "missing.json")
	oversized := paddedReport(t, maxReportSize+1)

	t.Run("missing head file", func(t *testing.T) {
		kind, _, _, err := CompareReports(vulnerability, missing, Options{})
		require.Error(t, err)
		assert.Equal(t, VulnerabilityReport, kind)
		assert.Contains(t, err.Error(), "loading head report")
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("missing base file", func(t *testing.T) {
		kind, _, _, err := CompareReports(missing, vulnerability, Options{})
		require.Error(t, err)
		assert.Equal(t, VulnerabilityReport, kind)
		assert.Contains(t, err.Error(), "loading base report")
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("oversized head file", func(t *testing.T) {
		kind, _, _, err := CompareReports(vulnerability, oversized, Options{})
		require.ErrorIs(t, err, errReportTooLarge)
		assert.Equal(t, VulnerabilityReport, kind)
		assert.Contains(t, err.Error(), "loading head report")
	})

	t.Run("oversized base file", func(t *testing.T) {
		kind, _, _, err := CompareReports(oversized, vulnerability, Options{})
		require.ErrorIs(t, err, errReportTooLarge)
		assert.Equal(t, VulnerabilityReport, kind)
		assert.Contains(t, err.Error(), "loading base report")
	})
}
