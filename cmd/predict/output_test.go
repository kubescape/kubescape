package predict

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kubescape/kubescape/v4/core/pkg/pss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleResult() pss.NamespaceResult {
	return pss.NamespaceResult{
		Namespace:             "test-ns",
		TargetLevel:           pss.Restricted,
		TotalWorkloads:        2,
		PassingWorkloads:      1,
		FailingWorkloads:      1,
		UnevaluatedWorkloads:  0,
		CurrentEffectiveLevel: pss.Baseline,
		Results: []pss.WorkloadResult{
			{
				Kind:     "Deployment",
				Name:     "failing-app",
				PassesAt: pss.Baseline,
				Violations: []pss.Violation{
					{
						Check:       "Capabilities",
						Container:   "main",
						Level:       pss.Restricted,
						Description: "container 'main' must drop ALL capabilities",
					},
				},
			},
			{
				Kind:       "Pod",
				Name:       "passing-app",
				PassesAt:   pss.Restricted,
				Violations: nil,
			},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	res := sampleResult()
	var buf bytes.Buffer
	err := writeJSON(&buf, res)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "test-ns", parsed["namespace"])
	assert.Equal(t, "Restricted", parsed["target_level"])

	summary, ok := parsed["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), summary["total_workloads"])
	assert.Equal(t, float64(1), summary["passing"])
	assert.Equal(t, float64(1), summary["failing"])
	assert.Equal(t, "Baseline", summary["current_effective_level"])

	failing, ok := parsed["failing_workloads"].([]any)
	require.True(t, ok)
	require.Len(t, failing, 1)

	fw := failing[0].(map[string]any)
	assert.Equal(t, "Deployment", fw["kind"])
	assert.Equal(t, "failing-app", fw["name"])
	assert.Equal(t, "Baseline", fw["passes_at"])
}

// TestWriteTable verifies tabular output for failing workloads and verbose mode.
func TestWriteTable(t *testing.T) {
	res := sampleResult()

	// Non-verbose: only failing workloads
	var buf bytes.Buffer
	err := writeTable(&buf, res, false)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "KIND")
	assert.Contains(t, out, "NAME")
	assert.Contains(t, out, "failing-app")
	assert.NotContains(t, out, "passing-app")
	assert.Contains(t, out, "Summary: 1/2 workloads pass at Restricted (current effective level: Baseline)")

	// Verbose: includes passing workloads
	buf.Reset()
	err = writeTable(&buf, res, true)
	require.NoError(t, err)
	outVerbose := buf.String()

	assert.Contains(t, outVerbose, "failing-app")
	assert.Contains(t, outVerbose, "passing-app")
}

// TestWriteTable_WithDecodeWarnings verifies that unevaluated workloads and
// decode warnings are displayed in the summary table before the summary line.
func TestWriteTable_WithDecodeWarnings(t *testing.T) {
	res := sampleResult()
	res.UnevaluatedWorkloads = 1
	res.TotalWorkloads += 1
	res.DecodeWarnings = []string{"Pod/bad-pod: PodSpec extraction failed"}

	var buf bytes.Buffer
	err := writeTable(&buf, res, false)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "Warnings (1 unevaluated):")
	assert.Contains(t, out, "⚠ Pod/bad-pod: PodSpec extraction failed")
	assert.Contains(t, out, "Summary: 1/3 workloads pass at Restricted (current effective level: Baseline)")
}

func TestWritePretty(t *testing.T) {
	res := sampleResult()

	var buf bytes.Buffer
	err := writePretty(&buf, res, false)
	require.NoError(t, err)
	out := buf.String()

	assert.Contains(t, out, "PSS Compliance Prediction")
	assert.Contains(t, out, "Namespace:    test-ns")
	assert.Contains(t, out, "Target Level: Restricted")
	assert.Contains(t, out, "Failing Workloads (1):")
	assert.Contains(t, out, "✗ Deployment/failing-app  (passes at: Baseline)")
	assert.Contains(t, out, "Capabilities [main] (Restricted):")
	assert.NotContains(t, out, "Passing Workloads")

	// Verbose: includes passing workloads
	buf.Reset()
	err = writePretty(&buf, res, true)
	require.NoError(t, err)
	outVerbose := buf.String()

	assert.Contains(t, outVerbose, "Passing Workloads (1):")
	assert.Contains(t, outVerbose, "✓ Pod/passing-app")
}

func TestWritePretty_Empty(t *testing.T) {
	res := pss.NamespaceResult{
		Namespace:   "empty-ns",
		TargetLevel: pss.Restricted,
	}

	var buf bytes.Buffer
	err := writePretty(&buf, res, false)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "No workloads found.")
}

// TestWriteSARIF verifies SARIF report generation for sample prediction results.
func TestWriteSARIF(t *testing.T) {
	res := sampleResult()

	var buf bytes.Buffer
	err := writeSARIF(&buf, res)
	require.NoError(t, err)

	var report sarifReport
	err = json.Unmarshal(buf.Bytes(), &report)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", report.Version)
	require.Len(t, report.Runs, 1)
	run := report.Runs[0]
	assert.Equal(t, "kubescape", run.Tool.Driver.Name)

	require.Len(t, run.Tool.Driver.Rules, 1)
	assert.Equal(t, "PSS/Capabilities", run.Tool.Driver.Rules[0].ID)

	require.Len(t, run.Results, 1)
	assert.Equal(t, "PSS/Capabilities", run.Results[0].RuleID)
	assert.Equal(t, 0, run.Results[0].RuleIndex)
	assert.Equal(t, "warning", run.Results[0].Level)
	require.NotEmpty(t, run.Results[0].Locations)
	assert.Equal(t, "failing-app", run.Results[0].Locations[0].LogicalLocations[0].Name)
	assert.Equal(t, "test-ns/Deployment/failing-app/main", run.Results[0].Locations[0].LogicalLocations[0].FullyQualifiedName)
}

// TestWriteSARIF_DeterministicRuleOrdering verifies that SARIF rules are sorted
// alphabetically by rule ID rather than emitting in non-deterministic map order,
// and that each result's ruleIndex points to the correct rule in the driver.
func TestWriteSARIF_DeterministicRuleOrdering(t *testing.T) {
	res := pss.NamespaceResult{
		Namespace:        "test-ns",
		TargetLevel:      pss.Restricted,
		TotalWorkloads:   2,
		PassingWorkloads: 0,
		FailingWorkloads: 2,
		Results: []pss.WorkloadResult{
			{
				Kind:     "Deployment",
				Name:     "app-a",
				PassesAt: pss.Privileged,
				Violations: []pss.Violation{
					{Check: "Privileged", Level: pss.Baseline, Description: "container is privileged"},
					{Check: "Capabilities", Level: pss.Restricted, Description: "drop ALL capabilities"},
				},
			},
			{
				Kind:     "DaemonSet",
				Name:     "app-b",
				PassesAt: pss.Privileged,
				Violations: []pss.Violation{
					{Check: "HostNetwork", Level: pss.Baseline, Description: "hostNetwork not allowed"},
					{Check: "AllowPrivilegeEscalation", Level: pss.Restricted, Description: "allowPrivilegeEscalation must be false"},
				},
			},
		},
	}

	for i := 0; i < 5; i++ {
		var buf bytes.Buffer
		err := writeSARIF(&buf, res)
		require.NoError(t, err)

		var report sarifReport
		err = json.Unmarshal(buf.Bytes(), &report)
		require.NoError(t, err)

		require.Len(t, report.Runs, 1)
		driver := report.Runs[0].Tool.Driver
		require.Len(t, driver.Rules, 4)

		expectedRules := []string{
			"PSS/AllowPrivilegeEscalation",
			"PSS/Capabilities",
			"PSS/HostNetwork",
			"PSS/Privileged",
		}
		for idx, expectedID := range expectedRules {
			assert.Equal(t, expectedID, driver.Rules[idx].ID)
		}

		for _, result := range report.Runs[0].Results {
			require.GreaterOrEqual(t, result.RuleIndex, 0)
			require.Less(t, result.RuleIndex, len(driver.Rules))
			assert.Equal(t, result.RuleID, driver.Rules[result.RuleIndex].ID)
		}
	}
}

// TestWriteSARIF_CleanReport verifies that a clean report outputs empty slices rather than null.
func TestWriteSARIF_CleanReport(t *testing.T) {
	// A report with no failing results should serialize empty arrays for rules and results, not null
	res := pss.NamespaceResult{
		Namespace:        "clean-ns",
		TargetLevel:      pss.Restricted,
		TotalWorkloads:   1,
		PassingWorkloads: 1,
		Results: []pss.WorkloadResult{
			{Kind: "Pod", Name: "clean-pod", PassesAt: pss.Restricted},
		},
	}

	var buf bytes.Buffer
	err := writeSARIF(&buf, res)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, `"rules": []`)
	assert.Contains(t, out, `"results": []`)
}

// TestWriteJUnit verifies JUnit XML output generation and aggregate counters.
func TestWriteJUnit(t *testing.T) {
	res := sampleResult()

	var buf bytes.Buffer
	err := writeJUnit(&buf, res)
	require.NoError(t, err)

	var suites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &suites)
	require.NoError(t, err)

	assert.Equal(t, 2, suites.Tests)
	assert.Equal(t, 1, suites.Failures)
	assert.Equal(t, 0, suites.Skipped)

	require.Len(t, suites.TestSuite, 1)
	suite := suites.TestSuite[0]
	assert.Equal(t, "PSS Compliance: test-ns @ Restricted", suite.Name)
	assert.Equal(t, 2, suite.Tests)
	assert.Equal(t, 1, suite.Failures)
	assert.Equal(t, 0, suite.Skipped)

	require.Len(t, suite.TestCases, 2)
	assert.Equal(t, "Deployment/failing-app", suite.TestCases[0].Name)
	assert.NotNil(t, suite.TestCases[0].Failure)
	assert.Contains(t, suite.TestCases[0].Failure.Text, "Capabilities")

	assert.Equal(t, "Pod/passing-app", suite.TestCases[1].Name)
	assert.Nil(t, suite.TestCases[1].Failure)
}

// TestWriteJUnit_WithDecodeWarnings verifies JUnit XML output when unevaluated workloads exist.
func TestWriteJUnit_WithDecodeWarnings(t *testing.T) {
	res := sampleResult()
	res.UnevaluatedWorkloads = 1
	res.TotalWorkloads += 1
	res.DecodeWarnings = []string{"Pod/bad-pod: PodSpec extraction failed"}

	var buf bytes.Buffer
	err := writeJUnit(&buf, res)
	require.NoError(t, err)

	var suites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &suites)
	require.NoError(t, err)

	assert.Equal(t, 3, suites.Tests)
	assert.Equal(t, 1, suites.Failures)
	assert.Equal(t, 1, suites.Skipped)

	require.Len(t, suites.TestSuite, 1)
	suite := suites.TestSuite[0]
	assert.Equal(t, 3, suite.Tests)
	assert.Equal(t, 1, suite.Failures)
	assert.Equal(t, 1, suite.Skipped)

	require.Len(t, suite.TestCases, 3)
	skippedCase := suite.TestCases[2]
	assert.Equal(t, "Pod/bad-pod: PodSpec extraction failed", skippedCase.Name)
	assert.Equal(t, "pss.test-ns.unevaluated", skippedCase.ClassName)
	require.NotNil(t, skippedCase.Skipped)
	assert.Equal(t, "Pod/bad-pod: PodSpec extraction failed", skippedCase.Skipped.Message)
}

func TestWriteOutput_Dispatch(t *testing.T) {
	res := sampleResult()

	for _, format := range []string{"json", "table", "sarif", "junit", "pretty-printer"} {
		t.Run(format, func(t *testing.T) {
			err := writeOutput(res, format, "", false)
			assert.NoError(t, err)
		})
	}

	err := writeOutput(res, "unknown-format", "", false)
	assert.Error(t, err)
}

type errWriter struct {
	err error
}

func (e *errWriter) Write(p []byte) (n int, err error) {
	return 0, e.err
}

type failAfterNWriter struct {
	remaining int
	err       error
}

func (w *failAfterNWriter) Write(p []byte) (n int, err error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	w.remaining--
	return len(p), nil
}

func TestWriteTable_FailingWriter(t *testing.T) {
	res := sampleResult()

	t.Run("immediate write failure", func(t *testing.T) {
		ew := &errWriter{err: errors.New("write failed")}
		err := writeTable(ew, res, false)
		assert.Error(t, err)
		assert.Equal(t, "write failed", err.Error())
	})

	t.Run("flush failure", func(t *testing.T) {
		fw := &failAfterNWriter{remaining: 1, err: errors.New("flush failed")}
		err := writeTable(fw, res, false)
		assert.Error(t, err)
	})
}

func TestWritePretty_FailingWriter(t *testing.T) {
	res := sampleResult()

	t.Run("immediate write failure", func(t *testing.T) {
		ew := &errWriter{err: errors.New("write failed")}
		err := writePretty(ew, res, false)
		assert.Error(t, err)
		assert.Equal(t, "write failed", err.Error())
	})

	t.Run("mid-stream write failure", func(t *testing.T) {
		fw := &failAfterNWriter{remaining: 2, err: errors.New("disk full")}
		err := writePretty(fw, res, true)
		assert.Error(t, err)
		assert.Equal(t, "disk full", err.Error())
	})
}

type countingWriter struct {
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

func TestWriteJUnit_FailingWriter(t *testing.T) {
	res := sampleResult()

	t.Run("immediate write failure on header", func(t *testing.T) {
		ew := &errWriter{err: errors.New("write failed")}
		err := writeJUnit(ew, res)
		assert.Error(t, err)
		assert.Equal(t, "write failed", err.Error())
	})

	t.Run("write failure on trailing newline", func(t *testing.T) {
		var cw countingWriter
		require.NoError(t, writeJUnit(&cw, res))
		// Fail on the very last write (trailing newline)
		fw := &failAfterNWriter{remaining: cw.writes - 1, err: errors.New("disk full")}
		err := writeJUnit(fw, res)
		assert.Error(t, err)
		assert.Equal(t, "disk full", err.Error())
	})
}

func TestWriteOutput_NestedDirectoryAndPermissions(t *testing.T) {
	res := sampleResult()
	tmpDir := t.TempDir()

	t.Run("creates nested directories and writes json output", func(t *testing.T) {
		nestedOutput := filepath.Join(tmpDir, "nested", "sub", "report.json")
		err := writeOutput(res, "json", nestedOutput, false)
		require.NoError(t, err)

		info, err := os.Stat(nestedOutput)
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular())

		// On Unix systems, verify permissions are 0600
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}

		data, err := os.ReadFile(nestedOutput)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"namespace": "test-ns"`)
	})

	t.Run("supports all valid formats when writing to file", func(t *testing.T) {
		formats := []string{"json", "table", "sarif", "junit", "pretty-printer"}
		for _, fmtName := range formats {
			outPath := filepath.Join(tmpDir, fmtName+"-report.out")
			err := writeOutput(res, fmtName, outPath, true)
			require.NoError(t, err, "format %s should succeed", fmtName)

			info, err := os.Stat(outPath)
			require.NoError(t, err)
			assert.Greater(t, info.Size(), int64(0))
		}
	})

	t.Run("tightens permissions on pre-existing file", func(t *testing.T) {
		existingFile := filepath.Join(tmpDir, "existing.json")
		require.NoError(t, os.WriteFile(existingFile, []byte("old content"), 0o600))
		if runtime.GOOS != "windows" {
			require.NoError(t, os.Chmod(existingFile, 0o644))
			initialInfo, err := os.Stat(existingFile)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o644), initialInfo.Mode().Perm())
		}

		err := writeOutput(res, "json", existingFile, false)
		require.NoError(t, err)

		info, err := os.Stat(existingFile)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	})

	t.Run("returns error on unsupported format", func(t *testing.T) {
		outPath := filepath.Join(tmpDir, "invalid.out")
		err := writeOutput(res, "unknown-format", outPath, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported format")
	})

	t.Run("preserves symlink target resolution without overwriting lexical sentinel", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on windows")
		}
		baseDir := t.TempDir()
		sentinel := filepath.Join(baseDir, "report.json")
		require.NoError(t, os.WriteFile(sentinel, []byte("sentinel content"), 0o600))

		physicalDir := filepath.Join(baseDir, "physical", "child")
		require.NoError(t, os.MkdirAll(physicalDir, 0o750))

		linkPath := filepath.Join(baseDir, "link")
		require.NoError(t, os.Symlink(physicalDir, linkPath))

		outputPath := linkPath + string(filepath.Separator) + ".." + string(filepath.Separator) + "report.json"
		err := writeOutput(res, "json", outputPath, false)
		require.NoError(t, err)

		// Sentinel in baseDir must remain untouched
		sentinelContent, err := os.ReadFile(sentinel)
		require.NoError(t, err)
		assert.Equal(t, "sentinel content", string(sentinelContent))

		// Actual target in physical directory must be written
		targetFile := filepath.Join(baseDir, "physical", "report.json")
		targetContent, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		assert.Contains(t, string(targetContent), `"namespace": "test-ns"`)
	})

	t.Run("fails when output path has trailing slash and leaves sentinel untouched", func(t *testing.T) {
		baseDir := t.TempDir()
		sentinelFile := filepath.Join(baseDir, "report.json")
		require.NoError(t, os.WriteFile(sentinelFile, []byte("sentinel content"), 0o600))

		trailingSlashPath := sentinelFile + string(filepath.Separator)
		err := writeOutput(res, "json", trailingSlashPath, false)
		assert.Error(t, err)

		sentinelContent, err := os.ReadFile(sentinelFile)
		require.NoError(t, err)
		assert.Equal(t, "sentinel content", string(sentinelContent))
	})
}
