package predict

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
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
	assert.Equal(t, "warning", run.Results[0].Level)
	require.NotEmpty(t, run.Results[0].Locations)
	assert.Equal(t, "failing-app", run.Results[0].Locations[0].LogicalLocations[0].Name)
	assert.Equal(t, "test-ns/Deployment/failing-app/main", run.Results[0].Locations[0].LogicalLocations[0].FullyQualifiedName)
}

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

func TestWriteJUnit(t *testing.T) {
	res := sampleResult()

	var buf bytes.Buffer
	err := writeJUnit(&buf, res)
	require.NoError(t, err)

	var suites junitTestSuites
	err = xml.Unmarshal(buf.Bytes(), &suites)
	require.NoError(t, err)

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
