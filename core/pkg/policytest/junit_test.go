package policytest

import (
	"context"
	"encoding/xml"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeJUnit(t *testing.T, report []byte) junitTestSuites {
	t.Helper()
	require.True(t, strings.HasPrefix(string(report), xml.Header), "report must start with the XML declaration")
	var decoded junitTestSuites
	require.NoError(t, xml.Unmarshal(report, &decoded))
	return decoded
}

func TestJUnitReport_GroupsCasesByRule(t *testing.T) {
	results := []CaseResult{
		{RuleName: "rule-a", CaseName: "clean", Passed: true, Duration: 1500 * time.Millisecond},
		{RuleName: "rule-a", CaseName: "flagged", Diff: "-want\n+got", Duration: 500 * time.Millisecond},
		{RuleName: "rule-b", CaseName: "broken", Err: errors.New("load input: bad yaml"), Duration: 250 * time.Millisecond},
	}

	report, err := JUnitReport(results)
	require.NoError(t, err)
	got := decodeJUnit(t, report)

	assert.Equal(t, "kubescape policy test", got.Name)
	assert.Equal(t, 3, got.Tests)
	assert.Equal(t, 1, got.Failures)
	assert.Equal(t, 1, got.Errors)
	assert.Equal(t, "2.250", got.Time)
	require.Len(t, got.Suites, 2)

	a := got.Suites[0]
	assert.Equal(t, "rule-a", a.Name)
	assert.Equal(t, 2, a.Tests)
	assert.Equal(t, 1, a.Failures)
	assert.Equal(t, 0, a.Errors)
	assert.Equal(t, "2.000", a.Time)
	require.Len(t, a.Cases, 2)

	clean := a.Cases[0]
	assert.Equal(t, "clean", clean.Name)
	assert.Equal(t, "rule-a", clean.ClassName)
	assert.Equal(t, "1.500", clean.Time)
	assert.Nil(t, clean.Failure, "a passing case must not carry a failure")
	assert.Nil(t, clean.Error, "a passing case must not carry an error")

	flagged := a.Cases[1]
	assert.Equal(t, "flagged", flagged.Name)
	require.NotNil(t, flagged.Failure)
	assert.Nil(t, flagged.Error, "a mismatch is a failure, not an error")
	assert.Equal(t, "rule output does not match expected.json", flagged.Failure.Message)
	assert.Equal(t, "-want\n+got", flagged.Failure.Text)

	b := got.Suites[1]
	assert.Equal(t, "rule-b", b.Name)
	assert.Equal(t, 1, b.Tests)
	assert.Equal(t, 0, b.Failures)
	assert.Equal(t, 1, b.Errors)
	require.Len(t, b.Cases, 1)
	require.NotNil(t, b.Cases[0].Error)
	assert.Nil(t, b.Cases[0].Failure, "a case that could not be evaluated is an error, not a failure")
	assert.Equal(t, "load input: bad yaml", b.Cases[0].Error.Message)
	assert.Equal(t, "load input: bad yaml", b.Cases[0].Error.Text)
}

func TestJUnitReport_SuitesFollowFirstAppearance(t *testing.T) {
	results := []CaseResult{
		{RuleName: "zeta", CaseName: "one", Passed: true},
		{RuleName: "alpha", CaseName: "one", Passed: true},
		{RuleName: "zeta", CaseName: "two", Passed: true},
	}

	report, err := JUnitReport(results)
	require.NoError(t, err)
	got := decodeJUnit(t, report)

	require.Len(t, got.Suites, 2)
	assert.Equal(t, "zeta", got.Suites[0].Name)
	assert.Equal(t, 2, got.Suites[0].Tests)
	assert.Equal(t, "alpha", got.Suites[1].Name)
	assert.Equal(t, 1, got.Suites[1].Tests)
}

func TestJUnitReport_EscapesDiffText(t *testing.T) {
	diff := `-	"alertMessage": "a < b && c > d"` + "\n+\tnull"
	results := []CaseResult{{RuleName: "rule", CaseName: "case", Diff: diff}}

	report, err := JUnitReport(results)
	require.NoError(t, err)
	got := decodeJUnit(t, report)

	require.Len(t, got.Suites, 1)
	require.Len(t, got.Suites[0].Cases, 1)
	require.NotNil(t, got.Suites[0].Cases[0].Failure)
	assert.Equal(t, diff, got.Suites[0].Cases[0].Failure.Text)
}

func TestJUnitReport_NoResults(t *testing.T) {
	report, err := JUnitReport(nil)
	require.NoError(t, err)
	got := decodeJUnit(t, report)

	assert.Equal(t, 0, got.Tests)
	assert.Equal(t, "0.000", got.Time)
	assert.Empty(t, got.Suites)
}

func TestRunRule_RecordsCaseDuration(t *testing.T) {
	rules, err := DiscoverPath(filepath.Join(rulesRoot(t), "modify-node-status-v1"))
	require.NoError(t, err)
	require.Len(t, rules, 1)

	results := RunRule(context.Background(), rules[0])
	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Positive(t, r.Duration, "case %s", r.CaseName)
	}
}
