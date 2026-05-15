package printer

import (
	"bytes"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update-golden", false, "regenerate JUnit golden fixture under testdata/")

func TestJunitPrinter(t *testing.T) {
	// Verbose mode off
	jp := NewJunitPrinter(false)
	assert.NotNil(t, jp)
	assert.Equal(t, false, jp.verbose)

	// Verbose mode on
	jp = NewJunitPrinter(true)
	assert.NotNil(t, jp)
	assert.Equal(t, true, jp.verbose)
}

func TestScore_Junit(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 21\n",
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 50\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "\nOverall compliance-score (100- Excellent, 0- All failed): 100\n",
		},
	}

	jp := NewJunitPrinter(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to capture output
			f, err := os.CreateTemp("", "score-output")
			if err != nil {
				panic(err)
			}
			defer f.Close()

			// Redirect stderr to the temporary file
			oldStderr := os.Stderr
			defer func() {
				os.Stderr = oldStderr
			}()
			os.Stderr = f

			// Print the score using the `Score` function
			jp.Score(tt.score)

			// Read the contents of the temporary file
			f.Seek(0, 0)
			got, err := io.ReadAll(f)
			if err != nil {
				panic(err)
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestTestSuites(t *testing.T) {
	results := cautils.NewOPASessionObjMock()
	junitTestSuites := testsSuites(results)

	assert.NotNil(t, junitTestSuites)
	assert.Equal(t, listTestsSuite(results), junitTestSuites.Suites)
	assert.Equal(t, results.Report.SummaryDetails.NumberOfControls().All(), junitTestSuites.Tests)
	assert.Equal(t, "Kubescape Scanning", junitTestSuites.Name)
}

func TestListTestSuites(t *testing.T) {
	// Non empty OPASessionObj
	results := cautils.NewOPASessionObjMock()
	testsSuites := listTestsSuite(results)

	if assert.Len(t, testsSuites, 1) {
		// Timestamp is generated from time.Now() when the report has no
		// generation time set, so just assert it parses as ISO 8601 and zero it
		// out before comparing the rest of the struct.
		_, err := time.Parse("2006-01-02T15:04:05Z", testsSuites[0].Timestamp)
		assert.NoError(t, err, "timestamp should be ISO 8601")
		testsSuites[0].Timestamp = ""
	}

	expectedTestSuites := []JUnitTestSuite{
		{
			XMLName:  xml.Name{Space: "", Local: ""},
			Tests:    0,
			Name:     "kubescape",
			Errors:   0,
			Failures: 0,
			Hostname: "",
			ID:       0,
			Skipped:  0,
			Time:     "",
			Properties: []JUnitProperty{
				{Name: "complianceScore", Value: "0.00"},
			},
			TestCases: []JUnitTestCase(nil),
		},
	}

	assert.Equal(t, expectedTestSuites, testsSuites)
}

func TestProperties(t *testing.T) {
	tests := []struct {
		name             string
		score            float32
		expectedProperty []JUnitProperty
	}{
		{
			name:  "Score not an integer",
			score: 20.7,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 20.7),
				},
			},
		},
		{
			name:  "Score less than 0",
			score: -20.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", -20.0),
				},
			},
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 120.0),
				},
			},
		},
		{
			name:  "Score 50",
			score: 50.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 50.0),
				},
			},
		},
		{
			name:  "Zero Score",
			score: 0.0,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 0.0),
				},
			},
		},
		{
			name:  "Perfect Score",
			score: 100,
			expectedProperty: []JUnitProperty{
				{
					Name:  "complianceScore",
					Value: fmt.Sprintf("%.2f", 100.0),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedProperty, properties(tt.score))
		})
	}
}

func TestTestCases_SkipMessage(t *testing.T) {
	tests := []struct {
		name      string
		subStatus apis.ScanningSubStatus
		innerInfo string
		wantMsg   string
	}{
		{
			name:      "not evaluated",
			subStatus: apis.SubStatusNotEvaluated,
			innerInfo: string(apis.SubStatusNotEvaluatedInfo),
			wantMsg:   "notEvaluated: " + string(apis.SubStatusNotEvaluatedInfo),
		},
		{
			name:      "configuration",
			subStatus: apis.SubStatusConfiguration,
			innerInfo: string(apis.SubStatusConfigurationInfo),
			wantMsg:   "configuration: " + string(apis.SubStatusConfigurationInfo),
		},
		{
			name:      "manual review",
			subStatus: apis.SubStatusManualReview,
			innerInfo: string(apis.SubStatusManualReviewInfo),
			wantMsg:   "manual review: " + string(apis.SubStatusManualReviewInfo),
		},
		{
			name:      "requires review",
			subStatus: apis.SubStatusRequiresReview,
			innerInfo: string(apis.SubStatusRequiresReviewInfo),
			wantMsg:   "requires review: " + string(apis.SubStatusRequiresReviewInfo),
		},
		{
			name:      "unknown substatus no info",
			subStatus: apis.SubStatusUnknown,
			innerInfo: "",
			wantMsg:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := cautils.NewOPASessionObjMock()
			results.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{
				"C-0001": reportsummary.ControlSummary{
					ControlID: "C-0001",
					Name:      "test-control",
					StatusInfo: apis.StatusInfo{
						InnerStatus: apis.StatusSkipped,
						SubStatus:   tt.subStatus,
						InnerInfo:   tt.innerInfo,
					},
				},
			}

			cases := testsCases(results, &results.Report.SummaryDetails.Controls, "TestSuite")

			if assert.Len(t, cases, 1) {
				if tt.wantMsg == "" {
					if cases[0].SkipMessage != nil {
						assert.Equal(t, tt.wantMsg, cases[0].SkipMessage.Message)
					}
				} else {
					if assert.NotNil(t, cases[0].SkipMessage) {
						assert.Equal(t, tt.wantMsg, cases[0].SkipMessage.Message)
					}
				}
				assert.Nil(t, cases[0].Failure)
			}
		})
	}
}

func TestSetWriter_Junit(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		expected   string
	}{
		{
			name:       "Output file name contains doesn't contain any extension",
			outputFile: "customFilename",
			expected:   "customFilename.xml",
		},
		{
			name:       "Output file name contains .xml",
			outputFile: "customFilename.xml",
			expected:   "customFilename.xml",
		},
		{
			name:       "Output file name is empty",
			outputFile: "",
			expected:   "/dev/stdout",
		},
	}

	jp := NewJunitPrinter(false)
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			jp.SetWriter(ctx, tt.outputFile)
			assert.Equal(t, tt.expected, jp.writer.Name())
		})
	}
}

func TestBuildSkipMessage(t *testing.T) {
	tests := []struct {
		name     string
		status   apis.IStatus
		expected string
	}{
		{
			name:     "nil status returns empty string",
			status:   nil,
			expected: "",
		},
		{
			name:     "configuration substatus with InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusConfiguration, InnerInfo: "control not configured"},
			expected: "configuration: control not configured",
		},
		{
			name:     "irrelevant substatus no InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusIrrelevant},
			expected: "irrelevant",
		},
		{
			name:     "manual review substatus with InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusManualReview, InnerInfo: "requires manual check"},
			expected: "manual review: requires manual check",
		},
		{
			name:     "notEvaluated substatus with InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusNotEvaluated, InnerInfo: "not evaluated"},
			expected: "notEvaluated: not evaluated",
		},
		{
			name:     "requires review substatus no InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: apis.SubStatusRequiresReview},
			expected: "requires review",
		},
		{
			name:     "empty subStatus with InnerInfo returns only InnerInfo",
			status:   &apis.StatusInfo{InnerStatus: apis.StatusSkipped, SubStatus: "", InnerInfo: "some detail"},
			expected: "some detail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSkipMessage(tt.status)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestJunitOutputInvariants is a regression test for the bugs reported in
// issue #2099: counts mismatch, zero-time timestamps, missing XML prolog,
// string-typed Skipped attribute, multi-line failure messages, and empty
// attributes. It exercises the full ActionPrint path against a mock session
// populated from the shared mock_summaryDetails.json fixture and asserts the
// invariants standard JUnit parsers depend on.
func TestJunitOutputInvariants(t *testing.T) {
	mockSummary, err := mockSummaryDetails()
	require.NoError(t, err)

	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: *mockSummary,
	}

	tmp, err := os.CreateTemp("", "junit-regression-*.xml")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	jp := NewJunitPrinter(false)
	jp.writer = tmp
	jp.ActionPrint(context.Background(), session, nil)
	require.NoError(t, tmp.Close())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	// 4c — XML prolog present.
	assert.True(t, bytes.HasPrefix(raw, []byte("<?xml")), "output must start with XML prolog")

	// Round-trip through encoding/xml to ensure the document is well-formed.
	var got JUnitXML
	dec := xml.NewDecoder(bytes.NewReader(raw))
	require.NoError(t, dec.Decode(&got.TestSuites), "output must round-trip through encoding/xml")
	require.NotEmpty(t, got.TestSuites.Suites, "expected at least one <testsuite>")

	// 4a — Σ(children) == parent for tests, failures, errors. This is a
	// structural invariant any conformant JUnit document must satisfy; on the
	// single-framework fixture used here it is trivially true even under the
	// pre-fix code, so the *regression* of the deduplicated-parent bug is
	// covered by TestJunitMultiFrameworkSharedControl below, which fabricates
	// two frameworks sharing a control and asserts parent counts are derived
	// from the child suites rather than SummaryDetails.NumberOfControls().
	var sumTests, sumFailures, sumErrors int
	for _, s := range got.TestSuites.Suites {
		sumTests += s.Tests
		sumFailures += s.Failures
		sumErrors += s.Errors
	}
	assert.Equal(t, sumTests, got.TestSuites.Tests, "parent tests must equal sum of child tests")
	assert.Equal(t, sumFailures, got.TestSuites.Failures, "parent failures must equal sum of child failures")
	assert.Equal(t, sumErrors, got.TestSuites.Errors, "parent errors must equal sum of child errors")

	// 4b — Timestamp is ISO 8601, not Go's default zero time.
	for _, s := range got.TestSuites.Suites {
		assert.NotContains(t, s.Timestamp, "0001-01-01", "timestamp must not be Go zero time")
		_, perr := time.Parse("2006-01-02T15:04:05Z", s.Timestamp)
		assert.NoError(t, perr, "timestamp %q must be ISO 8601", s.Timestamp)
	}

	// 4d — Skipped is now typed as int; the marshaller no longer emits skipped="".
	assert.NotContains(t, string(raw), `skipped=""`, "skipped attribute must not be an empty string")

	// 4e — Failure body lives in chardata, not in a multi-line message attribute.
	for _, s := range got.TestSuites.Suites {
		for _, tc := range s.TestCases {
			if tc.Failure == nil {
				continue
			}
			assert.NotContains(t, tc.Failure.Message, "\n", "failure message attribute must not contain newlines")
			if strings.Contains(tc.Failure.Contents, "Remediation:") {
				// remediation detail must live in element body, not the attribute
				assert.NotContains(t, tc.Failure.Message, "Remediation:", "remediation belongs in the element body")
			}
		}
	}

	// 4f — Optional attributes are omitted when empty.
	assert.NotContains(t, string(raw), `hostname=""`, "empty hostname attribute should be omitted")
	assert.NotContains(t, string(raw), `time=""`, "empty time attribute should be omitted")

	// Sanity check: golden testdata fixture still exists alongside this test.
	_, statErr := os.Stat(filepath.Join("testdata", "mock_summaryDetails.json"))
	assert.NoError(t, statErr)
}

// TestJunitGoldenFile pins the marshalled JUnit output byte-for-byte against
// testdata/junit_golden.xml so future regressions of the issue #2099 fixes are
// caught at review time. A fixed ReportGenerationTime keeps the output
// deterministic; run with `go test -update-golden` to regenerate the fixture.
func TestJunitGoldenFile(t *testing.T) {
	mockSummary, err := mockSummaryDetails()
	require.NoError(t, err)

	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails:       *mockSummary,
		ReportGenerationTime: time.Date(2024, 3, 14, 9, 15, 26, 0, time.UTC),
	}

	tmp, err := os.CreateTemp("", "junit-golden-*.xml")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	jp := NewJunitPrinter(false)
	jp.writer = tmp
	jp.ActionPrint(context.Background(), session, nil)
	require.NoError(t, tmp.Close())

	got, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	goldenPath := filepath.Join("testdata", "junit_golden.xml")
	if *updateGolden {
		require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
	}

	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden fixture missing — run `go test -update-golden`")
	assert.Equal(t, string(want), string(got), "marshalled JUnit output diverged from testdata/junit_golden.xml")

	// Also round-trip the golden file through encoding/xml and re-check the
	// invariants on the *stored* fixture so a hand-edited golden that breaks
	// JUnit semantics still fails the test.
	var doc JUnitXML
	require.NoError(t, xml.NewDecoder(bytes.NewReader(want)).Decode(&doc.TestSuites))
	require.True(t, bytes.HasPrefix(want, []byte("<?xml")), "golden must include XML prolog")
	var sumTests, sumFailures, sumErrors int
	for _, s := range doc.TestSuites.Suites {
		sumTests += s.Tests
		sumFailures += s.Failures
		sumErrors += s.Errors
		assert.NotContains(t, s.Timestamp, "0001-01-01", "golden timestamp must not be Go zero time")
	}
	assert.Equal(t, sumTests, doc.TestSuites.Tests, "golden: Σ child tests must equal parent")
	assert.Equal(t, sumFailures, doc.TestSuites.Failures, "golden: Σ child failures must equal parent")
	assert.Equal(t, sumErrors, doc.TestSuites.Errors, "golden: Σ child errors must equal parent")
}

// TestIso8601Timestamp covers the small helper that powers the timestamp fix
// in 4b — including the fallback when ReportGenerationTime is the zero value.
func TestIso8601Timestamp(t *testing.T) {
	fixed := time.Date(2024, 3, 14, 9, 15, 26, 0, time.UTC)
	assert.Equal(t, "2024-03-14T09:15:26Z", iso8601Timestamp(fixed))

	got := iso8601Timestamp(time.Time{})
	_, err := time.Parse("2006-01-02T15:04:05Z", got)
	assert.NoError(t, err, "zero time must fall back to a valid ISO 8601 timestamp, got %q", got)
}

// TestJunitMultiFrameworkSharedControl directly targets the issue #2099/4a
// regression: when 2+ frameworks share a control, the parent <testsuites>
// totals must equal Σ(children), not the deduplicated control count.
//
// The single-framework fixture used elsewhere cannot exercise this because the
// deduplicated SummaryDetails count and the per-framework count happen to be
// equal. Here we build a synthetic posture with two frameworks that both
// reference the same failed control, then assert:
//
//   - Σ child Tests == 2 (each framework contributes one testcase)
//   - parent.Tests == Σ child Tests (would be 1 under the old, regressed code)
//   - parent.Tests != SummaryDetails.NumberOfControls().All() (would be 1)
//
// If testsSuites ever regresses to sourcing parent counts from
// SummaryDetails.NumberOfControls() this test fails.
func TestJunitMultiFrameworkSharedControl(t *testing.T) {
	sharedID := "C-9999"
	failed := apis.StatusInfo{InnerStatus: apis.StatusFailed}
	sharedCtrl := reportsummary.ControlSummary{
		ControlID:  sharedID,
		Name:       "Shared failing control",
		StatusInfo: failed,
		Status:     apis.StatusFailed,
	}

	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			// Top-level Controls map is deduplicated — the shared control
			// appears here exactly once. SummaryDetails.NumberOfControls().All()
			// will therefore return 1.
			Controls: reportsummary.ControlSummaries{sharedID: sharedCtrl},
			Frameworks: []reportsummary.FrameworkSummary{
				{
					Name:     "F1",
					Controls: reportsummary.ControlSummaries{sharedID: sharedCtrl},
				},
				{
					Name:     "F2",
					Controls: reportsummary.ControlSummaries{sharedID: sharedCtrl},
				},
			},
		},
	}

	// Sanity-check the assumption that drives the regression: the
	// deduplicated parent counter and Σ(per-framework counters) disagree.
	require.Equal(t, 1, session.Report.SummaryDetails.NumberOfControls().All(),
		"precondition: dedup'd SummaryDetails counts the shared control once")
	require.Equal(t, 2,
		session.Report.SummaryDetails.Frameworks[0].NumberOfControls().All()+
			session.Report.SummaryDetails.Frameworks[1].NumberOfControls().All(),
		"precondition: per-framework counts double-count the shared control")

	suites := testsSuites(session)

	// Σ(children) must equal 2 — each framework yields a <testsuite> with one
	// <testcase>. This is the value parsers will see when summing children.
	var sumTests, sumFailures int
	for _, s := range suites.Suites {
		sumTests += s.Tests
		sumFailures += s.Failures
	}
	require.Equal(t, 2, sumTests, "Σ child tests should be 2 across the two frameworks")
	require.Equal(t, 2, sumFailures, "Σ child failures should be 2 across the two frameworks")

	// The fix: parent equals Σ(children). The regression: parent would equal
	// SummaryDetails.NumberOfControls().All() == 1.
	assert.Equal(t, sumTests, suites.Tests,
		"parent Tests must equal Σ child Tests (regressed code returns 1)")
	assert.Equal(t, sumFailures, suites.Failures,
		"parent Failures must equal Σ child Failures (regressed code returns 1)")
	assert.NotEqual(t, session.Report.SummaryDetails.NumberOfControls().All(), suites.Tests,
		"parent Tests must NOT be the deduplicated SummaryDetails count")
}

// TestAggregateSuiteCounts covers the Tests/Failures/Errors aggregator
// directly. The production code path in junit.go never populates child
// Errors (the printer only emits <failure> and <skipped>), so the multi-
// framework regression test above cannot exercise the errors branch via
// testsSuites. This unit test pins the loop itself.
func TestAggregateSuiteCounts(t *testing.T) {
	cases := []struct {
		name                                 string
		in                                   []JUnitTestSuite
		wantTests, wantFailures, wantErrors  int
	}{
		{
			name: "empty slice yields zeros",
		},
		{
			name: "errors aggregate across suites independently of failures",
			in: []JUnitTestSuite{
				{Tests: 5, Failures: 1, Errors: 2},
				{Tests: 3, Failures: 0, Errors: 4},
			},
			wantTests: 8, wantFailures: 1, wantErrors: 6,
		},
		{
			name: "mixed: errors-only, failures-only, and a clean suite",
			in: []JUnitTestSuite{
				{Tests: 4, Errors: 4},
				{Tests: 2, Failures: 2},
				{Tests: 7},
			},
			wantTests: 13, wantFailures: 2, wantErrors: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotTests, gotFailures, gotErrors := aggregateSuiteCounts(tc.in)
			assert.Equal(t, tc.wantTests, gotTests, "tests")
			assert.Equal(t, tc.wantFailures, gotFailures, "failures")
			assert.Equal(t, tc.wantErrors, gotErrors, "errors")
		})
	}
}
