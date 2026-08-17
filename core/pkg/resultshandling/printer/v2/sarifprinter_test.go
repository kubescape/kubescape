package printer

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_scoreToSeverityLevel(t *testing.T) {
	tc := []struct {
		Name               string
		ScoreFactor        float32
		ExpectedSARIFLevel sarifSeverityLevel
	}{
		{"Score factor 1.0 should map to 'note' SARIF level", 1.0, sarifSeverityLevelNote},
		{"Score facore 4.0 should map to 'warning' SARIF level", 4.0, sarifSeverityLevelWarning},
		{"Score facore 7.0 should map to 'warning' SARIF level", 7.0, sarifSeverityLevelWarning},
		{"Score facore 9.0 should map to 'error' SARIF level", 9.0, sarifSeverityLevelError},
	}

	for _, testCase := range tc {
		t.Run(testCase.Name, func(t *testing.T) {
			got := scoreFactorToSARIFSeverityLevel(testCase.ScoreFactor)
			want := testCase.ExpectedSARIFLevel

			if got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}

func Test_collectDiffs(t *testing.T) {
	tc := []struct {
		Name        string
		fileString  string
		fixedString string
		fixesNum    int
		region      [][4]int
		text        []string
	}{
		{
			"Collect diffs should work for fix object in sarif",

			`apiVersion: v1
kind: Pod
metadata:
  name: test

spec:
  containers:
  - name: nginx_container
    image: nginx
    securityContext:
      capabilities:
        drop: [NET_RAW]
      runAsRoot: true`,

			`apiVersion: v1
kind: Pod
metadata:
  name: test

spec:
  containers:
  - name: nginx_container
    image: nginx
    securityContext:
      capabilities:
        drop: [NET_RAW, SYS_ADM]
      runAsRoot: false
      allowPrivilegeEscalation: false`,
			3,
			[][4]int{
				{12, 23, 12, 23},
				{13, 18, 13, 19},
				{13, 20, 13, 21},
			},
			[]string{
				", SYS_ADM",
				`false
      allowP`,
				"ivilegeEscalation: fals",
			},
		},
	}

	for _, testCase := range tc {
		t.Run(testCase.Name, func(t *testing.T) {
			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(testCase.fileString, testCase.fixedString, false)
			run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
			result := run.CreateResultForRule("0")
			collectDiffs(dmp, diffs, result, "", testCase.fileString)
			if len(result.Fixes) != testCase.fixesNum {
				t.Errorf("wrong number of fixes, got %d, want %d", len(result.Fixes), testCase.fixesNum)
			}
			for index, fix := range result.Fixes {
				if len(fix.ArtifactChanges) != 1 {
					t.Errorf("wrong number of artifactChanges in fix %d, got %d, want %d", index, len(fix.ArtifactChanges), 1)
				}
				replacements := fix.ArtifactChanges[0].Replacements
				if len(replacements) != 1 {
					t.Errorf("wrong number of replacements in fix %d, got %d, want %d", index, len(replacements), 1)
				}
				startLine := *replacements[0].DeletedRegion.StartLine
				startColumn := *replacements[0].DeletedRegion.StartColumn
				endLine := *replacements[0].DeletedRegion.EndLine
				endColumn := *replacements[0].DeletedRegion.EndColumn
				location := testCase.region[index]
				if location[0] != startLine || location[1] != startColumn || location[2] != endLine || location[3] != endColumn {
					t.Errorf("wrong deleted region in fix %d, got (%d, %d, %d, %d), want (%d, %d, %d, %d)",
						index, startLine, startColumn, endLine, endColumn, location[0], location[1], location[2], location[3])
				}
				if testCase.text[index] != *replacements[0].InsertedContent.Text {
					t.Errorf("wrong inserted text in fix %d, got (%s), want (%s)",
						index, *replacements[0].InsertedContent.Text, testCase.text[index])
				}
			}
		})
	}
}

// The function correctly converts a string to an integer and returns the new line and column position based on the input string and current line and column position.
func TestCalculateMove(t *testing.T) {
	str := "5"
	file := []string{"line 1", "line 2", "line 3"}
	endColumn := 3
	endLine := 2

	newColumn, newLine, success := calculateMove(str, file, endColumn, endLine)

	assert.True(t, success)
	assert.Equal(t, 3, newColumn)
	assert.Equal(t, 1, newLine)
}

// The function handles the case where the end line is greater than the length of the file and returns false.
func TestCalculateMove_EndLineGreaterThanFileLength(t *testing.T) {
	str := "5"
	file := []string{"line 1", "line 2", "line 3"}
	endColumn := 3
	endLine := 5

	_, _, success := calculateMove(str, file, endColumn, endLine)

	assert.False(t, success)
}

// The input string is an empty string and returns false.
func TestCalculateMove_EmptyString(t *testing.T) {
	str := ""
	file := []string{"line 1", "line 2", "line 3"}
	endColumn := 3
	endLine := 2

	_, _, success := calculateMove(str, file, endColumn, endLine)

	assert.False(t, success)
}

// The input file is an empty array and returns false.
func TestCalculateMove_EmptyFile(t *testing.T) {
	str := "5"
	file := []string{}
	endColumn := 3
	endLine := 2

	endLine, endColumn, success := calculateMove(str, file, endColumn, endLine)

	assert.Equal(t, 0, endLine)
	assert.Equal(t, 0, endColumn)
	assert.False(t, success)
}

// The input file contains an empty line and adjusts the end line and column accordingly.
func TestCalculateMove_InvalidString(t *testing.T) {
	str := "abc"
	file := []string{"line 1", "line 2", "line 3"}
	endColumn := 3
	endLine := 2

	_, _, success := calculateMove(str, file, endColumn, endLine)

	assert.False(t, success)
}

// Lines containing multi-byte characters must be measured in runes, not bytes,
// or the computed position drifts past the line's actual length.
func TestCalculateMove_MultiByteRunes(t *testing.T) {
	str := "10"
	file := []string{"héllo world", "line 2", "line 3"}
	endColumn := 5
	endLine := 1

	newLine, newColumn, success := calculateMove(str, file, endColumn, endLine)

	assert.True(t, success)
	assert.Equal(t, 2, newLine)
	assert.Equal(t, 3, newColumn)
}

// The end line is 1-indexed, so values below 1 are as out of range as values past the end of the file and both return false.
func TestCalculateMove_EndLineOutOfRange(t *testing.T) {
	file := []string{"line 1", "line 2", "line 3"}

	tc := []struct {
		name      string
		file      []string
		endLine   int
		endColumn int
	}{
		{"zero end line, as left behind by a failed move", file, 0, 0},
		{"negative end line", file, -1, 1},
		{"end line one past the last line", file, 4, 1},
		{"any end line into an empty file", []string{}, 1, 1},
	}

	for _, testCase := range tc {
		t.Run(testCase.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				newLine, newColumn, success := calculateMove("5", testCase.file, testCase.endColumn, testCase.endLine)

				assert.False(t, success)
				assert.Equal(t, 0, newLine)
				assert.Equal(t, 0, newColumn)
			})
		})
	}
}

// A move that claims more characters than the file holds walks past the last line and returns false.
func TestCalculateMove_WalkPastLastLine(t *testing.T) {
	file := []string{"line 1", "line 2", "line 3"}

	assert.NotPanics(t, func() {
		newLine, newColumn, success := calculateMove("50", file, 1, 3)

		assert.False(t, success)
		assert.Equal(t, 0, newLine)
		assert.Equal(t, 0, newColumn)
	})
}

// A move that fails mid-delta leaves the position untouched, so later fixes keep 1-indexed regions instead of landing on line 0.
func TestCollectDiffs_FailedMoveKeepsRegionOneIndexed(t *testing.T) {
	// the equality run claims more content than the file holds, so the first move fails
	diffs := []diffmatchpatch.Diff{
		{Type: diffmatchpatch.DiffEqual, Text: strings.Repeat("a", 44)},
		{Type: diffmatchpatch.DiffInsert, Text: "x"},
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
	result := run.CreateResultForRule("0")

	assert.NotPanics(t, func() {
		collectDiffs(diffmatchpatch.New(), diffs, result, "", "short")
	})

	require.Len(t, result.Fixes, 1)
	replacements := result.Fixes[0].ArtifactChanges[0].Replacements
	require.Len(t, replacements, 1)

	region := replacements[0].DeletedRegion
	assert.Equal(t, 1, *region.StartLine)
	assert.Equal(t, 1, *region.StartColumn)
	assert.Equal(t, 1, *region.EndLine)
	assert.Equal(t, 1, *region.EndColumn)
}

// An empty diff set yields a single empty delta segment and collects no fixes.
func TestCollectDiffs_EmptyDelta(t *testing.T) {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain("", "", false)
	require.Empty(t, diffs)

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
	result := run.CreateResultForRule("0")

	assert.NotPanics(t, func() {
		collectDiffs(dmp, diffs, result, "", "")
	})

	assert.Empty(t, result.Fixes)
}

// The region lookahead reports the last segment and an equality run as closing, and tolerates an empty neighbor.
func TestClosesFixRegion(t *testing.T) {
	tc := []struct {
		name     string
		delta    []string
		index    int
		expected bool
	}{
		{"last segment closes the region", []string{"+abc", "=5"}, 1, true},
		{"next segment resumes unchanged content", []string{"+abc", "=5"}, 0, true},
		{"next segment continues the edit", []string{"+abc", "-5"}, 0, false},
		{"trailing empty segment leaves no operation to resume", []string{"+abc", ""}, 0, true},
		{"empty segments skipped before an equality run", []string{"+abc", "", "", "=5"}, 0, true},
		{"empty segments skipped before a further edit", []string{"+abc", "", "-5"}, 0, false},
		{"index past the end of the delta", []string{"+abc"}, 5, true},
	}

	for _, testCase := range tc {
		t.Run(testCase.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Equal(t, testCase.expected, closesFixRegion(testCase.delta, testCase.index))
			})
		})
	}
}

// Adds a new fix to the result with the given filepath, start and end positions, and text.
func TestAddFix_AddsNewFixToResult(t *testing.T) {
	result := sarif.Result{}
	filepath := "example/file.txt"
	startLine := 1
	startColumn := 1
	endLine := 2
	endColumn := 5
	text := "example text"

	addFix(&result, filepath, startLine, startColumn, endLine, endColumn, text)

	expectedFix := sarif.NewFix().WithArtifactChanges([]*sarif.ArtifactChange{
		sarif.NewArtifactChange(
			sarif.NewSimpleArtifactLocation(filepath),
		).WithReplacement(
			sarif.NewReplacement(sarif.NewRegion().
				WithStartLine(startLine).
				WithStartColumn(startColumn).
				WithEndLine(endLine).
				WithEndColumn(endColumn),
			).WithInsertedContent(
				sarif.NewArtifactContent().WithText(text),
			),
		),
	})

	assert.Equal(t, expectedFix, result.Fixes[0])
}

// TestAddRule_SetsSecuritySeverity is the regression test for
// kubescape/kubescape#2394: SARIF rules omitted properties["security-severity"],
// so GitHub Code Scanning had no severity to display or filter on. The value must
// mirror the control's score factor, formatted the same way grype emits it.
func TestAddRule_SetsSecuritySeverity(t *testing.T) {
	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)

	control := &reportsummary.ControlSummary{
		ControlID:   "C-0001",
		Name:        "Test control",
		Description: "a test control",
		Remediation: "do the thing",
		ScoreFactor: 8.5,
	}

	sp := NewSARIFPrinter()
	sp.addRule(run, control)

	require.Len(t, run.Tool.Driver.Rules, 1)
	rule := run.Tool.Driver.Rules[0]
	require.NotNil(t, rule.Properties, "rule properties must be set")
	assert.Equal(t, "8.5", rule.Properties["security-severity"],
		"security-severity must mirror the control score factor")
}

func TestPrintConfigurationScan_MissingControl(t *testing.T) {
	resourceID := "apps/v1/Deployment/default/my-deployment"

	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: "C-MISSING",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	result := resourcesresults.Result{
		ResourceID:         resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac},
	}
	require.True(t, result.GetStatus(nil).IsFailed())

	session := cautils.NewOPASessionObjMock()
	session.ResourcesResult[resourceID] = result
	session.ResourceSource = map[string]reporthandling.Source{
		resourceID: {RelativePath: "deploy.yaml"},
	}
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{},
		},
	}

	tmp, err := os.CreateTemp("", "sarif-missing-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	sp := NewSARIFPrinter()
	sp.writer = tmp

	assert.NotPanics(t, func() {
		err := sp.printConfigurationScan(context.Background(), session)
		assert.NoError(t, err)
	})
}

// TestPrintConfigurationScan_SkipsResourcesWithoutRelativePath verifies that a resource
// with no relative path is dropped even when a base path is available: the SARIF
// location is written from the relative path alone, so such a result would carry an
// empty artifact location, which GitHub Code Scanning rejects on upload.
func TestPrintConfigurationScan_SkipsResourcesWithoutRelativePath(t *testing.T) {
	const controlID = "C-0057"
	resourceID := "apps/v1/Deployment/default/demo"

	tests := []struct {
		name           string
		resourceSource reporthandling.Source
	}{
		{name: "no anchor at all", resourceSource: reporthandling.Source{}},
		{name: "resource path set", resourceSource: reporthandling.Source{Path: t.TempDir()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := cautils.NewOPASessionObjMock()
			session.Metadata = &reporthandlingv2.Metadata{
				ScanMetadata: reporthandlingv2.ScanMetadata{
					ScanningTarget: reporthandlingv2.Directory,
				},
				ContextMetadata: reporthandlingv2.ContextMetadata{
					DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
						BasePath: t.TempDir(),
					},
				},
			}
			session.ResourcesResult[resourceID] = resourcesresults.Result{
				ResourceID: resourceID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: controlID,
						Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
					},
				},
			}
			session.ResourceSource = map[string]reporthandling.Source{resourceID: tt.resourceSource}
			session.Report = &reporthandlingv2.PostureReport{
				SummaryDetails: reportsummary.SummaryDetails{
					Controls: reportsummary.ControlSummaries{
						controlID: reportsummary.ControlSummary{
							ControlID:   controlID,
							Name:        "Privileged container",
							Description: "Do not run privileged containers",
							ScoreFactor: 8.0,
						},
					},
				},
			}

			// the base path is non-empty, so only the missing relative path can skip this finding
			require.NotEmpty(t, getBasePathFromMetadata(*session))

			tmp, err := os.CreateTemp("", "sarif-norelpath-*.sarif")
			require.NoError(t, err)
			defer func() {
				assert.NoError(t, os.Remove(tmp.Name()))
			}()

			sp := NewSARIFPrinter()
			sp.writer = tmp
			require.NoError(t, sp.printConfigurationScan(context.Background(), session))
			require.NoError(t, tmp.Close())

			raw, err := os.ReadFile(tmp.Name())
			require.NoError(t, err)

			var report struct {
				Runs []struct {
					Results []json.RawMessage `json:"results"`
				} `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(raw, &report))
			require.Len(t, report.Runs, 1)
			assert.Empty(t, report.Runs[0].Results, "a result with no file location must not be emitted")
		})
	}
}

// TestPrintConfigurationScan_PopulatesInvocations is the regression test for
// the SARIF half of kubescape/kubescape#2325: runs[].invocations was absent
// from every SARIF report, so GitHub code-scanning ingestion collapsed every
// upload to "scanned just now" and there was no startTimeUtc/endTimeUtc.
func TestPrintConfigurationScan_PopulatesInvocations(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{},
		},
	}

	tmp, err := os.CreateTemp("", "sarif-invocations-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	sp := NewSARIFPrinter()
	sp.writer = tmp

	before := time.Now().UTC()
	require.NoError(t, sp.printConfigurationScan(context.Background(), session))
	after := time.Now().UTC()

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)

	invocations := report.Runs[0].Invocations
	require.Len(t, invocations, 1, "exactly one invocation must be recorded per run")

	inv := invocations[0]
	require.NotNil(t, inv.StartTimeUTC, "startTimeUtc must be populated")
	require.NotNil(t, inv.EndTimeUTC, "endTimeUtc must be populated")
	require.NotNil(t, inv.ExecutionSuccessful)
	assert.True(t, *inv.ExecutionSuccessful)

	// endTime is set just before the SARIF file is written, so it must fall
	// inside the [before, after] window observed by this test.
	assert.False(t, inv.EndTimeUTC.Before(before), "endTimeUtc precedes the test's before-marker")
	assert.False(t, inv.EndTimeUTC.After(after), "endTimeUtc is after the test's after-marker")
	assert.False(t, inv.EndTimeUTC.Before(*inv.StartTimeUTC), "endTimeUtc must be >= startTimeUtc")
}

// TestPrintConfigurationScan_InvocationStartTimeUsesReportGenerationTime
// verifies the start-time fallback chain: when ReportGenerationTime is already
// set (e.g. by FinalizeResults running earlier on the same session), the SARIF
// invocation uses it as startTimeUtc instead of "now". This keeps the JSON and
// SARIF outputs reporting the same scan start for the same scan.
func TestPrintConfigurationScan_InvocationStartTimeUsesReportGenerationTime(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	preset := time.Date(2024, 3, 14, 9, 15, 26, 0, time.UTC)
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{},
		},
		ReportGenerationTime: preset,
	}

	tmp, err := os.CreateTemp("", "sarif-start-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	sp := NewSARIFPrinter()
	sp.writer = tmp

	require.NoError(t, sp.printConfigurationScan(context.Background(), session))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Invocations, 1)

	inv := report.Runs[0].Invocations[0]
	require.NotNil(t, inv.StartTimeUTC)
	assert.True(t, inv.StartTimeUTC.Equal(preset),
		"startTimeUtc must reuse ReportGenerationTime, got %s want %s", inv.StartTimeUTC, preset)
}

// TestGetDocIndex_PathContainingColon guards against a regression where
// getDocIndex parsed LocalWorkload.GetPath() ("<file path>:<document
// index>") with strings.Split(path, ":")[1] instead of splitting on the last
// colon. That silently picked the wrong segment whenever the file path
// itself contained more than one colon (e.g. a Windows path like
// "C:\repo\deploy.yaml:0"), so strconv.Atoi failed on a non-numeric segment
// and getDocIndex reported "no document index" even though one exists. This
// must match how fixhandler.getFilePathAndIndex parses the same convention
// (splitting on the last colon).
func TestGetDocIndex_PathContainingColon(t *testing.T) {
	resourceID := "apps/v1/Deployment/default/demo"
	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "demo"},
		"spec":       map[string]interface{}{},
	}

	tests := []struct {
		name      string
		path      string
		wantIndex int
		wantOk    bool
	}{
		{name: "plain relative path, no colon in file path", path: "deploy.yaml:0", wantIndex: 0, wantOk: true},
		{name: "nested relative path", path: "charts/app/deploy.yaml:2", wantIndex: 2, wantOk: true},
		{name: "file path itself contains a colon", path: `C:\repo\deploy.yaml:3`, wantIndex: 3, wantOk: true},
		{name: "no colon at all", path: "deploy.yaml", wantIndex: 0, wantOk: false},
		{name: "trailing colon with non-numeric suffix", path: "deploy.yaml:abc", wantIndex: 0, wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lw := localworkload.NewLocalWorkload(obj)
			lw.SetPath(tt.path)

			session := cautils.NewOPASessionObjMock()
			session.AllResources[resourceID] = lw

			gotIndex, gotOk := getDocIndex(session, resourceID)
			assert.Equal(t, tt.wantOk, gotOk)
			if tt.wantOk {
				assert.Equal(t, tt.wantIndex, gotIndex)
			}
		})
	}
}

func TestGetBasePathFromMetadata(t *testing.T) {
	tempDir := t.TempDir()
	absFilePath := filepath.Join(tempDir, "deploy.yaml")

	tests := []struct {
		name    string
		session cautils.OPASessionObj
		want    string
	}{
		{
			name: "GitLocal",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.GitLocal,
					},
					ContextMetadata: reporthandlingv2.ContextMetadata{
						RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
							LocalRootPath: tempDir,
						},
					},
				},
			},
			want: tempDir,
		},
		{
			name: "GitLocal without repository metadata",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.GitLocal,
					},
				},
			},
			want: "",
		},
		{
			name:    "missing metadata",
			session: cautils.OPASessionObj{},
			want:    "",
		},
		{
			name: "Directory",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.Directory,
					},
					ContextMetadata: reporthandlingv2.ContextMetadata{
						DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{
							BasePath: tempDir,
						},
					},
				},
			},
			want: tempDir,
		},
		{
			name: "File",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.File,
					},
					ContextMetadata: reporthandlingv2.ContextMetadata{
						FileContextMetadata: &reporthandlingv2.FileContextMetadata{
							FilePath: absFilePath,
						},
					},
				},
			},
			want: tempDir,
		},
		{
			name: "File without metadata",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.File,
					},
				},
			},
			want: "",
		},
		{
			name: "Cluster",
			session: cautils.OPASessionObj{
				Metadata: &reporthandlingv2.Metadata{
					ScanMetadata: reporthandlingv2.ScanMetadata{
						ScanningTarget: reporthandlingv2.Cluster,
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getBasePathFromMetadata(tt.session))
		})
	}
}

// TestEffectiveBasePath verifies that a resource's own Source.Path wins over the
// scan-wide base path, because it is the root its RelativePath was computed from,
// while the scan-wide path covers only the first input pattern of a multi-input scan.
func TestEffectiveBasePath(t *testing.T) {
	tests := []struct {
		name           string
		resourceSource reporthandling.Source
		basePath       string
		want           string
	}{
		{
			name:           "resource path wins over the scan-wide base path",
			resourceSource: reporthandling.Source{Path: "/repo", RelativePath: "workloads/deploy.yaml"},
			basePath:       "/repo/workloads",
			want:           "/repo",
		},
		{
			name:           "sources without a path fall back to the scan-wide base path",
			resourceSource: reporthandling.Source{RelativePath: "deploy.yaml"},
			basePath:       "/repo",
			want:           "/repo",
		},
		{
			name:           "no anchor at all",
			resourceSource: reporthandling.Source{RelativePath: "deploy.yaml"},
			want:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, effectiveBasePath(tt.resourceSource, tt.basePath))
		})
	}
}

// TestPrintConfigurationScan_FileScanResolvesLineNumbers is the regression test
// for absolute-path single-file scans: SARIF must resolve real line numbers even
// when cwd differs from the manifest directory (common in CI).
func TestPrintConfigurationScan_FileScanResolvesLineNumbers(t *testing.T) {
	const privilegedLine = 13

	manifestDir := t.TempDir()
	manifestPath := filepath.Join(manifestDir, "deploy.yaml")
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata: {name: demo, namespace: default}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo}}
  template:
    metadata: {labels: {app: demo}}
    spec:
      containers:
      - name: app
        image: nginx:1.23
        securityContext: {privileged: true}
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0600))

	resourceID := "apps/v1/Deployment/default/demo"
	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath("deploy.yaml:0")

	controlID := "C-0001"
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:   "privileged-container",
				Status: apis.StatusFailed,
				Paths: []armotypes.PosturePaths{
					{
						FixPath: armotypes.FixPath{
							Path:  "spec.template.spec.containers[0].securityContext.privileged",
							Value: "false",
						},
					},
				},
			},
		},
	}

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{
			ScanningTarget: reporthandlingv2.File,
		},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			FileContextMetadata: &reporthandlingv2.FileContextMetadata{
				FilePath: manifestPath,
			},
		},
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID:         resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac},
	}
	session.ResourceSource = map[string]reporthandling.Source{
		resourceID: {
			Path:         manifestDir,
			RelativePath: "deploy.yaml",
			FileType:     reporthandling.SourceTypeYaml,
		},
	}
	session.AllResources[resourceID] = lw
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID: reportsummary.ControlSummary{
					ControlID:   controlID,
					Name:        "Privileged container",
					Description: "Do not run privileged containers",
					Remediation: "Set privileged to false",
					ScoreFactor: 8.0,
				},
			},
		},
	}

	tmp, err := os.CreateTemp("", "sarif-file-scan-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	otherWD := t.TempDir()
	require.NoError(t, os.Chdir(otherWD))

	sp := NewSARIFPrinter()
	sp.writer = tmp
	require.NoError(t, sp.printConfigurationScan(context.Background(), session))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	require.NotEmpty(t, report.Runs[0].Results)

	var startLines []int
	for _, result := range report.Runs[0].Results {
		require.NotEmpty(t, result.Locations)
		require.NotNil(t, result.Locations[0].PhysicalLocation)
		require.NotNil(t, result.Locations[0].PhysicalLocation.Region)
		startLines = append(startLines, *result.Locations[0].PhysicalLocation.Region.StartLine)
	}

	assert.Contains(t, startLines, privilegedLine,
		"SARIF must resolve the privileged field to line %d, got startLines=%v", privilegedLine, startLines)
	assert.NotEqual(t, []int{1}, startLines,
		"all findings must not collapse to line 1 for absolute-path file scans")
}

// TestPrintConfigurationScan_FailedPathGetsRelatedLocation is a regression test for evidence
// locations: a control's FailedPath previously had no location of its own in SARIF output - only
// the (possibly different) FixPath got the primary Locations entry. This asserts the FailedPath
// now resolves to its own relatedLocations entry, pointing at the actual line the failing field
// lives on, independent of where the fix would apply.
func TestPrintConfigurationScan_FailedPathGetsRelatedLocation(t *testing.T) {
	const (
		imageLine      = 12
		privilegedLine = 13
	)

	manifestDir := t.TempDir()
	manifestPath := filepath.Join(manifestDir, "deploy.yaml")
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata: {name: demo, namespace: default}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo}}
  template:
    metadata: {labels: {app: demo}}
    spec:
      containers:
      - name: app
        image: nginx:1.23
        securityContext: {privileged: true}
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0600))

	resourceID := "apps/v1/Deployment/default/demo"
	obj := map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]interface{}{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]interface{}{},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath("deploy.yaml:0")

	controlID := "C-0001"
	// FixPath targets a different field (image) than FailedPath (privileged), so their
	// resolved locations diverge - the test would pass by coincidence if they matched.
	ac := resourcesresults.ResourceAssociatedControl{
		ControlID: controlID,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:   "privileged-container",
				Status: apis.StatusFailed,
				Paths: []armotypes.PosturePaths{
					{
						FailedPath: "spec.template.spec.containers[0].securityContext.privileged",
						FixPath: armotypes.FixPath{
							Path:  "spec.template.spec.containers[0].image",
							Value: "nginx:1.25",
						},
					},
				},
			},
		},
	}

	session := cautils.NewOPASessionObjMock()
	session.Metadata = &reporthandlingv2.Metadata{
		ScanMetadata: reporthandlingv2.ScanMetadata{
			ScanningTarget: reporthandlingv2.File,
		},
		ContextMetadata: reporthandlingv2.ContextMetadata{
			FileContextMetadata: &reporthandlingv2.FileContextMetadata{
				FilePath: manifestPath,
			},
		},
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID:         resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{ac},
	}
	session.ResourceSource = map[string]reporthandling.Source{
		resourceID: {
			Path:         manifestDir,
			RelativePath: "deploy.yaml",
			FileType:     reporthandling.SourceTypeYaml,
		},
	}
	session.AllResources[resourceID] = lw
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				controlID: reportsummary.ControlSummary{
					ControlID:   controlID,
					Name:        "Privileged container",
					Description: "Do not run privileged containers",
					Remediation: "Set privileged to false",
					ScoreFactor: 8.0,
				},
			},
		},
	}

	tmp, err := os.CreateTemp("", "sarif-related-location-*.sarif")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	otherWD := t.TempDir()
	require.NoError(t, os.Chdir(otherWD))

	sp := NewSARIFPrinter()
	sp.writer = tmp
	require.NoError(t, sp.printConfigurationScan(context.Background(), session))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 1)

	result := report.Runs[0].Results[0]

	// Primary location follows the fix path (image), as before this change.
	require.NotEmpty(t, result.Locations)
	require.NotNil(t, result.Locations[0].PhysicalLocation.Region)
	assert.Equal(t, imageLine, *result.Locations[0].PhysicalLocation.Region.StartLine,
		"primary location should still resolve to the FixPath's line")

	// The FailedPath now gets its own relatedLocations entry, at its own line.
	require.Len(t, result.RelatedLocations, 1)
	relatedLoc := result.RelatedLocations[0]
	require.NotNil(t, relatedLoc.PhysicalLocation)
	require.NotNil(t, relatedLoc.PhysicalLocation.Region)
	assert.Equal(t, privilegedLine, *relatedLoc.PhysicalLocation.Region.StartLine,
		"relatedLocations must resolve the FailedPath to its own line, distinct from the fix location")
	require.NotNil(t, relatedLoc.Message)
	assert.Equal(t, "spec.template.spec.containers[0].securityContext.privileged", *relatedLoc.Message.Text)
}

// TestPrintImageScan_WriterIsNonSeekablePipe is a regression test for image
// SARIF output hanging when the destination is a pipe (e.g. stdout in a Unix
// pipeline). printImageScan used to render the report to sp.writer, then
// reopen sp.writer.Name() to patch the driver name and write it back. For a
// pipe there is nothing meaningful to reopen by name, so the fix renders and
// patches the report in memory and writes it to sp.writer exactly once. This
// test uses a real os.Pipe() as the writer, with a concurrent reader (playing
// the role of a downstream consumer like `tee` or `jq`), and asserts
// ActionPrint returns promptly with a correctly patched report.
func TestPrintImageScan_WriterIsNonSeekablePipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	sp := NewSARIFPrinter()
	sp.writer = w

	imageScanData := buildSeverityExceptionImageScanData()

	printDone := make(chan error, 1)
	go func() {
		printDone <- sp.ActionPrint(context.Background(), nil, []cautils.ImageScanData{imageScanData})
	}()

	readDone := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		readDone <- data
	}()

	select {
	case err := <-printDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("ActionPrint did not return within 5s: image SARIF output is hanging on a pipe writer")
	}

	require.NoError(t, w.Close())

	var raw []byte
	select {
	case raw = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading the piped SARIF output")
	}

	var report sarif.Report
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Len(t, report.Runs, 1)
	assert.Equal(t, "Kubescape", report.Runs[0].Tool.Driver.Name, "driver name must still be patched when writing to a pipe")
}
