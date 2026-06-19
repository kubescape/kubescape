package printer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
