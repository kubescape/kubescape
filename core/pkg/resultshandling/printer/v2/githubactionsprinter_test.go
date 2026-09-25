package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ghSessionFixture builds a session with one failed control on a real
// manifest, so the location resolver has a file to read. It mirrors the
// gitlab-sast fixture.
func ghSessionFixture(t *testing.T, controlID string, scoreFactor float32) *cautils.OPASessionObj {
	t.Helper()
	t.Setenv("GITHUB_STEP_SUMMARY", "")

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
					ScoreFactor: scoreFactor,
				},
			},
		},
	}
	return session
}

// ghOutputFor runs the printer against a session and returns the raw output.
func ghOutputFor(t *testing.T, session *cautils.OPASessionObj) string {
	t.Helper()

	tmp, err := os.CreateTemp("", "github-actions-*.txt")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	})

	gp := NewGitHubActionsPrinter()
	gp.writer = tmp
	require.NoError(t, gp.ActionPrint(context.Background(), session, nil))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return string(raw)
}

// TestGitHubActionsPrinter_GoldenAnnotation verifies the exact workflow-command
// shape and the resolved line number for a known failing control.
func TestGitHubActionsPrinter_GoldenAnnotation(t *testing.T) {
	const privilegedLine = 13

	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	output := ghOutputFor(t, ghSessionFixture(t, "C-0057", 8.0))

	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	require.NotEmpty(t, lines)
	wantMsg := fmt.Sprintf("High severity finding on apps/v1/Deployment/default/demo. Remediation: https://hub.armosec.io/docs/c-0057%%0AFailed paths:%%0Aspec.template.spec.containers[0].securityContext.privileged=false")
	assert.Equal(t,
		fmt.Sprintf("::error file=deploy.yaml,line=%d,title=C-0057 Privileged container::%s",
			privilegedLine, wantMsg),
		lines[0], "the first line must be the exact workflow command with evidence paths")
	assert.Contains(t, output, "1 of 1 High/Critical finding(s) annotated")
}

// TestGitHubActionsPrinter_EscapesPropertyValues pins the workflow-command
// escaping: control names containing ',' and ':' would otherwise corrupt the
// annotation's property list.
func TestGitHubActionsPrinter_EscapesPropertyValues(t *testing.T) {
	session := ghSessionFixture(t, "C-0001", 9.0)
	session.Report.SummaryDetails.Controls["C-0001"] = reportsummary.ControlSummary{
		ControlID:   "C-0001",
		Name:        "Privileged, with colon: and %percent",
		ScoreFactor: 9,
	}

	output := ghOutputFor(t, session)

	assert.Contains(t, output, "title=C-0001 Privileged%2C with colon%3A and %25percent",
		"property values must escape ',', ':' and '%'")
	assert.NotContains(t, output, "title=C-0001 Privileged, with colon:")
}

// TestGitHubActionsPrinter_FiltersBelowHighSeverity verifies only High and
// Critical findings become annotations; lower severities are counted in the
// summary instead.
func TestGitHubActionsPrinter_FiltersBelowHighSeverity(t *testing.T) {
	session := ghSessionFixture(t, "C-0001", 9.0)

	resourceID := "apps/v1/Deployment/default/demo"
	result := session.ResourcesResult[resourceID]
	for _, extra := range []struct {
		id          string
		scoreFactor float32
	}{
		{id: "C-0002", scoreFactor: 5},
		{id: "C-0003", scoreFactor: 2},
	} {
		result.AssociatedControls = append(result.AssociatedControls, resourcesresults.ResourceAssociatedControl{
			ControlID: extra.id,
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		})
		session.Report.SummaryDetails.Controls[extra.id] = reportsummary.ControlSummary{
			ControlID:   extra.id,
			Name:        "Lower severity control",
			ScoreFactor: extra.scoreFactor,
		}
	}
	session.ResourcesResult[resourceID] = result

	output := ghOutputFor(t, session)

	assert.Equal(t, 1, strings.Count(output, "::error "), "only the High/Critical finding may be annotated")
	assert.Contains(t, output, "2 finding(s) below the High severity threshold")
}

// TestGitHubActionsPrinter_CapsAtTenAnnotations mirrors GitHub's per-step cap:
// with twelve eligible findings, exactly the ten most severe (Critical before
// High, then ControlID order) are emitted and the remainder are summarized.
func TestGitHubActionsPrinter_CapsAtTenAnnotations(t *testing.T) {
	session := ghSessionFixture(t, "C-0001", 9.0)

	resourceID := "apps/v1/Deployment/default/demo"
	result := session.ResourcesResult[resourceID]
	for _, controlID := range []string{"C-0012", "C-0003", "C-0007", "C-0002", "C-0009", "C-0004", "C-0011", "C-0005", "C-0010", "C-0006", "C-0008", "C-0013"} {
		result.AssociatedControls = append(result.AssociatedControls, resourcesresults.ResourceAssociatedControl{
			ControlID: controlID,
			Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		})
		session.Report.SummaryDetails.Controls[controlID] = reportsummary.ControlSummary{
			ControlID:   controlID,
			Name:        "Control " + controlID,
			ScoreFactor: 9,
		}
	}
	session.ResourcesResult[resourceID] = result

	output := ghOutputFor(t, session)

	assert.Equal(t, 10, strings.Count(output, "::error "), "GitHub renders at most 10 error annotations per step")
	for _, controlID := range []string{"C-0001", "C-0002", "C-0003", "C-0004", "C-0005", "C-0006", "C-0007", "C-0008", "C-0009", "C-0010"} {
		assert.Contains(t, output, "title="+controlID+" ", "the lowest ControlIDs must be prioritized under the cap")
	}
	assert.NotContains(t, output, "title=C-0011 ")
	assert.NotContains(t, output, "title=C-0012 ")
	assert.NotContains(t, output, "title=C-0013 ")
	assert.Contains(t, output, "3 suppressed by GitHub's 10-annotation step limit")
}

// TestGitHubActionsPrinter_SkipsResourcesWithoutFilePath mirrors the GitLab
// SAST exclusion rules: findings with no repository-relative manifest path
// cannot be anchored to a PR line.
func TestGitHubActionsPrinter_SkipsResourcesWithoutFilePath(t *testing.T) {
	session := ghSessionFixture(t, "C-0057", 9.0)

	resourceID := "apps/v1/Deployment/default/demo"
	session.ResourceSource[resourceID] = reporthandling.Source{RelativePath: ""}

	output := ghOutputFor(t, session)

	assert.NotContains(t, output, "::error")
	assert.Contains(t, output, "0 of 0 High/Critical finding(s) annotated")
}

// TestGitHubActionsPrinter_RejectsImageScanData pins the config-scan boundary:
// image findings have no manifest location to anchor an annotation to.
func TestGitHubActionsPrinter_RejectsImageScanData(t *testing.T) {
	gp := NewGitHubActionsPrinter()

	err := gp.ActionPrint(context.Background(), nil, []cautils.ImageScanData{{}})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "only supported for configuration scanning")
}

// TestGitHubActionsPrinter_EmitsOnlyHighAndCritical pins the severity filter
// boundary: score factor 7 (High) is annotated, 6 (Medium) is not.
func TestGitHubActionsPrinter_EmitsOnlyHighAndCritical(t *testing.T) {
	tests := []struct {
		name          string
		scoreFactor   float32
		wantAnnotated bool
	}{
		{name: "critical is annotated", scoreFactor: 9, wantAnnotated: true},
		{name: "high is annotated", scoreFactor: 7, wantAnnotated: true},
		{name: "medium is not annotated", scoreFactor: 6, wantAnnotated: false},
		{name: "low is not annotated", scoreFactor: 2, wantAnnotated: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := ghOutputFor(t, ghSessionFixture(t, "C-0057", tt.scoreFactor))
			if tt.wantAnnotated {
				assert.Contains(t, output, "::error file=deploy.yaml,")
			} else {
				assert.NotContains(t, output, "::error")
			}
		})
	}
}

// TestEscapeAnnotationData verifies the message-part escaping GitHub's
// workflow-command syntax requires.
func TestEscapeAnnotationData(t *testing.T) {
	assert.Equal(t, "100%25 done", escapeAnnotationData("100% done"))
	assert.Equal(t, "line1%0Aline2", escapeAnnotationData("line1\nline2"))
	assert.Equal(t, "cr%0Dend", escapeAnnotationData("cr\rend"))
	assert.Equal(t, "comma,colon:no", escapeAnnotationData("comma,colon:no"),
		"the data portion tolerates ',' and ':' — only the property list escapes them")
}

// TestEscapeAnnotationProperty verifies the property-part escaping, which must
// additionally mask the ',' and ':' delimiters.
func TestEscapeAnnotationProperty(t *testing.T) {
	assert.Equal(t, "100%25 done", escapeAnnotationProperty("100% done"))
	assert.Equal(t, "a%2Cb%3Ac", escapeAnnotationProperty("a,b:c"))
	assert.Equal(t, "nl%0Aend", escapeAnnotationProperty("nl\nend"))
}

// TestGitHubActionsPrinter_EvidencePathsInMessage verifies that when a
// resource has assisted-remediation paths, they are appended to the annotation
// message so developers see the failing field directly in the PR annotation.
func TestGitHubActionsPrinter_EvidencePathsInMessage(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	output := ghOutputFor(t, session)

	// The fix path from the fixture is spec.template.spec.containers[0].securityContext.privileged=false.
	// After workflow-command escaping, newlines become %0A.
	assert.Contains(t, output, "Failed paths:%0Aspec.template.spec.containers[0].securityContext.privileged=false",
		"annotation message must include assisted-remediation paths so the failing field is visible in the PR")
}

// TestGitHubActionsPrinter_NoEvidencePathsWhenNone verifies that when a
// control has no fix/delete/review paths, the annotation message does not
// contain a stray "Failed paths:" header.
func TestGitHubActionsPrinter_NoEvidencePathsWhenNone(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	// Remove all paths from the control so AssistedRemediationPathsWithCurrentValues returns empty.
	resourceID := "apps/v1/Deployment/default/demo"
	result := session.ResourcesResult[resourceID]
	for i := range result.AssociatedControls {
		for j := range result.AssociatedControls[i].ResourceAssociatedRules {
			result.AssociatedControls[i].ResourceAssociatedRules[j].Paths = nil
		}
	}
	session.ResourcesResult[resourceID] = result

	output := ghOutputFor(t, session)
	assert.NotContains(t, output, "Failed paths:",
		"annotation message must not contain a paths header when there are no evidence paths")
}

func TestGitHubActionsPrinter_DegradedCoverageWarning(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     85.0,
		EvaluatedControls: 17,
		TotalControls:     20,
		Degraded:          true,
	}

	output := ghOutputFor(t, session)

	assert.Contains(t, output, "::warning title=Degraded Scan Coverage::Scan coverage is degraded (85.00%): 17 of 20 controls evaluated")
}

func TestGitHubActionsPrinter_SkippedControlWarnings(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     90.0,
		EvaluatedControls: 9,
		TotalControls:     10,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID: "C-0099",
				Reason:    "missing: apps/v1/deployments",
			},
		},
	}
	ctrl98 := reportsummary.ControlSummary{
		ControlID: "C-0098",
		Name:      "Configuration control",
	}
	ctrl98.SetStatus(&apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusConfiguration,
		InnerInfo:   "disabled in config",
	})
	session.Report.SummaryDetails.Controls["C-0098"] = ctrl98

	output := ghOutputFor(t, session)

	assert.Contains(t, output, "::warning title=Control C-0098 Skipped::Control C-0098 was not evaluated: configuration: disabled in config")
	assert.Contains(t, output, "::warning title=Control C-0099 Skipped::Control C-0099 was not evaluated: missing: apps/v1/deployments")
}

func TestGitHubActionsPrinter_StepSummary(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     85.5,
		EvaluatedControls: 17,
		TotalControls:     20,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID: "C-0099",
				Reason:    "missing: apps/v1/deployments",
			},
		},
		FailedGVRPulls: []cautils.FailedGVRPull{
			{
				GVR:   "apps/v1/deployments",
				Error: "the server could not find the requested resource",
			},
		},
	}

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err, "step summary file must exist when GITHUB_STEP_SUMMARY is set")
	summary := string(summaryBytes)

	assert.Contains(t, summary, "### Kubescape Scan Coverage Summary")
	assert.Contains(t, summary, "| Coverage Score | 85.50% |")
	assert.Contains(t, summary, "| Status | Degraded |")
	assert.Contains(t, summary, "| Evaluated Controls | 17 / 20 |")
	assert.Contains(t, summary, "#### Skipped Controls")
	assert.Contains(t, summary, "| C-0099 |")
	assert.Contains(t, summary, "missing: apps/v1/deployments")
	assert.Contains(t, summary, "#### Failed Resource Queries")
	assert.Contains(t, summary, "| apps/v1/deployments |")
	assert.Contains(t, summary, "the server could not find the requested resource")
}

func TestGitHubActionsPrinter_StepSummaryUnset(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     100.0,
		EvaluatedControls: 20,
		TotalControls:     20,
		Degraded:          false,
	}
	ctrl98 := reportsummary.ControlSummary{
		ControlID: "C-0098",
		Name:      "Configuration control",
	}
	ctrl98.SetStatus(&apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusConfiguration,
		InnerInfo:   "disabled in config",
	})
	session.Report.SummaryDetails.Controls["C-0098"] = ctrl98

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)
	assert.NotContains(t, output, "::warning", "full coverage scans must emit zero warnings even when controls are skipped")
}

func TestGitHubActionsPrinter_StepSummaryWriteFailureNonFatal(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)

	// Point GITHUB_STEP_SUMMARY to an invalid directory path
	t.Setenv("GITHUB_STEP_SUMMARY", "/nonexistent/dir/step_summary.md")
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     100.0,
		EvaluatedControls: 20,
		TotalControls:     20,
		Degraded:          false,
	}

	tmp, err := os.CreateTemp("", "github-actions-*.txt")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	gp := NewGitHubActionsPrinter()
	gp.writer = tmp
	// ActionPrint should succeed despite step summary write failure
	err = gp.ActionPrint(context.Background(), session, nil)
	require.NoError(t, err, "step summary write failure must not fail ActionPrint")
}

func TestGitHubActionsPrinter_ZeroComplianceScore(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)
	session.Report.SummaryDetails.ComplianceScore = 0.0
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 5,
		TotalControls:     10,
		Degraded:          true,
	}

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	summaryBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	summary := string(summaryBytes)
	assert.Contains(t, summary, "| Compliance Score | 0.00% |", "genuine 0% compliance score must be displayed")
}

func TestGitHubActionsPrinter_CapsAtNineSkippedControlWarnings(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	notEval := make([]cautils.NotEvaluatedControl, 0, 12)
	for i := 1; i <= 12; i++ {
		id := fmt.Sprintf("C-%04d", i)
		notEval = append(notEval, cautils.NotEvaluatedControl{
			ControlID: id,
			Reason:    fmt.Sprintf("reason for %s", id),
		})
	}
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:        50.0,
		EvaluatedControls:    12,
		TotalControls:        24,
		Degraded:             true,
		NotEvaluatedControls: notEval,
	}

	output := ghOutputFor(t, session)

	// Exactly 10 warnings: 1 scan-level warning + 9 skipped-control warnings.
	assert.Equal(t, 10, strings.Count(output, "::warning "), "GitHub renders at most 10 warning annotations per step")
	assert.Contains(t, output, "::warning title=Degraded Scan Coverage::Scan coverage is degraded (50.00%): 12 of 24 controls evaluated")

	// First 9 skipped controls must be annotated.
	for i := 1; i <= 9; i++ {
		id := fmt.Sprintf("C-%04d", i)
		assert.Contains(t, output, fmt.Sprintf("title=Control %s Skipped::", id))
	}

	// 10th through 12th must not be annotated as warnings.
	for i := 10; i <= 12; i++ {
		id := fmt.Sprintf("C-%04d", i)
		assert.NotContains(t, output, fmt.Sprintf("title=Control %s Skipped::", id))
	}

	// Log must report the 3 omitted warnings.
	assert.Contains(t, output, "Kubescape: 9 of 12 skipped control(s) annotated as warnings; 3 omitted due to GitHub's 10-warning step limit. See step summary for full list.")
}

func TestGitHubActionsPrinter_StepSummaryPrePopulatedExhausted(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 5,
		TotalControls:     10,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0001", Reason: "missing"},
		},
	}

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	// Pre-populate with exactly 1 MiB of dummy data
	prePopulated := make([]byte, githubActionsMaxStepSummaryBytes)
	for i := range prePopulated {
		prePopulated[i] = 'x'
	}
	require.NoError(t, os.WriteFile(summaryFile, prePopulated, 0600))
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	info, err := os.Stat(summaryFile)
	require.NoError(t, err)
	assert.Equal(t, int64(githubActionsMaxStepSummaryBytes), info.Size(),
		"must not append anything to step summary when existing content has already exhausted the 1 MiB limit")
}

func TestGitHubActionsPrinter_StepSummaryPrePopulatedNearLimit(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	notEval := make([]cautils.NotEvaluatedControl, 0, 20)
	for i := 1; i <= 20; i++ {
		id := fmt.Sprintf("C-%04d", i)
		notEval = append(notEval, cautils.NotEvaluatedControl{
			ControlID: id,
			Reason:    "some very long explanation for why this control was skipped during evaluation",
		})
	}
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:        50.0,
		EvaluatedControls:    20,
		TotalControls:        40,
		Degraded:             true,
		NotEvaluatedControls: notEval,
	}

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	// Pre-populate with 1 MiB minus safety margin minus 600 bytes
	remainingAllowance := 600
	prePopulatedSize := githubActionsMaxStepSummaryBytes - githubActionsStepSummarySafetyMargin - remainingAllowance
	prePopulated := make([]byte, prePopulatedSize)
	for i := range prePopulated {
		prePopulated[i] = 'a'
	}
	require.NoError(t, os.WriteFile(summaryFile, prePopulated, 0600))
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	info, err := os.Stat(summaryFile)
	require.NoError(t, err)
	assert.LessOrEqual(t, info.Size(), int64(githubActionsMaxStepSummaryBytes-githubActionsStepSummarySafetyMargin),
		"accumulated step summary file must never exceed safe margin below 1 MiB")
	assert.Greater(t, info.Size(), int64(prePopulatedSize),
		"must append within the remaining byte capacity")

	contentBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	appended := string(contentBytes[prePopulatedSize:])
	assert.Contains(t, appended, "Summary truncated to stay within GitHub's 1 MiB limit")
	assert.Contains(t, appended, "entries omitted")
}

func TestGitHubActionsPrinter_StepSummaryPrePopulatedWithinSafetyMargin(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 5,
		TotalControls:     10,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0001", Reason: "missing"},
		},
	}

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	// Pre-populate so remaining space is within safety margin (e.g. 600 bytes below 1 MiB)
	prePopulatedSize := githubActionsMaxStepSummaryBytes - 600
	prePopulated := make([]byte, prePopulatedSize)
	for i := range prePopulated {
		prePopulated[i] = 's'
	}
	require.NoError(t, os.WriteFile(summaryFile, prePopulated, 0600))
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	info, err := os.Stat(summaryFile)
	require.NoError(t, err)
	assert.Equal(t, int64(prePopulatedSize), info.Size(),
		"must not append anything when remaining capacity is within the safety margin")
}

func TestGitHubActionsPrinter_StepSummaryOversized(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := ghSessionFixture(t, "C-0057", 8.0)
	// Create 15,000 skipped controls (~1.5 MB uncompressed markdown)
	const count = 15000
	notEval := make([]cautils.NotEvaluatedControl, 0, count)
	for i := 1; i <= count; i++ {
		id := fmt.Sprintf("C-%05d", i)
		notEval = append(notEval, cautils.NotEvaluatedControl{
			ControlID: id,
			Reason:    "missing resource definition in target cluster or manifest",
		})
	}
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:        10.0,
		EvaluatedControls:    100,
		TotalControls:        count + 100,
		Degraded:             true,
		NotEvaluatedControls: notEval,
	}

	summaryFile := filepath.Join(t.TempDir(), "step_summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summaryFile)

	output := ghOutputFor(t, session)
	require.NotEmpty(t, output)

	info, err := os.Stat(summaryFile)
	require.NoError(t, err)
	assert.LessOrEqual(t, info.Size(), int64(githubActionsMaxStepSummaryBytes),
		"oversized step summary must be truncated to stay strictly within 1 MiB")

	contentBytes, err := os.ReadFile(summaryFile)
	require.NoError(t, err)
	content := string(contentBytes)
	assert.Contains(t, content, "### Kubescape Scan Coverage Summary")
	assert.Contains(t, content, "#### Skipped Controls")
	assert.Contains(t, content, "Summary truncated to stay within GitHub's 1 MiB limit")
	assert.Contains(t, content, "entries omitted")
}

func TestGenerateStepSummaryWithBudget_Boundaries(t *testing.T) {
	session := ghSessionFixture(t, "C-0057", 8.0)
	longReason := strings.Repeat("detailed diagnostic reason explaining why control evaluation was skipped; ", 3)
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     50.0,
		EvaluatedControls: 5,
		TotalControls:     10,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0001", Reason: "first: " + longReason},
			{ControlID: "C-0002", Reason: "second: " + longReason},
		},
	}

	// 1. Zero or negative budget returns empty string.
	assert.Empty(t, generateStepSummaryWithBudget(session, 0))
	assert.Empty(t, generateStepSummaryWithBudget(session, -10))

	// 2. Full budget returns full summary without truncation notice.
	full := generateStepSummaryWithBudget(session, 1024*1024)
	assert.Contains(t, full, "C-0001")
	assert.Contains(t, full, "C-0002")
	assert.NotContains(t, full, "truncated")

	// 3. Budget that can fit first row + notice but not second row must truncate and show "1 entry omitted".
	// Since each row is ~250 bytes and the notice is ~87 bytes, len(full) - 50 accommodates row 1 + notice.
	budget := len(full) - 50
	truncated := generateStepSummaryWithBudget(session, budget)
	assert.LessOrEqual(t, len(truncated), budget)
	assert.Contains(t, truncated, "C-0001")
	assert.Contains(t, truncated, "Summary truncated to stay within GitHub's 1 MiB limit (1 entry omitted).")
	assert.NotContains(t, truncated, "C-0002")
}
