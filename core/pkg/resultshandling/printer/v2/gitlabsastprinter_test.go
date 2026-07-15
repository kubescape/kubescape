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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gitLabSessionFixture builds a session with one failed control on a real manifest, so the location resolver has a file to read
func gitLabSessionFixture(t *testing.T, controlID string, scoreFactor float32) *cautils.OPASessionObj {
	t.Helper()

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

// gitLabReportFor runs the printer against a session and returns the decoded report
func gitLabReportFor(t *testing.T, session *cautils.OPASessionObj) gitLabSASTReport {
	t.Helper()

	tmp, err := os.CreateTemp("", "gitlab-sast-*.json")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	})

	gp := NewGitLabSASTPrinter()
	gp.writer = tmp
	require.NoError(t, gp.printConfigurationScan(context.Background(), session))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var report gitLabSASTReport
	require.NoError(t, json.Unmarshal(raw, &report))
	return report
}

// TestGitLabSASTPrintConfigurationScan_MapsControlToVulnerability verifies the fields GitLab needs to render a finding are all populated
func TestGitLabSASTPrintConfigurationScan_MapsControlToVulnerability(t *testing.T) {
	const controlID = "C-0057"

	report := gitLabReportFor(t, gitLabSessionFixture(t, controlID, 8.0))

	assert.Equal(t, gitLabSASTReportVersion, report.Version)
	assert.Equal(t, "sast", report.Scan.Type)
	assert.Equal(t, "success", report.Scan.Status)
	assert.Equal(t, gitLabScannerID, report.Scan.Scanner.ID)
	assert.Equal(t, gitLabScannerName, report.Scan.Analyzer.Name)
	assert.Equal(t, gitLabScannerVendor, report.Scan.Scanner.Vendor.Name)
	assert.NotEmpty(t, report.Scan.Scanner.Version, "scanner version is required by the schema")

	require.Len(t, report.Vulnerabilities, 1)
	vuln := report.Vulnerabilities[0]

	assert.NotEmpty(t, vuln.ID)
	assert.Equal(t, "sast", vuln.Category)
	// the control ID is part of the name so the finding is identifiable from GitLab's title
	assert.Equal(t, "C-0057 - Privileged container", vuln.Name)
	assert.Equal(t, "Privileged container", vuln.Message)
	assert.Equal(t, "Do not run privileged containers", vuln.Description)
	// score factor 8.0 maps to High, which is a valid GitLab severity
	assert.Equal(t, "High", vuln.Severity)
	assert.Equal(t, "deploy.yaml", vuln.Location.File)

	require.Len(t, vuln.Identifiers, 1)
	assert.Equal(t, gitLabControlIDType, vuln.Identifiers[0].Type)
	assert.Equal(t, controlID, vuln.Identifiers[0].Name)
	assert.Equal(t, controlID, vuln.Identifiers[0].Value)
	assert.NotEmpty(t, vuln.Identifiers[0].URL)
}

// TestGitLabSASTPrintConfigurationScan_ResolvesLineNumbers is the point of reusing the SARIF resolver: findings must anchor at the offending line, not collapse to line 1
func TestGitLabSASTPrintConfigurationScan_ResolvesLineNumbers(t *testing.T) {
	const privilegedLine = 13

	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	report := gitLabReportFor(t, gitLabSessionFixture(t, "C-0057", 8.0))

	require.Len(t, report.Vulnerabilities, 1)
	assert.Equal(t, privilegedLine, report.Vulnerabilities[0].Location.StartLine,
		"the privileged field must resolve to line %d", privilegedLine)
}

// TestGitLabSASTPrintConfigurationScan_ScanTimeFormat guards the schema's timestamp pattern, which rejects timezone offsets and fractional seconds
func TestGitLabSASTPrintConfigurationScan_ScanTimeFormat(t *testing.T) {
	session := gitLabSessionFixture(t, "C-0057", 8.0)
	preset := time.Date(2024, 3, 14, 9, 15, 26, 0, time.UTC)
	session.Report.ReportGenerationTime = preset

	report := gitLabReportFor(t, session)

	assert.Equal(t, "2024-03-14T09:15:26", report.Scan.StartTime,
		"start_time must use the report generation time in the schema's format")
	_, err := time.Parse(gitLabTimeFormat, report.Scan.EndTime)
	assert.NoError(t, err, "end_time must match the schema's timestamp format")
}

// TestGitLabSASTPrintConfigurationScan_MissingControl covers a failed control absent from the summary: skip it rather than panic
func TestGitLabSASTPrintConfigurationScan_MissingControl(t *testing.T) {
	resourceID := "apps/v1/Deployment/default/my-deployment"

	result := resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-MISSING",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
			},
		},
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

	report := gitLabReportFor(t, session)
	assert.Empty(t, report.Vulnerabilities)
}

// TestGitLabSASTPrintConfigurationScan_SkipsResourceWithoutRelativePath covers a failed resource with no relative path but a non-empty base path: GitLab gets no file to anchor the finding to, so it must be skipped
func TestGitLabSASTPrintConfigurationScan_SkipsResourceWithoutRelativePath(t *testing.T) {
	const controlID = "C-0057"
	resourceID := "apps/v1/Deployment/default/demo"

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
	session.ResourceSource = map[string]reporthandling.Source{
		resourceID: {RelativePath: ""},
	}
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

	// the base path is non-empty, so only the relative-path check can skip this finding
	require.NotEmpty(t, getBasePathFromMetadata(*session))

	report := gitLabReportFor(t, session)
	assert.Empty(t, report.Vulnerabilities, "a finding with no file path must not be emitted")
}

// TestGitLabSASTSeverityIsValid guards the score-factor mapping onto GitLab's severity enum: an unlisted value makes GitLab reject the whole report
func TestGitLabSASTSeverityIsValid(t *testing.T) {
	gitLabSeverities := []string{"Info", "Unknown", "Low", "Medium", "High", "Critical"}

	tests := []struct {
		scoreFactor float32
		want        string
	}{
		{scoreFactor: 9.5, want: "Critical"},
		{scoreFactor: 8.0, want: "High"},
		{scoreFactor: 5.0, want: "Medium"},
		{scoreFactor: 2.0, want: "Low"},
		{scoreFactor: 0, want: "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			report := gitLabReportFor(t, gitLabSessionFixture(t, "C-0057", tt.scoreFactor))
			require.Len(t, report.Vulnerabilities, 1)

			assert.Equal(t, tt.want, report.Vulnerabilities[0].Severity)
			assert.Contains(t, gitLabSeverities, report.Vulnerabilities[0].Severity)
		})
	}
}

func TestGitLabVulnerabilityID(t *testing.T) {
	first := gitLabVulnerabilityID("C-0057", "apps/v1/Deployment/default/demo", "deploy.yaml")

	assert.Equal(t, first, gitLabVulnerabilityID("C-0057", "apps/v1/Deployment/default/demo", "deploy.yaml"),
		"the same finding must keep a stable id so GitLab can track it across scans")
	assert.NotEqual(t, first, gitLabVulnerabilityID("C-0058", "apps/v1/Deployment/default/demo", "deploy.yaml"),
		"a different control must produce a different id")
	assert.NotEqual(t, first, gitLabVulnerabilityID("C-0057", "apps/v1/Deployment/default/other", "deploy.yaml"),
		"a different resource must produce a different id")
}
