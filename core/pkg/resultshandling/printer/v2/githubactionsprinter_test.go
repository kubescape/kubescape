package printer

import (
	"context"
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
	assert.Equal(t,
		"::error file=deploy.yaml,line=13,title=C-0057 Privileged container::High severity finding on apps/v1/Deployment/default/demo. Remediation: https://hub.armosec.io/docs/c-0057",
		lines[0], "the first line must be the exact workflow command")
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
