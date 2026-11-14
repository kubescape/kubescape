package printer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/locationresolver"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func codeQualityReportFor(t *testing.T, session *cautils.OPASessionObj) ([]codeQualityIssue, string) {
	t.Helper()

	tmp, err := os.CreateTemp(t.TempDir(), "gl-code-quality-*.json")
	require.NoError(t, err)

	cp := NewGitLabCodeQualityPrinter(false)
	cp.writer = tmp
	require.NoError(t, cp.ActionPrint(context.Background(), session, nil))
	require.NoError(t, cp.CloseWriter())

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)

	var issues []codeQualityIssue
	require.NoError(t, json.Unmarshal(raw, &issues))
	return issues, string(raw)
}

func TestGitLabCodeQuality_MapsFailedControlToIssue(t *testing.T) {
	const controlID = "C-0057"

	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	issues, _ := codeQualityReportFor(t, gitLabSessionFixture(t, controlID, 8.0))

	require.Len(t, issues, 1)
	issue := issues[0]
	assert.Equal(t, "issue", issue.Type)
	assert.Equal(t, controlID, issue.CheckName)
	assert.Equal(t, "C-0057 Privileged container (Deployment/demo)", issue.Description)
	assert.Equal(t, []string{"Security"}, issue.Categories)
	assert.Equal(t, "major", issue.Severity)
	assert.Equal(t, "kubescape", issue.EngineName)
	assert.Equal(t, gitLabVulnerabilityID(controlID, "Deployment/default/demo", "deploy.yaml"), issue.Fingerprint)
	assert.Equal(t, "deploy.yaml", issue.Location.Path)
	assert.Equal(t, 13, issue.Location.Lines.Begin)

	assert.Contains(t, issue.Content.Body, "Do not run privileged containers")
	assert.Contains(t, issue.Content.Body, "**Remediation:** Set privileged to false")
	assert.Contains(t, issue.Content.Body, "spec.template.spec.containers[0].securityContext.privileged")
	assert.Contains(t, issue.Content.Body, cautils.GetControlLink(controlID))
}

func TestGitLabCodeQuality_FingerprintIsStableAcrossRuns(t *testing.T) {
	first, _ := codeQualityReportFor(t, gitLabSessionFixture(t, "C-0057", 8.0))
	second, _ := codeQualityReportFor(t, gitLabSessionFixture(t, "C-0057", 8.0))

	require.Len(t, first, 1)
	require.Len(t, second, 1)
	assert.Equal(t, first[0].Fingerprint, second[0].Fingerprint)
}

// sessionWithWorkloadPath keys the fixture's resource the way a scan does: by the
// LocalWorkload's own ID, which hashes the workload path ("<file>:<document index>"
// for a plain manifest, the absolute file path for a Helm or Kustomize resource).
func sessionWithWorkloadPath(t *testing.T, workloadPath string) *cautils.OPASessionObj {
	t.Helper()
	const fixtureID = "apps/v1/Deployment/default/demo"
	session := gitLabSessionFixture(t, "C-0057", 8.0)

	lw, ok := session.AllResources[fixtureID].(*localworkload.LocalWorkload)
	require.True(t, ok)
	lw.SetPath(workloadPath)
	id := lw.GetID()

	result := session.ResourcesResult[fixtureID]
	result.ResourceID = id
	session.ResourcesResult = map[string]resourcesresults.Result{id: result}
	session.ResourceSource[id] = session.ResourceSource[fixtureID]
	delete(session.ResourceSource, fixtureID)
	delete(session.AllResources, fixtureID)
	session.AllResources[id] = lw
	return session
}

// GitLab compares a merge request's report with the target branch's by fingerprint
// only, so the same control failing on the same resource in the same file must keep
// its fingerprint, or the widget lists it as both new and resolved.
func TestGitLabCodeQuality_FingerprintFollowsTheResourceNotItsWorkloadPath(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
	}{
		// a document added above the resource in the same file
		{name: "document index", before: "deploy.yaml:0", after: "deploy.yaml:1"},
		// a Helm or Kustomize resource scanned from another build directory
		{name: "checkout directory", before: "/builds/a1b2c3/0/group/project/deploy.yaml", after: "/builds/x9y8z7/1/group/project/deploy.yaml"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := codeQualityReportFor(t, sessionWithWorkloadPath(t, tc.before))
			after, _ := codeQualityReportFor(t, sessionWithWorkloadPath(t, tc.after))

			require.Len(t, before, 1)
			require.Len(t, after, 1)
			require.Equal(t, before[0].Location.Path, after[0].Location.Path)
			assert.Equal(t, before[0].Fingerprint, after[0].Fingerprint)
		})
	}
}

// A different control, resource or file is a different finding.
func TestCodeQualityFingerprintTellsFindingsApart(t *testing.T) {
	deployment := func(namespace, name string) *localworkload.LocalWorkload {
		return localworkload.NewLocalWorkload(map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]interface{}{"name": name, "namespace": namespace},
		})
	}
	base := codeQualityFingerprint("C-0057", deployment("default", "demo"), "id", "deploy.yaml")

	for name, other := range map[string]string{
		"control":   codeQualityFingerprint("C-0046", deployment("default", "demo"), "id", "deploy.yaml"),
		"name":      codeQualityFingerprint("C-0057", deployment("default", "other"), "id", "deploy.yaml"),
		"namespace": codeQualityFingerprint("C-0057", deployment("prod", "demo"), "id", "deploy.yaml"),
		"file":      codeQualityFingerprint("C-0057", deployment("default", "demo"), "id", "other.yaml"),
	} {
		assert.NotEqual(t, base, other, name)
	}
	assert.Equal(t, gitLabVulnerabilityID("C-0057", "id", "deploy.yaml"),
		codeQualityFingerprint("C-0057", nil, "id", "deploy.yaml"), "without the resource, the scan's ID is used")
}

func TestGitLabCodeQuality_CleanScanWritesEmptyArray(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{}

	issues, raw := codeQualityReportFor(t, session)

	assert.Empty(t, issues)
	assert.Equal(t, "[]", raw)
}

func TestGitLabCodeQuality_SkipsUnanchorablePaths(t *testing.T) {
	for _, tc := range []struct{ name, relPath string }{
		{name: "empty path", relPath: ""},
		{name: "path escaping the repository root", relPath: "../outside/deploy.yaml"},
		{name: "absolute path", relPath: "/etc/manifests/deploy.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := gitLabSessionFixture(t, "C-0057", 8.0)
			for id, source := range session.ResourceSource {
				source.RelativePath = tc.relPath
				session.ResourceSource[id] = source
			}

			issues, _ := codeQualityReportFor(t, session)
			assert.Empty(t, issues)
		})
	}
}

func TestGitLabCodeQuality_SkipsControlMissingFromSummary(t *testing.T) {
	session := gitLabSessionFixture(t, "C-0057", 8.0)
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{}

	issues, _ := codeQualityReportFor(t, session)
	assert.Empty(t, issues)
}

func TestGitLabCodeQuality_RejectsImageScans(t *testing.T) {
	cp := NewGitLabCodeQualityPrinter(false)
	images := []cautils.ImageScanData{{Image: "nginx:1.23"}}

	assert.ErrorContains(t, cp.ActionPrint(context.Background(), nil, images), "only supported for configuration scanning")
	assert.ErrorContains(t, cp.ActionPrint(context.Background(), cautils.NewOPASessionObjMock(), images), "--scan-images")
}

func TestCodeQualitySeverity(t *testing.T) {
	for _, tc := range []struct {
		scoreFactor float32
		want        string
	}{
		{scoreFactor: 9.0, want: "critical"},
		{scoreFactor: 7.0, want: "major"},
		{scoreFactor: 4.0, want: "minor"},
		{scoreFactor: 1.0, want: "info"},
		{scoreFactor: 0, want: "info"},
	} {
		assert.Equal(t, tc.want, codeQualitySeverity(tc.scoreFactor), "score factor %v", tc.scoreFactor)
	}
}

func TestToCodeQualityIssue_DescriptionWithoutResource(t *testing.T) {
	control := &reportsummary.ControlSummary{ControlID: "C-0057", Name: "Privileged container", ScoreFactor: 8.0}

	issue := toCodeQualityIssue(control, &resourcesresults.ResourceAssociatedControl{}, nil, "id", "deploy.yaml", 1, false)

	assert.Equal(t, "C-0057 Privileged container", issue.Description)
}

func TestCodeQualityLine(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "multi.yaml")
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
---
apiVersion: v1
kind: Pod
metadata:
  name: tool
`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifest), 0600))
	resolver, err := locationresolver.NewPathLocationResolver(manifestPath)
	require.NoError(t, err)

	session := cautils.NewOPASessionObjMock()
	for id, doc := range map[string]struct{ kind, name, path string }{
		"apps/v1/default/Deployment/web": {kind: "Deployment", name: "web", path: "multi.yaml:0"},
		"/v1/default/Pod/tool":           {kind: "Pod", name: "tool", path: "multi.yaml:1"},
	} {
		lw := localworkload.NewLocalWorkload(map[string]interface{}{"kind": doc.kind, "metadata": map[string]interface{}{"name": doc.name}})
		lw.SetPath(doc.path)
		session.AllResources[id] = lw
	}

	withFixPath := func(path string) *resourcesresults.ResourceAssociatedControl {
		return &resourcesresults.ResourceAssociatedControl{
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
				{Paths: []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: path, Value: "x"}}}},
			},
		}
	}

	for _, tc := range []struct {
		name       string
		resourceID string
		ac         *resourcesresults.ResourceAssociatedControl
		resolver   *locationresolver.PathLocationResolver
		want       int
	}{
		{name: "field resolved on line 1 stays on line 1", resourceID: "apps/v1/default/Deployment/web", ac: withFixPath("apiVersion"), resolver: resolver, want: 1},
		{name: "field resolved in a later document", resourceID: "/v1/default/Pod/tool", ac: withFixPath("metadata.name"), resolver: resolver, want: 9},
		{name: "no fix path anchors at the document kind", resourceID: "/v1/default/Pod/tool", ac: &resourcesresults.ResourceAssociatedControl{}, resolver: resolver, want: 7},
		{name: "no resolver falls back to line 1", resourceID: "/v1/default/Pod/tool", ac: withFixPath("metadata.name"), want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, codeQualityLine(session, tc.resolver, tc.ac, tc.resourceID))
		})
	}
}

func TestToCodeQualityIssue_RedactsSecretValuesUnlessShowSecrets(t *testing.T) {
	control := &reportsummary.ControlSummary{ControlID: "C-0012", Name: "Credentials in env var", ScoreFactor: 8.0}
	resource := &mockResource{kind: "Secret", obj: map[string]any{}}
	ac := &resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0012",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{Paths: []armotypes.PosturePaths{
				{FixPath: armotypes.FixPath{Path: "data.password", Value: "s3cr3t-plaintext-password"}},
			}},
		},
	}

	redacted := toCodeQualityIssue(control, ac, resource, "v1/Secret/default/demo", "secret.yaml", 1, false)
	assert.NotContains(t, redacted.Content.Body, "s3cr3t-plaintext-password")
	assert.Contains(t, redacted.Content.Body, "[redacted]")

	revealed := toCodeQualityIssue(control, ac, resource, "v1/Secret/default/demo", "secret.yaml", 1, true)
	assert.Contains(t, revealed.Content.Body, "s3cr3t-plaintext-password")
}
