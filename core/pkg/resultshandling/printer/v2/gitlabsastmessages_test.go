package printer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// degradeGitLabSession marks the session's coverage as degraded the way
// ComputeCoverageScore does for the given gaps.
func degradeGitLabSession(session *cautils.OPASessionObj, coverage cautils.ScanCoverage, totalControls int) {
	coverage.ComputeCoverageScore(totalControls)
	session.ScanCoverage = coverage
}

func messageValues(messages []gitLabScanMessage) []string {
	values := make([]string, 0, len(messages))
	for _, m := range messages {
		values = append(values, m.Value)
	}
	return values
}

// requireSchemaValidMessages checks the constraints scan.messages has in the
// GitLab SAST schema 15.2.4: level is one of info, warn and fatal, and value is
// a non-empty string.
func requireSchemaValidMessages(t *testing.T, messages []gitLabScanMessage) {
	t.Helper()
	for _, m := range messages {
		assert.Contains(t, []string{"info", "warn", "fatal"}, m.Level)
		assert.NotEmpty(t, m.Value)
	}
}

// TestGitLabSASTMessages_CompleteScanIsUnchanged covers the contract that a scan
// with no gaps keeps its report as it was: no messages key at all.
func TestGitLabSASTMessages_CompleteScanIsUnchanged(t *testing.T) {
	session := gitLabSessionFixture(t, "C-0057", 8.0)
	degradeGitLabSession(session, cautils.ScanCoverage{}, 20)
	require.False(t, session.ScanCoverage.Degraded)

	tmp := filepath.Join(t.TempDir(), "report.json")
	f, err := os.Create(tmp)
	require.NoError(t, err)
	gp := NewGitLabSASTPrinter(false)
	gp.writer = f
	require.NoError(t, gp.printConfigurationScan(context.Background(), session))
	require.NoError(t, f.Close())

	raw, err := os.ReadFile(tmp)
	require.NoError(t, err)
	var decoded struct {
		Scan map[string]any `json:"scan"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.NotContains(t, decoded.Scan, "messages")
	assert.Equal(t, "success", decoded.Scan["status"])
}

// TestGitLabSASTMessages_DegradedScanKeepsSuccessStatus covers the reported
// defect: a degraded scan still says success, so the warnings are what tell
// the reader the findings may be incomplete.
func TestGitLabSASTMessages_DegradedScanKeepsSuccessStatus(t *testing.T) {
	session := gitLabSessionFixture(t, "C-0057", 8.0)
	degradeGitLabSession(session, cautils.ScanCoverage{
		SkippedManifests: []cautils.SkippedManifest{{Path: "/work/broken.yaml", Reason: "parse error"}},
	}, 20)

	report := gitLabReportFor(t, session)

	assert.Equal(t, "success", report.Scan.Status)
	require.NotEmpty(t, report.Scan.Messages)
	requireSchemaValidMessages(t, report.Scan.Messages)
	assert.Equal(t, "Scan coverage is degraded: coverage score 95.00% (20 of 20 controls evaluated); the findings in this report may be incomplete",
		report.Scan.Messages[0].Value)
	assert.Len(t, report.Vulnerabilities, 1, "findings are kept alongside the warnings")
}

func TestBuildGitLabScanMessages_Categories(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "repo")
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{}
	degradeGitLabSession(session, cautils.ScanCoverage{
		SkippedManifests: []cautils.SkippedManifest{
			{Path: filepath.Join(base, "k8s", "bad.yaml"), Reason: "parse error: line 2"},
			{Path: filepath.Join(string(filepath.Separator), "elsewhere", "other.yaml"), Reason: "missing kind"},
		},
		PartialGVRPulls: []cautils.PartialGVRPull{
			{GVR: "apps/v1/deployments", Selector: "namespace=prod", Error: "forbidden"},
		},
		PolicyDegradations: []cautils.PolicyDegradation{
			{Component: "exceptions", Reason: "open exceptions.json: no such file"},
		},
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0099", Reason: "control timed out after 5s"},
		},
	}, 20)

	values := messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, base, true))

	assert.Contains(t, values, "Manifest k8s/bad.yaml was skipped: parse error: line 2",
		"a manifest inside the scan root is shown relative to it")
	assert.Contains(t, values, "Manifest /elsewhere/other.yaml was skipped: missing kind")
	assert.Contains(t, values, `Resources of apps/v1/deployments were only partially collected (selector "namespace=prod"): forbidden`)
	assert.Contains(t, values, "Policy input exceptions was not loaded from its configured source and a fallback was used: open exceptions.json: no such file")
	assert.Contains(t, values, "Control C-0099 was not evaluated: control timed out after 5s")
}

// TestBuildGitLabScanMessages_FailedPullNamesItsControls covers one failure
// that lives in two coverage structures: the failed GVR and the controls that
// could not run because of it. It must produce one warning, not one per control.
func TestBuildGitLabScanMessages_FailedPullNamesItsControls(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{}
	degradeGitLabSession(session, cautils.ScanCoverage{
		FailedGVRPulls: []cautils.FailedGVRPull{{GVR: "rbac.authorization.k8s.io/v1/roles", Error: "forbidden"}},
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{ControlID: "C-0188", MissingGVRs: []string{"rbac.authorization.k8s.io/v1/roles"}},
			{ControlID: "C-0035", MissingGVRs: []string{"rbac.authorization.k8s.io/v1/roles"}},
			{ControlID: "C-0007", MissingGVRs: []string{"never-failed/v1/things"}},
		},
	}, 20)

	values := messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true))

	assert.Contains(t, values, "Resources of rbac.authorization.k8s.io/v1/roles could not be collected: forbidden (controls not evaluated: C-0035, C-0188)")
	for _, v := range values {
		assert.False(t, strings.HasPrefix(v, "Control C-0188"), "C-0188 is already named on the GVR warning: %q", v)
		assert.False(t, strings.HasPrefix(v, "Control C-0035"), "C-0035 is already named on the GVR warning: %q", v)
	}
	assert.Contains(t, values, "Control C-0007 was not evaluated: missing: never-failed/v1/things",
		"a control whose GVR is not a recorded failed pull keeps its own warning")
}

// TestBuildGitLabScanMessages_SkippedControlReportedOnce covers a control that is
// both skipped in the summary and listed in NotEvaluatedControls.
func TestBuildGitLabScanMessages_SkippedControlReportedOnce(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				"C-0099": reportsummary.ControlSummary{
					ControlID: "C-0099",
					Name:      "Some control",
					Status:    apis.StatusSkipped,
				},
			},
		},
	}
	degradeGitLabSession(session, cautils.ScanCoverage{
		NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "C-0099", Reason: "control timed out"}},
	}, 20)

	values := messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true))

	count := 0
	for _, v := range values {
		if strings.HasPrefix(v, "Control C-0099") {
			count++
		}
	}
	assert.Equal(t, 1, count, "%v", values)
}

func TestBuildGitLabScanMessages_ControlWarningsOnlyWhenDegraded(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				"C-0001": reportsummary.ControlSummary{ControlID: "C-0001", Name: "Manual", Status: apis.StatusSkipped},
			},
		},
	}
	degradeGitLabSession(session, cautils.ScanCoverage{}, 20)
	require.False(t, session.ScanCoverage.Degraded)

	assert.Nil(t, buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true),
		"a skipped control in a complete scan is not a coverage gap")
}

// TestGitLabSASTMessages_ReportsOmittedResources covers failed resources the
// report cannot carry because GitLab cannot anchor them to a repository file.
func TestGitLabSASTMessages_ReportsOmittedResources(t *testing.T) {
	const controlID = "C-0057"
	tests := []struct {
		name    string
		relPath string
		want    string
	}{
		{name: "no path", relPath: "", want: "1 failed resource(s) were left out of this report because they are not associated with a file"},
		{name: "outside the repository", relPath: "../outside/deploy.yaml", want: "1 failed resource(s) were left out of this report because their paths are outside the repository root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := gitLabSessionFixture(t, controlID, 8.0)
			for id := range session.ResourceSource {
				session.ResourceSource[id] = reporthandling.Source{RelativePath: tt.relPath}
			}
			// not degraded: the omission alone must be reported
			require.False(t, session.ScanCoverage.Degraded)

			report := gitLabReportFor(t, session)

			assert.Empty(t, report.Vulnerabilities)
			require.Len(t, report.Scan.Messages, 1)
			assert.Equal(t, tt.want, report.Scan.Messages[0].Value)
			requireSchemaValidMessages(t, report.Scan.Messages)
		})
	}
}

func TestBuildGitLabScanMessages_OrderIsDeterministic(t *testing.T) {
	manifests := []cautils.SkippedManifest{
		{Path: "b.yaml", Reason: "r"}, {Path: "a.yaml", Reason: "r"}, {Path: "c.yaml", Reason: "r"},
	}
	partials := []cautils.PartialGVRPull{
		{GVR: "z/v1/x", Selector: "s", Error: "e"}, {GVR: "a/v1/x", Selector: "s", Error: "e"},
	}
	reversedManifests := []cautils.SkippedManifest{manifests[2], manifests[1], manifests[0]}
	reversedPartials := []cautils.PartialGVRPull{partials[1], partials[0]}

	build := func(m []cautils.SkippedManifest, p []cautils.PartialGVRPull) []string {
		session := cautils.NewOPASessionObjMock()
		session.Report = &reporthandlingv2.PostureReport{}
		degradeGitLabSession(session, cautils.ScanCoverage{SkippedManifests: m, PartialGVRPulls: p}, 20)
		return messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true))
	}

	first := build(manifests, partials)
	assert.Equal(t, first, build(reversedManifests, reversedPartials))
	assert.Equal(t, "Manifest a.yaml was skipped: r", first[1])
	assert.Equal(t, "Manifest b.yaml was skipped: r", first[2])
}

func TestBuildGitLabScanMessages_CapsOutput(t *testing.T) {
	const skipped = 40
	manifests := make([]cautils.SkippedManifest, 0, skipped)
	for i := 0; i < skipped; i++ {
		manifests = append(manifests, cautils.SkippedManifest{Path: fmt.Sprintf("m%02d.yaml", i), Reason: "parse error"})
	}
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{}
	degradeGitLabSession(session, cautils.ScanCoverage{SkippedManifests: manifests}, 20)

	messages := buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true)

	require.Len(t, messages, maxGitLabScanMessages)
	requireSchemaValidMessages(t, messages)
	// 1 coverage header + 40 manifests = 41 messages; 24 are kept, 17 are omitted
	assert.Equal(t, "17 additional warning(s) were omitted from this report; use --format json for the complete scan coverage",
		messages[len(messages)-1].Value)
	assert.Equal(t, "Manifest m22.yaml was skipped: parse error", messages[len(messages)-2].Value)
}

func TestBoundGitLabMessage(t *testing.T) {
	assert.Equal(t, "a b c", boundGitLabMessage("a\n  b\t\nc"))

	long := strings.Repeat("é", maxGitLabMessageLen+50)
	bounded := boundGitLabMessage(long)
	assert.Equal(t, maxGitLabMessageLen, len([]rune(bounded)))
	assert.True(t, strings.HasSuffix(bounded, "…"))
}

func TestGitLabDisplayPath(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "repo")
	assert.Equal(t, "k8s/a.yaml", gitLabDisplayPath(filepath.Join(base, "k8s", "a.yaml"), base))
	assert.Equal(t, "/other/a.yaml", gitLabDisplayPath(filepath.Join(string(filepath.Separator), "other", "a.yaml"), base))
	assert.Equal(t, "/repo/a.yaml", gitLabDisplayPath(filepath.Join(base, "a.yaml"), ""))
}

// TestGitLabSASTMessages_MalformedSecretDoesNotLeak runs the real manifest
// loader on a malformed Secret next to a valid manifest. The pinned JSON
// parser quotes the unparsed input in its error, so the loader's skip reason
// carries the Secret's value; the serialized report must not.
func TestGitLabSASTMessages_MalformedSecretDoesNotLeak(t *testing.T) {
	const sentinel = "sentinel-secret-do-not-leak-4206"
	dir := t.TempDir()
	// The missing comma after metadata makes fastjson report the rest of the input.
	malformed := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"} "stringData":{"password":"` + sentinel + `"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.json"), []byte(malformed), 0o600))
	valid := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"ok"},"data":{"k":"v"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.json"), []byte(valid), 0o600))

	workloads, skipped, _ := cautils.LoadResourcesFromFiles(context.Background(), dir, dir, nil)
	require.Len(t, skipped, 1)
	require.Contains(t, skipped[0].Reason, sentinel, "the loader's reason must carry the excerpt, or this test proves nothing")
	require.Len(t, workloads, 1, "the valid manifest is still loaded")

	session := gitLabSessionFixture(t, "C-0057", 8.0)
	degradeGitLabSession(session, cautils.ScanCoverage{SkippedManifests: skipped}, 20)

	tmp := filepath.Join(t.TempDir(), "report.json")
	f, err := os.Create(tmp)
	require.NoError(t, err)
	gp := NewGitLabSASTPrinter(false)
	gp.writer = f
	require.NoError(t, gp.printConfigurationScan(context.Background(), session))
	require.NoError(t, f.Close())
	raw, err := os.ReadFile(tmp)
	require.NoError(t, err)

	assert.NotContains(t, string(raw), sentinel, "no part of the report may carry the Secret value")

	var report gitLabSASTReport
	require.NoError(t, json.Unmarshal(raw, &report))
	requireSchemaValidMessages(t, report.Scan.Messages)
	var skippedWarning string
	for _, v := range messageValues(report.Scan.Messages) {
		if strings.HasSuffix(v, "secret.json was skipped: it could not be parsed") {
			skippedWarning = v
		}
	}
	assert.NotEmpty(t, skippedWarning, "the warning still names the manifest and says it could not be parsed")
	for _, m := range report.Scan.Messages {
		assert.LessOrEqual(t, len([]rune(m.Value)), maxGitLabMessageLen)
	}
}

func TestGitLabSkipReason(t *testing.T) {
	for reason, want := range map[string]string{
		"parse error: cannot parse " + "x":               "it could not be parsed",
		"unrendered Helm template: x":                    "it is an unrendered Helm template",
		"read error: open x: denied":                     "it could not be read",
		cautils.ErrFileTooLarge.Error() + `: "f" size 9`: "it exceeds the file size limit",
		"anything else, maybe quoting a value":           "it could not be loaded",
	} {
		assert.Equal(t, want, gitLabSkipReason(reason, false), reason)
		assert.Equal(t, reason, gitLabSkipReason(reason, true), "showSecrets keeps the loader's text")
	}
}

// TestBuildGitLabScanMessages_RedactsSkipReasonByDefault pins the builder
// itself, so a new caller cannot reach the raw reason without opting in.
func TestBuildGitLabScanMessages_RedactsSkipReasonByDefault(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{}
	degradeGitLabSession(session, cautils.ScanCoverage{
		SkippedManifests: []cautils.SkippedManifest{{Path: "a.yaml", Reason: "parse error: unparsed tail: \"hunter2\""}},
	}, 20)

	redacted := messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, "", false))
	assert.Contains(t, redacted, "Manifest a.yaml was skipped: it could not be parsed")
	assert.NotContains(t, strings.Join(redacted, "\n"), "hunter2")

	shown := messageValues(buildGitLabScanMessages(session, gitLabOmittedResources{}, "", true))
	assert.Contains(t, strings.Join(shown, "\n"), "hunter2")
}
