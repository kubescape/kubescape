package printer

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"maps"
	"os"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameworkScopedConsumerViews(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frameworks []string
		scope      string
		failed     bool
	}{
		{"single", []string{"NSA"}, "NSA", false},
		{"partial", []string{"NSA", "MITRE"}, "NSA", true},
		{"global", []string{"NSA", "MITRE"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := ghSessionFixture(t, "C-0034", 8)
			for _, name := range tc.frameworks {
				session.Report.SummaryDetails.Frameworks = append(session.Report.SummaryDetails.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: session.Report.SummaryDetails.Controls})
			}
			for id, result := range session.ResourcesResult {
				result.AssociatedControls[0].ResourceAssociatedRules[0].Exception = []armotypes.PostureExceptionPolicy{{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tc.scope, ControlID: "C-0034", RuleName: "privileged-container"}}}}
				session.ResourcesResult[id] = result
			}
			assert.Equal(t, tc.failed, len(buildResourceTableView(session, false)) > 0, "HTML")
			metrics := NewPrometheusPrinter(false).generatePrometheusFormat(session.AllResources, session.ResourcesResult, &session.Report.SummaryDetails, session.ScanCoverage)
			require.Len(t, metrics.listResources, 1)
			assert.Equal(t, tc.failed, metrics.listResources[0].controlsCountFailed > 0, "Prometheus")
			var sarifOutput bytes.Buffer
			require.NoError(t, NewSARIFPrinter(false).writeConfigurationSARIF(context.Background(), &sarifOutput, session))
			var sarifDoc struct {
				Runs []struct{ Results []json.RawMessage }
			}
			require.NoError(t, json.Unmarshal(sarifOutput.Bytes(), &sarifDoc))
			require.Len(t, sarifDoc.Runs, 1)
			assert.Equal(t, tc.failed, len(sarifDoc.Runs[0].Results) > 0, "SARIF")
			csvFile, err := os.CreateTemp(t.TempDir(), "csv")
			require.NoError(t, err)
			cp := NewCsvPrinter(false)
			cp.writer = csvFile
			require.NoError(t, cp.ActionPrint(context.Background(), session, nil))
			_, err = csvFile.Seek(0, 0)
			require.NoError(t, err)
			csvRows, err := csv.NewReader(csvFile).ReadAll()
			require.NoError(t, err)
			require.NoError(t, csvFile.Close())
			require.Len(t, csvRows, 2)
			assert.Equal(t, tc.failed, csvRows[1][3] == "failed", "CSV")
			glFile, err := os.CreateTemp(t.TempDir(), "gitlab")
			require.NoError(t, err)
			gp := NewGitLabSASTPrinter(false)
			gp.writer = glFile
			require.NoError(t, gp.ActionPrint(context.Background(), session, nil))
			_, err = glFile.Seek(0, 0)
			require.NoError(t, err)
			var glDoc struct{ Vulnerabilities []json.RawMessage }
			require.NoError(t, json.NewDecoder(glFile).Decode(&glDoc))
			require.NoError(t, glFile.Close())
			assert.Equal(t, tc.failed, len(glDoc.Vulnerabilities) > 0, "GitLab")
			annotations, _ := NewGitHubActionsPrinter().collectAnnotations(context.Background(), session)
			assert.Equal(t, tc.failed, len(annotations) > 0, "GitHub Actions")
			assert.Equal(t, tc.failed, len(failedResourcesInPrintOrder(session)) > 0, "resource table")
			assert.Equal(t, tc.failed, len(collectFailures(context.Background(), session)) > 0, "exceptions output")
			for _, report := range buildPolicyReports(session) {
				for _, result := range report.Results {
					assert.Equal(t, tc.failed, result.Result == "fail", "PolicyReport")
				}
			}
		})
	}
}

func TestFrameworkScopedMixedRuleEvidence(t *testing.T) {
	session := ghSessionFixture(t, "C-0034", 8)
	summary := &session.Report.SummaryDetails
	summary.Frameworks = []reportsummary.FrameworkSummary{{Name: "NSA", Controls: summary.Controls}}
	for id, result := range session.ResourcesResult {
		control := &result.AssociatedControls[0]
		control.ResourceAssociatedRules[0].Exception = []armotypes.PostureExceptionPolicy{{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "privileged-container"}}}}
		other := control.ResourceAssociatedRules[0]
		other.Name = "R2"
		other.Exception = nil
		other.Paths = []armotypes.PosturePaths{{ReviewPath: "spec.replicas"}}
		control.ResourceAssociatedRules = append(control.ResourceAssociatedRules, other)
		session.ResourcesResult[id] = result
	}
	rows := buildResourceTableView(session, false)
	require.Len(t, rows, 1)
	annotations, _ := NewGitHubActionsPrinter().collectAnnotations(context.Background(), session)
	require.Len(t, annotations, 1)
	assert.NotContains(t, annotations[0].message, "securityContext.privileged")
	assert.Contains(t, annotations[0].message, "spec.replicas")
	var output bytes.Buffer
	require.NoError(t, NewSARIFPrinter(false).writeConfigurationSARIF(context.Background(), &output, session))
	assert.NotContains(t, output.String(), "securityContext.privileged", "excepted rule evidence must be absent")
	assert.Contains(t, output.String(), "spec.replicas")
}

func TestFrameworkScopedSummaryConsumers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		frameworks []string
		scope      string
	}{
		{"single", []string{"NSA"}, "NSA"},
		{"partial", []string{"NSA", "MITRE"}, "NSA"},
		{"global", []string{"NSA", "MITRE"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := ghSessionFixture(t, "C-0034", 8)
			summary := &session.Report.SummaryDetails
			for _, name := range tc.frameworks {
				summary.Frameworks = append(summary.Frameworks, reportsummary.FrameworkSummary{Name: name, Controls: maps.Clone(summary.Controls)})
			}
			policy := armotypes.PostureExceptionPolicy{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tc.scope, ControlID: "C-0034", RuleName: "privileged-container"}}}
			for id, result := range session.ResourcesResult {
				result.SetExceptions(session.AllResources[id], []armotypes.PostureExceptionPolicy{policy}, "", nil)
				session.ResourcesResult[id] = result
				summary.AppendResourceResult(&result)
			}
			summary.InitResourcesSummary(nil)
			suites := listTestsSuite(session)
			require.Len(t, suites, len(tc.frameworks))
			for i, framework := range summary.Frameworks {
				failed := tc.scope != "" && framework.Name != tc.scope
				require.Len(t, suites[i].TestCases, 1)
				assert.Equal(t, failed, suites[i].TestCases[0].Failure != nil, "JUnit "+framework.Name)
				control := framework.Controls["C-0034"]
				f, err := os.CreateTemp(t.TempDir(), "pretty")
				require.NoError(t, err)
				pp := &PrettyPrinter{writer: f}
				pp.printTitle(&control)
				require.NoError(t, f.Close())
				output, err := os.ReadFile(f.Name())
				require.NoError(t, err)
				if failed {
					assert.Contains(t, string(output), "failed")
				} else {
					assert.Contains(t, string(output), "passed (w/exceptions)")
				}
			}
		})
	}
	for _, status := range []apis.ScanningStatus{apis.StatusPassed, apis.StatusSkipped} {
		t.Run("manual-"+string(status), func(t *testing.T) {
			session := ghSessionFixture(t, "C-0034", 8)
			sub := apis.SubStatusManualReview
			if status == apis.StatusPassed {
				sub = apis.SubStatusException
			}
			control := session.Report.SummaryDetails.Controls["C-0034"]
			control.SetStatus(&apis.StatusInfo{InnerStatus: status, SubStatus: sub})
			session.Report.SummaryDetails.Controls["C-0034"] = control
			cases := testsCases(session, &session.Report.SummaryDetails.Controls, "NSA")
			require.Len(t, cases, 1)
			assert.Nil(t, cases[0].Failure)
			assert.Equal(t, status == apis.StatusSkipped, cases[0].SkipMessage != nil)
			f, err := os.CreateTemp(t.TempDir(), "manual")
			require.NoError(t, err)
			(&PrettyPrinter{writer: f}).printTitle(&control)
			require.NoError(t, f.Close())
			output, err := os.ReadFile(f.Name())
			require.NoError(t, err)
			assert.Contains(t, string(output), string(sub))
		})
	}
}

func TestFrameworkScopedMixedControlConsumers(t *testing.T) {
	session := ghSessionFixture(t, "C-0034", 8)
	summary := &session.Report.SummaryDetails
	other := summary.Controls["C-0034"]
	other.ControlID = "C-0286"
	summary.Controls[other.ControlID] = other
	summary.Frameworks = []reportsummary.FrameworkSummary{{Name: "NSA", Controls: summary.Controls}}
	for id, result := range session.ResourcesResult {
		excepted := result.AssociatedControls[0]
		excepted.ResourceAssociatedRules = append([]resourcesresults.ResourceAssociatedRule(nil), excepted.ResourceAssociatedRules...)
		excepted.ResourceAssociatedRules[0].Exception = []armotypes.PostureExceptionPolicy{{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "privileged-container"}}}}
		failed := result.AssociatedControls[0]
		failed.ControlID = "C-0286"
		result.AssociatedControls = []resourcesresults.ResourceAssociatedControl{excepted, failed}
		session.ResourcesResult[id] = result
	}
	prettyFile, err := os.CreateTemp(t.TempDir(), "resource-table")
	require.NoError(t, err)
	(&PrettyPrinter{writer: prettyFile}).resourceTable(session)
	require.NoError(t, prettyFile.Close())
	rendered, err := os.ReadFile(prettyFile.Name())
	require.NoError(t, err)
	assert.Contains(t, string(rendered), "Controls: 2 (Failed: 1, action required: 0)")
	annotations, _ := NewGitHubActionsPrinter().collectAnnotations(context.Background(), session)
	require.Len(t, annotations, 1)
	assert.Equal(t, "C-0286", annotations[0].controlID)
	var output bytes.Buffer
	require.NoError(t, NewSARIFPrinter(false).writeConfigurationSARIF(context.Background(), &output, session))
	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			}
		}
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &sarifDoc))
	require.Len(t, sarifDoc.Runs, 1)
	require.Len(t, sarifDoc.Runs[0].Results, 1)
	assert.Equal(t, "C-0286", sarifDoc.Runs[0].Results[0].RuleID)
	f, err := os.CreateTemp(t.TempDir(), "gitlab")
	require.NoError(t, err)
	gp := NewGitLabSASTPrinter(false)
	gp.writer = f
	require.NoError(t, gp.ActionPrint(context.Background(), session, nil))
	_, err = f.Seek(0, 0)
	require.NoError(t, err)
	var glDoc struct{ Vulnerabilities []json.RawMessage }
	require.NoError(t, json.NewDecoder(f).Decode(&glDoc))
	require.NoError(t, f.Close())
	require.Len(t, glDoc.Vulnerabilities, 1)
}

func TestFrameworkScopedSARIFEvidenceKeepsCorrelatedRule(t *testing.T) {
	summary := reportsummary.SummaryDetails{Frameworks: []reportsummary.FrameworkSummary{{Name: "NSA", Controls: reportsummary.ControlSummaries{"C-0034": {ControlID: "C-0034"}}}}}
	rule := resourcesresults.ResourceAssociatedRule{Name: "R1", Status: apis.StatusFailed, Paths: []armotypes.PosturePaths{{ReviewPath: "spec.replicas"}}, Exception: []armotypes.PostureExceptionPolicy{
		{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable}, PosturePolicies: []armotypes.PosturePolicy{{ControlID: "C-OTHER", RuleName: "R1"}}},
		{Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly}, PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}}},
	}}
	control := resourcesresults.ResourceAssociatedControl{ControlID: "C-0034", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}, ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{rule}}
	evidence := cautils.FailedRules(&summary, control)
	require.Len(t, evidence.ResourceAssociatedRules, 1)
	fragments := sarifEvidenceIdentity(&evidence)
	require.Len(t, fragments, 1)
	assert.Equal(t, "R1", fragments[0].RuleName)
	assert.Equal(t, []string{"spec.replicas"}, fragments[0].ReviewPaths)
}
