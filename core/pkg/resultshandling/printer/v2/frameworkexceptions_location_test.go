package printer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	locationManifest = `apiVersion: apps/v1
kind: Deployment
metadata: {name: demo, namespace: default}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo}}
  template:
    metadata: {labels: {app: demo}}
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: app
        image: nginx:1.23
`
	hostNetworkLine = 10
	hostPIDLine     = 11

	hostNetworkFixPath = "spec.template.spec.hostNetwork"
	hostPIDFixPath     = "spec.template.spec.hostPID"
)

// mixedRuleControl is a control whose first fix path belongs to a rule that an
// NSA-scoped exception removes and whose second belongs to a rule nothing
// excepts, so the first fix path is the one a location taken from the raw
// control would pick.
func mixedRuleControl() resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: testHostNetworkControl,
		Name:      "HostNetwork access",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
			{
				Name:   "host-network-access",
				Status: apis.StatusFailed,
				Paths:  []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostNetworkFixPath, Value: "false"}}},
				Exception: []armotypes.PostureExceptionPolicy{{
					PortalBase:      armotypes.PortalBase{Name: "nsa-only-hostnetwork"},
					Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
					PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: testHostNetworkControl}},
				}},
			},
			{
				Name:   "host-pid-access",
				Status: apis.StatusFailed,
				Paths:  []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: hostPIDFixPath, Value: "false"}}},
			},
		},
	}
}

// withMixedRuleControl turns a printer fixture into a scan of the given
// framework whose only control is mixedRuleControl, on a manifest that sets both
// fields.
func withMixedRuleControl(t *testing.T, session *cautils.OPASessionObj, framework string) *cautils.OPASessionObj {
	t.Helper()
	for id, source := range session.ResourceSource {
		require.NoError(t, os.WriteFile(filepath.Join(source.Path, source.RelativePath), []byte(locationManifest), 0o600))
		result := session.ResourcesResult[id]
		result.AssociatedControls = []resourcesresults.ResourceAssociatedControl{mixedRuleControl()}
		session.ResourcesResult[id] = result
	}
	controls := reportsummary.ControlSummaries{
		testHostNetworkControl: {ControlID: testHostNetworkControl, Name: "HostNetwork access", ScoreFactor: 8.0},
	}
	session.Report.SummaryDetails.Controls = controls
	session.Report.SummaryDetails.Frameworks = []reportsummary.FrameworkSummary{{Name: framework, Controls: controls}}
	return session
}

func TestGitHubActionsPrinter_AnnotationIgnoresExceptedRule(t *testing.T) {
	for _, tc := range []struct {
		name          string
		framework     string
		wantLine      string
		wantPaths     []string
		wantNotInText []string
	}{
		{
			name:          "excepted framework",
			framework:     "NSA",
			wantLine:      "line=11",
			wantPaths:     []string{hostPIDFixPath + "=false"},
			wantNotInText: []string{hostNetworkFixPath, "line=10"},
		},
		{
			name:      "framework without the exception",
			framework: "MITRE",
			wantLine:  "line=10",
			wantPaths: []string{hostNetworkFixPath + "=false", hostPIDFixPath + "=false"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origWD, err := os.Getwd()
			require.NoError(t, err)
			defer func() { _ = os.Chdir(origWD) }()
			require.NoError(t, os.Chdir(t.TempDir()))

			session := withMixedRuleControl(t, ghSessionFixture(t, testHostNetworkControl, 8.0), tc.framework)
			output := ghOutputFor(t, session)

			assert.Contains(t, output, tc.wantLine)
			for _, want := range tc.wantPaths {
				assert.Contains(t, output, want)
			}
			for _, unwanted := range tc.wantNotInText {
				assert.NotContains(t, output, unwanted)
			}
			assert.Contains(t, output, "1 of 1 High/Critical finding(s) annotated")
		})
	}
}

func TestGitLabSASTPrintConfigurationScan_LocationIgnoresExceptedRule(t *testing.T) {
	for _, tc := range []struct {
		name         string
		framework    string
		wantLine     int
		wantSolution string
		wantAbsent   string
	}{
		{
			name:         "excepted framework",
			framework:    "NSA",
			wantLine:     hostPIDLine,
			wantSolution: hostPIDFixPath + "=false",
			wantAbsent:   hostNetworkFixPath,
		},
		{
			name:         "framework without the exception",
			framework:    "MITRE",
			wantLine:     hostNetworkLine,
			wantSolution: hostNetworkFixPath + "=false\n" + hostPIDFixPath + "=false",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origWD, err := os.Getwd()
			require.NoError(t, err)
			defer func() { _ = os.Chdir(origWD) }()
			require.NoError(t, os.Chdir(t.TempDir()))

			session := withMixedRuleControl(t, gitLabSessionFixture(t, testHostNetworkControl, 8.0), tc.framework)
			report := gitLabReportFor(t, session)

			require.Len(t, report.Vulnerabilities, 1)
			vuln := report.Vulnerabilities[0]
			assert.Equal(t, tc.wantLine, vuln.Location.StartLine)
			assert.Equal(t, tc.wantSolution, vuln.Solution)
			if tc.wantAbsent != "" {
				assert.NotContains(t, vuln.Solution, tc.wantAbsent)
			}
		})
	}
}

// The raw control is only read: building the displayed evidence must not drop
// the excepted rule, or its exception, from the scan's own evaluation.
func TestGitHubActionsPrinter_LeavesRawControlIntact(t *testing.T) {
	origWD, err := os.Getwd()
	require.NoError(t, err)
	defer func() { _ = os.Chdir(origWD) }()
	require.NoError(t, os.Chdir(t.TempDir()))

	session := withMixedRuleControl(t, ghSessionFixture(t, testHostNetworkControl, 8.0), "NSA")
	_ = ghOutputFor(t, session)

	for _, result := range session.ResourcesResult {
		rules := result.AssociatedControls[0].ResourceAssociatedRules
		require.Len(t, rules, 2)
		assert.Equal(t, apis.StatusFailed, rules[0].Status)
		assert.Len(t, rules[0].Exception, 1)
	}
}
