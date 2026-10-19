package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGateFailuresAreMarked pins that every gate breach is marked as a gate, with its message unchanged.
func TestGateFailuresAreMarked(t *testing.T) {
	critical := match.NewMatches(match.Match{Vulnerability: vulnerability.Vulnerability{
		Reference: vulnerability.Reference{ID: "CVE-TEST"},
		Metadata:  &vulnerability.Metadata{Severity: vulnerability.CriticalSeverity.String()},
	}})
	degraded := cautils.ScanCoverage{PolicyDegradations: []cautils.PolicyDegradation{{Component: "controls", Reason: "cache"}}}

	tests := map[string]struct {
		err     error
		message string
	}{
		"severity threshold": {
			err: enforceSeverityThresholds(&reportsummary.SummaryDetails{ResourcesSeverityCounters: reportsummary.SeverityCounters{CriticalSeverityCounter: 1}},
				&cautils.ScanInfo{FailThresholdSeverity: apis.SeverityCriticalString}),
			message: "compliance result exceeds severity threshold: Critical",
		},
		"severity threshold on unknown severity": {
			err: enforceSeverityThresholds(&reportsummary.SummaryDetails{Controls: map[string]reportsummary.ControlSummary{
				"C-0001": {StatusCounters: reportsummary.StatusCounters{FailedResources: 1}},
			}}, &cautils.ScanInfo{FailThresholdSeverity: apis.SeverityLowString}),
			message: "compliance result exceeds severity threshold: Low (1 failed resource(s) with unknown severity)",
		},
		"image severity threshold": {
			err:     enforceImageSeverityThresholds([]cautils.ImageScanData{{Matches: critical}}, &cautils.ScanInfo{FailThresholdSeverity: "high"}),
			message: "image scan result exceeds severity threshold: high",
		},
		"coverage floor": {
			err:     enforceCoverageThreshold(cautils.ScanCoverage{CoverageScore: 40}, 1, &cautils.ScanInfo{FailCoverageThreshold: 80}),
			message: "scan coverage is below permitted threshold: 40.00% (fail-coverage-below: 80.00%)",
		},
		"coverage floor of 100 with a score just below it": {
			err:     enforceCoverageThreshold(cautils.ScanCoverage{CoverageScore: 99.996}, 1, &cautils.ScanInfo{FailCoverageThreshold: 100}),
			message: "scan coverage is below permitted threshold: 99.99% (fail-coverage-below: 100.00%)",
		},
		"coverage floor with no controls": {
			err:     enforceCoverageThreshold(cautils.ScanCoverage{}, 0, &cautils.ScanInfo{FailCoverageThreshold: 1}),
			message: "scan loaded no controls: coverage is 0% (fail-coverage-below: 1.00%)",
		},
		"degraded policy": {
			err:     enforcePolicyDegradation(degraded, &cautils.ScanInfo{FailOnDegradedConfig: true}),
			message: "scan policy inputs were degraded (fail-on-degraded-config is true)",
		},
		"baseline drift": {
			err:     enforceBaselineDrift(context.Background(), resultsFailingOn("res1"), baselineScanInfo(t)),
			message: `baseline drift: found 1 new failure(s) at or above baseline severity threshold "all"`,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.EqualError(t, tt.err, tt.message)
			assert.True(t, isGateFailure(tt.err))
		})
	}
}

// TestComplianceThresholdIsAGate pins the compliance gate in each runner that enforces it.
func TestComplianceThresholdIsAGate(t *testing.T) {
	runners := map[string]fleetRunner{"framework": runFrameworkScan, "control": runControlScan, "workload": runWorkloadScan}
	for name, run := range runners {
		t.Run(name, func(t *testing.T) {
			var ks meta.IKubescape = &scoredWorkloadKubescape{complianceScore: 50}
			results, err := run(context.Background(), &cautils.ScanInfo{ComplianceThreshold: 80}, ks, nil)

			require.NotNil(t, results)
			require.EqualError(t, err, "scan compliance-score is below permitted threshold: 50.00 (compliance-threshold: 80.00)")
			assert.True(t, isGateFailure(err))
		})
	}
}

// TestComplianceThresholdMessageKeepsNearPerfectScoreBelowHundred pins that a score just under a threshold of 100 is not reported as 100.00.
func TestComplianceThresholdMessageKeepsNearPerfectScoreBelowHundred(t *testing.T) {
	runners := map[string]fleetRunner{"framework": runFrameworkScan, "control": runControlScan, "workload": runWorkloadScan}
	for name, run := range runners {
		t.Run(name, func(t *testing.T) {
			var ks meta.IKubescape = &scoredWorkloadKubescape{complianceScore: 99.996}
			_, err := run(context.Background(), &cautils.ScanInfo{ComplianceThreshold: 100}, ks, nil)

			require.EqualError(t, err, "scan compliance-score is below permitted threshold: 99.99 (compliance-threshold: 100.00)")
		})
	}
}

// TestFailuresThatAreNotGates pins that a gate that could not be evaluated is not counted as a breach.
func TestFailuresThatAreNotGates(t *testing.T) {
	invalidSeverity := enforceSeverityThresholds(&reportsummary.SummaryDetails{}, &cautils.ScanInfo{FailThresholdSeverity: "bogus"})
	require.Error(t, invalidSeverity)
	assert.False(t, isGateFailure(invalidSeverity))

	scanInfo := baselineScanInfo(t)
	scanInfo.Baseline = filepath.Join(t.TempDir(), "missing.json")
	unreadableBaseline := enforceBaselineDrift(context.Background(), resultsFailingOn("res1"), scanInfo)
	require.ErrorContains(t, unreadableBaseline, "comparing against baseline")
	assert.False(t, isGateFailure(unreadableBaseline))
}

// resultsFailingOn returns results where control C-0016 failed on the given resource.
func resultsFailingOn(resourceID string) *resultshandling.ResultsHandler {
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{"C-0016": {ControlID: "C-0016", Name: "Allow privilege escalation", ScoreFactor: 5}}
	session.ResourcesResult = map[string]resourcesresults.Result{resourceID: {
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{{
			ControlID:               "C-0016",
			Name:                    "Allow privilege escalation",
			Status:                  apis.StatusInfo{InnerStatus: apis.StatusFailed},
			ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{Name: "rule", Status: apis.StatusFailed}},
		}},
	}}
	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	results.SetData(session)
	return results
}

// baselineScanInfo points --baseline at a report where C-0016 passed on res1.
func baselineScanInfo(t *testing.T) *cautils.ScanInfo {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	baseline := `{"results":[{"resourceID":"res1","controls":[{"controlID":"C-0016","name":"Allow privilege escalation","status":{"status":"passed"}}]}],"summaryDetails":{"controls":{}}}`
	require.NoError(t, os.WriteFile(path, []byte(baseline), 0o600))
	return &cautils.ScanInfo{Baseline: path, BaselineFailOnNew: true}
}
