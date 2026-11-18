package scan

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scoredKubescape returns a finished scan with a fixed compliance score, so the
// tests can tell whether the compliance gate ran.
type scoredKubescape struct {
	mocks.MockIKubescape
	score    float32
	calls    int
	scanInfo *cautils.ScanInfo
}

func (m *scoredKubescape) Context() context.Context { return context.Background() }

func (m *scoredKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	m.calls++
	m.scanInfo = scanInfo
	results := resultshandling.NewResultsHandler(nil, nil, &fakePrinter{})
	data := cautils.NewOPASessionObjMock()
	data.Report.SummaryDetails.ComplianceScore = m.score
	results.SetData(data)
	return results, nil
}

const contractPolicyBody = `
      policy:
        frameworks: [nsa]`

func runScoredScan(t *testing.T, score float32, contractBody string, args ...string) (*scoredKubescape, error) {
	t.Helper()
	ks := &scoredKubescape{score: score}
	if contractBody != "" {
		args = append(args, "--scan-contract", writeScanContract(t, contractBody))
	}
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(GetScanCommand(ks))
	root.SetArgs(append([]string{"scan"}, args...))
	return ks, root.Execute()
}

func TestContractPolicyScanEnforcesComplianceFloor(t *testing.T) {
	tests := []struct {
		name    string
		score   float32
		failure string
		args    []string
		wantErr bool
	}{
		{name: "contract floor not met", score: 50, failure: "complianceBelow: 80", wantErr: true},
		{name: "contract floor met", score: 85, failure: "complianceBelow: 80"},
		{name: "explicit flag not met without a contract floor", score: 50, args: []string{"--compliance-threshold", "80"}, wantErr: true},
		{name: "explicit flag stricter than contract floor", score: 70, failure: "complianceBelow: 40", args: []string{"--compliance-threshold", "80"}, wantErr: true},
		{name: "resource view", score: 50, failure: "complianceBelow: 80", args: []string{"--view", "resource"}, wantErr: true},
		{name: "explicit security view stays exempt", score: 50, failure: "complianceBelow: 80", args: []string{"--view", "security"}},
		{name: "explicit security view in another case stays exempt", score: 50, failure: "complianceBelow: 80", args: []string{"--view", "Security"}},
		{name: "no floor configured", score: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := contractPolicyBody
			if tt.failure != "" {
				body += "\n      failure:\n        " + tt.failure
			}
			ks, err := runScoredScan(t, tt.score, body, tt.args...)
			require.Equal(t, 1, ks.calls)
			if tt.wantErr {
				assert.ErrorContains(t, err, "scan compliance-score is below permitted threshold")
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestContractPolicyScanEnforcesComplianceFloorAcrossFleet(t *testing.T) {
	body := contractPolicyBody + "\n      failure:\n        complianceBelow: 80"
	ks, err := runScoredScan(t, 50, body, "--kube-contexts", "ctx-a,ctx-b", "--output", filepath.Join(t.TempDir(), "report"))
	require.Equal(t, 2, ks.calls)
	assert.ErrorContains(t, err, "2 of 2 context(s) failed")
}

func TestSecurityViewWithoutContractIgnoresComplianceThreshold(t *testing.T) {
	ks, err := runScoredScan(t, 50, "", "--compliance-threshold", "80")
	require.Equal(t, 1, ks.calls)
	assert.NoError(t, err)
}

func TestContractPolicyScanProvenanceReportsEnforcedComplianceGate(t *testing.T) {
	body := contractPolicyBody + "\n      failure:\n        complianceBelow: 80"
	ks, err := runScoredScan(t, 85, body)
	require.NoError(t, err)
	require.NotNil(t, ks.scanInfo.ScanContract)

	metadata := ks.scanInfo.ScanContract
	require.NotNil(t, metadata.GateResolution.ComplianceBelow.Effective)
	assert.Equal(t, 80.0, *metadata.GateResolution.ComplianceBelow.Effective)
	require.NotNil(t, metadata.Effective.Failure)
	require.NotNil(t, metadata.Effective.Failure.ComplianceBelow)
	assert.Equal(t, 80.0, *metadata.Effective.Failure.ComplianceBelow)
}

func TestContractPolicyScanProvenanceOmitsExemptComplianceGate(t *testing.T) {
	tests := []struct {
		name        string
		failure     string
		wantFailure bool
	}{
		{name: "compliance gate only", failure: "complianceBelow: 80"},
		{name: "other gates stay effective", failure: "complianceBelow: 80\n        severityAtLeast: high", wantFailure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := contractPolicyBody + "\n      failure:\n        " + tt.failure
			ks, err := runScoredScan(t, 50, body, "--view", "security")
			require.NoError(t, err)
			require.NotNil(t, ks.scanInfo.ScanContract)

			metadata := ks.scanInfo.ScanContract
			require.NotNil(t, metadata.GateResolution)
			require.NotNil(t, metadata.GateResolution.ComplianceBelow.Contract)
			assert.Equal(t, 80.0, *metadata.GateResolution.ComplianceBelow.Contract)
			assert.Nil(t, metadata.GateResolution.ComplianceBelow.Effective)
			if !tt.wantFailure {
				assert.Nil(t, metadata.Effective.Failure)
				return
			}
			require.NotNil(t, metadata.Effective.Failure)
			assert.Nil(t, metadata.Effective.Failure.ComplianceBelow)
			require.NotNil(t, metadata.Effective.Failure.SeverityAtLeast)
			assert.Equal(t, "high", *metadata.Effective.Failure.SeverityAtLeast)
		})
	}
}
