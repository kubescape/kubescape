package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/fleet"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	contractPolicyNSA = `
      policy:
        frameworks: [nsa]`
	contractComplianceFloor80 = `
      failure:
        complianceBelow: 80`
)

var contractNSAPolicies = []cautils.PolicyIdentifier{{Identifier: "nsa", Kind: apisv1.KindFramework}}

// contractGateKubescape completes every scan with a chosen compliance score and
// records what it was asked to scan, so a test can run the real scan command
// through its gates.
type contractGateKubescape struct {
	mocks.MockIKubescape
	complianceScore  float32
	criticalFailures int
	scanned          *cautils.ScanInfo
	policies         []cautils.PolicyIdentifier
}

func (m *contractGateKubescape) Context() context.Context { return context.Background() }

func (m *contractGateKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policies []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	copied := *scanInfo
	m.scanned = &copied
	m.policies = append([]cautils.PolicyIdentifier(nil), policies...)

	results := resultshandling.NewResultsHandler(nil, []printer.IPrinter{&fakePrinter{}}, &fakePrinter{})
	session := cautils.NewOPASessionObjMock()
	session.Report.SummaryDetails.ComplianceScore = m.complianceScore
	session.Report.SummaryDetails.ResourcesSeverityCounters.CriticalSeverityCounter = m.criticalFailures
	results.SetData(session)
	return results, nil
}

// runScanCommand runs "kubescape scan <args>" against ks.
func runScanCommand(ks *contractGateKubescape, args ...string) error {
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(GetScanCommand(ks))
	root.SetArgs(append([]string{"scan"}, args...))
	return root.Execute()
}

// runContractGateScan runs "kubescape scan <args> --scan-contract <contract>" against ks.
func runContractGateScan(t *testing.T, ks *contractGateKubescape, contractBody string, args ...string) error {
	t.Helper()
	return runScanCommand(ks, append(args, "--scan-contract", writeScanContract(t, contractBody))...)
}

func complianceBreach(score, threshold string) string {
	return "scan compliance-score is below permitted threshold: " + score + " (compliance-threshold: " + threshold + ")"
}

// TestContractPolicyScanEnforcesComplianceGate pins that a contract-driven
// policy scan enforces the compliance floor the contract and the runner
// resolve, whichever view it prints, instead of only recording it.
func TestContractPolicyScanEnforcesComplianceGate(t *testing.T) {
	tests := []struct {
		name     string
		contract string
		args     []string
		score    float32
		wantErr  string
		wantView string
	}{
		{
			name:     "contract floor with the default view",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{"."},
			score:    50,
			wantErr:  complianceBreach("50.00", "80.00"),
			wantView: "security",
		},
		{
			name:     "contract floor that is met",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{"."},
			score:    90,
			wantView: "security",
		},
		{
			name: "explicit CLI floor stricter than the contract floor",
			contract: contractPolicyNSA + `
      failure:
        complianceBelow: 70`,
			args:     []string{".", "--compliance-threshold", "90"},
			score:    80,
			wantErr:  complianceBreach("80.00", "90.00"),
			wantView: "security",
		},
		{
			name:     "explicit CLI floor with no contract failure section",
			contract: contractPolicyNSA,
			args:     []string{".", "--compliance-threshold", "80"},
			score:    50,
			wantErr:  complianceBreach("50.00", "80.00"),
			wantView: "security",
		},
		{
			name: "contract floor stricter than the explicit CLI floor",
			contract: contractPolicyNSA + `
      failure:
        complianceBelow: 90`,
			args:     []string{".", "--compliance-threshold", "70"},
			score:    80,
			wantErr:  complianceBreach("80.00", "90.00"),
			wantView: "security",
		},
		{
			name:     "issue reproduction with both sections allowed",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{".", "--contract-allow=policy,failure", "--compliance-threshold", "80"},
			score:    45,
			wantErr:  complianceBreach("45.00", "80.00"),
			wantView: "security",
		},
		{
			name:     "resource view",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{".", "--view", "resource"},
			score:    50,
			wantErr:  complianceBreach("50.00", "80.00"),
			wantView: "resource",
		},
		{
			name:     "resource view with an explicit CLI floor",
			contract: contractPolicyNSA,
			args:     []string{".", "--view", "resource", "--compliance-threshold", "80"},
			score:    50,
			wantErr:  complianceBreach("50.00", "80.00"),
			wantView: "resource",
		},
		{
			name:     "control view",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{".", "--view", "control"},
			score:    50,
			wantErr:  complianceBreach("50.00", "80.00"),
			wantView: "control",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &contractGateKubescape{complianceScore: tt.score}

			err := runContractGateScan(t, ks, tt.contract, tt.args...)

			require.NotNil(t, ks.scanned, "the scan must run")
			assert.Equal(t, contractNSAPolicies, ks.policies, "the contract's policy selection is scanned")
			assert.Equal(t, tt.wantView, ks.scanned.View)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
			assert.True(t, isGateFailure(err))
		})
	}
}

// TestContractComplianceGateDistinguishesDefaultFromExplicitSecurityView pins
// that only an explicitly selected security view keeps the compliance
// exemption: security is also the default view, so a plain contract scan
// resolves to it without asking for the exemption. The provenance of each
// scan describes the gate it actually enforced.
func TestContractComplianceGateDistinguishesDefaultFromExplicitSecurityView(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantEnforced bool
	}{
		{name: "default view", args: []string{"."}, wantEnforced: true},
		{name: "explicit --view security", args: []string{".", "--view", "security"}},
		{name: "explicit --view=security", args: []string{".", "--view=security"}},
		// The scan routes on the view lower-cased, so these select the security
		// view too, and provenance must not call the skipped gate effective.
		{name: "explicit --view Security", args: []string{".", "--view", "Security"}},
		{name: "explicit --view=SECURITY", args: []string{".", "--view=SECURITY"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &contractGateKubescape{complianceScore: 50}

			err := runContractGateScan(t, ks, contractPolicyNSA+contractComplianceFloor80, tt.args...)

			require.NotNil(t, ks.scanned)
			assert.Equal(t, "security", ks.scanned.View, "both resolve to the security view")
			assert.Equal(t, contractNSAPolicies, ks.policies)

			provenance := ks.scanned.ScanContract
			require.NotNil(t, provenance)
			require.NotNil(t, provenance.GateResolution)
			require.NotNil(t, provenance.GateResolution.ComplianceBelow.Contract, "what the contract asked for is always recorded")
			assert.Equal(t, 80.0, *provenance.GateResolution.ComplianceBelow.Contract)
			require.NotNil(t, provenance.Effective)

			if tt.wantEnforced {
				require.EqualError(t, err, complianceBreach("50.00", "80.00"))
				assert.True(t, isGateFailure(err))
				require.NotNil(t, provenance.GateResolution.ComplianceBelow.Effective)
				assert.Equal(t, 80.0, *provenance.GateResolution.ComplianceBelow.Effective)
				require.NotNil(t, provenance.Effective.Failure)
				require.NotNil(t, provenance.Effective.Failure.ComplianceBelow)
				assert.Equal(t, 80.0, *provenance.Effective.Failure.ComplianceBelow)
				return
			}
			require.NoError(t, err, "an explicit security view keeps its compliance exemption")
			assert.Nil(t, provenance.GateResolution.ComplianceBelow.Effective, "an unenforced gate is not effective")
			assert.Nil(t, provenance.Effective.Failure, "the failure section held only the unenforced gate")
			require.NotNil(t, provenance.Effective.Policy)
			assert.Equal(t, []string{"nsa"}, provenance.Effective.Policy.Frameworks)
		})
	}
}

// TestExplicitSecurityViewRecordsAnUnenforcedCLIFloor pins that an explicit
// CLI floor on an explicit security view keeps the exemption, and that its
// provenance records the floor that was asked for without calling it effective.
func TestExplicitSecurityViewRecordsAnUnenforcedCLIFloor(t *testing.T) {
	for _, view := range [][]string{{"--view", "security"}, {"--view=SECURITY"}} {
		t.Run(view[len(view)-1], func(t *testing.T) {
			ks := &contractGateKubescape{complianceScore: 50}

			args := append([]string{"."}, append(view, "--compliance-threshold", "90")...)
			err := runContractGateScan(t, ks, contractPolicyNSA+contractComplianceFloor80, args...)

			require.NoError(t, err)
			require.NotNil(t, ks.scanned)
			resolution := ks.scanned.ScanContract.GateResolution
			require.NotNil(t, resolution)
			assert.Equal(t, 80.0, *resolution.ComplianceBelow.Contract)
			assert.Equal(t, 90.0, *resolution.ComplianceBelow.RunnerFloor)
			assert.Nil(t, resolution.ComplianceBelow.Effective)
			assert.Nil(t, ks.scanned.ScanContract.Effective.Failure)
		})
	}
}

// TestExplicitSecurityViewKeepsOtherContractGates pins that the security
// view's exemption covers only the compliance gate: the contract's other gates
// stay enforced and effective.
func TestExplicitSecurityViewKeepsOtherContractGates(t *testing.T) {
	ks := &contractGateKubescape{complianceScore: 50, criticalFailures: 1}

	err := runContractGateScan(t, ks, contractPolicyNSA+`
      failure:
        severityAtLeast: critical
        complianceBelow: 80`, ".", "--view", "security")

	require.Error(t, err)
	assert.True(t, isGateFailure(err))
	assert.ErrorContains(t, err, "exceeds severity threshold")
	assert.NotContains(t, err.Error(), "compliance-score")

	provenance := ks.scanned.ScanContract
	require.NotNil(t, provenance.Effective.Failure)
	require.NotNil(t, provenance.Effective.Failure.SeverityAtLeast)
	assert.Equal(t, "critical", *provenance.Effective.Failure.SeverityAtLeast)
	assert.Nil(t, provenance.Effective.Failure.ComplianceBelow)
	require.NotNil(t, provenance.GateResolution.SeverityAtLeast.Effective)
	assert.Equal(t, "critical", *provenance.GateResolution.SeverityAtLeast.Effective)
	assert.Nil(t, provenance.GateResolution.ComplianceBelow.Effective)
}

// TestContractWithoutPolicyKeepsItsRouting pins that a contract with no
// effective policy section runs as before, by view: the security view stays
// exempt and the other views reach the framework runner, which enforces the
// gate. Provenance follows what each route enforces.
func TestContractWithoutPolicyKeepsItsRouting(t *testing.T) {
	tests := []struct {
		name         string
		contract     string
		args         []string
		wantEnforced bool
	}{
		{
			name:     "default view stays on the security runner",
			contract: contractComplianceFloor80,
			args:     []string{"."},
		},
		{
			name:     "explicit security view stays on the security runner",
			contract: contractComplianceFloor80,
			args:     []string{".", "--view", "security"},
		},
		{
			name:     "explicit security view in another case stays on the security runner",
			contract: contractComplianceFloor80,
			args:     []string{".", "--view", "Security"},
		},
		{
			name:         "resource view reaches the framework runner",
			contract:     contractComplianceFloor80,
			args:         []string{".", "--view", "resource"},
			wantEnforced: true,
		},
		{
			name:     "policy section denied by --contract-allow",
			contract: contractPolicyNSA + contractComplianceFloor80,
			args:     []string{".", "--contract-allow=failure"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &contractGateKubescape{complianceScore: 50}

			err := runContractGateScan(t, ks, tt.contract, tt.args...)

			require.NotNil(t, ks.scanned)
			assert.NotEqual(t, contractNSAPolicies, ks.policies, "no contract policy selection is scanned")
			resolution := ks.scanned.ScanContract.GateResolution
			require.NotNil(t, resolution)
			assert.Equal(t, 80.0, *resolution.ComplianceBelow.Contract)
			if tt.wantEnforced {
				require.EqualError(t, err, complianceBreach("50.00", "80.00"))
				require.NotNil(t, resolution.ComplianceBelow.Effective)
				assert.Equal(t, 80.0, *resolution.ComplianceBelow.Effective)
				return
			}
			require.NoError(t, err)
			assert.Nil(t, resolution.ComplianceBelow.Effective)
			assert.Nil(t, ks.scanned.ScanContract.Effective, "the contract's only section was the unenforced gate")
		})
	}
}

// TestContractAllowWithoutFailureAppliesNoContractFloor pins that a failure
// section denied by --contract-allow sets no compliance floor to enforce.
func TestContractAllowWithoutFailureAppliesNoContractFloor(t *testing.T) {
	ks := &contractGateKubescape{complianceScore: 50}

	err := runContractGateScan(t, ks, contractPolicyNSA+contractComplianceFloor80, ".", "--contract-allow=policy")

	require.NoError(t, err)
	assert.Equal(t, contractNSAPolicies, ks.policies)
	assert.Nil(t, ks.scanned.ScanContract.GateResolution)
}

// TestScanWithoutContractKeepsSecurityViewExemption pins the documented
// behavior this fix leaves alone: without a contract, the security view does
// not enforce --compliance-threshold, and the resource view does.
func TestScanWithoutContractKeepsSecurityViewExemption(t *testing.T) {
	ks := &contractGateKubescape{complianceScore: 50}
	require.NoError(t, runScanCommand(ks, ".", "--compliance-threshold", "80"))

	ks = &contractGateKubescape{complianceScore: 50}
	require.EqualError(t, runScanCommand(ks, ".", "--view", "resource", "--compliance-threshold", "80"), complianceBreach("50.00", "80.00"))
}

// TestContractFleetScanEnforcesComplianceGatePerContext pins that the runner a
// contract-driven policy scan uses enforces the compliance gate in every
// context of a fleet scan, while the security view's runner does not.
func TestContractFleetScanEnforcesComplianceGatePerContext(t *testing.T) {
	scored := func() (*resultshandling.ResultsHandler, error) { return resultsWithControl(apis.StatusPassed, 50), nil }
	newKubescape := func() *fleetOutcomeKubescape {
		return &fleetOutcomeKubescape{outcomes: map[string]func() (*resultshandling.ResultsHandler, error){"prod": scored, "staging": scored}}
	}

	scanInfo := exitScanInfo(t)
	scanInfo.ComplianceThreshold = 80
	err := securityScanWith(scanInfo, newKubescape(), contractNSAPolicies, runSecurityScanWithCompliance)

	require.Error(t, err)
	assert.Equal(t, exitGateFailed, shared.ExitCode(err))
	assert.ErrorContains(t, err, "prod: "+complianceBreach("50.00", "80.00"))
	assert.ErrorContains(t, err, "staging: "+complianceBreach("50.00", "80.00"))

	scanInfo = exitScanInfo(t)
	scanInfo.ComplianceThreshold = 80
	assert.NoError(t, securityScanWith(scanInfo, newKubescape(), contractNSAPolicies, runSecurityScan))
}

// runBareFleetE2E is runFleetE2E for the bare scan command rather than "scan
// framework nsa". It also returns the directory the per-context reports are in.
func runBareFleetE2E(t *testing.T, servers map[string]string, args ...string) (fleetRun, string) {
	t.Helper()
	fleetReport := prepareFleetE2E(t, servers)
	run := scanFleetE2EWith(t, fleetReport, nil, args...)
	run.report = readFleetReport(t, fleetReport)
	return run, filepath.Dir(fleetReport)
}

// contractProvenanceIn reads the scan contract provenance one context's report recorded.
func contractProvenanceIn(t *testing.T, dir, kubeContext string) *reporthandlingv2.ScanContractMetadata {
	t.Helper()
	path, err := perContextOutputPath(filepath.Join(dir, "report.json"), kubeContext)
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var report struct {
		Metadata struct {
			ScanMetadata struct {
				ScanContract *reporthandlingv2.ScanContractMetadata `json:"scanContract"`
			} `json:"scanMetadata"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(data, &report))
	require.NotNil(t, report.Metadata.ScanMetadata.ScanContract, "the report of %s records its scan contract", kubeContext)
	return report.Metadata.ScanMetadata.ScanContract
}

// TestFleetE2E_ContractPolicyScanEnforcesComplianceGate pins the supported
// fleet invocation of a contract-driven policy scan, the bare scan command in
// the security view, end to end: the contract floor and a stricter explicit
// CLI floor fail the run, an explicitly selected security view keeps its
// exemption, and both hold when each context runs in its own process. Every
// context's report records the gate it enforced.
func TestFleetE2E_ContractPolicyScanEnforcesComplianceGate(t *testing.T) {
	const floor100 = contractPolicyNSA + `
      failure:
        complianceBelow: 100`
	const floor10 = contractPolicyNSA + `
      failure:
        complianceBelow: 10`

	tests := []struct {
		name     string
		contract string
		args     []string
		parallel bool
		wantExit int
		// wantEffective is the compliance floor each report records as
		// effective; 0 means the gate was not enforced and is not effective.
		wantEffective float64
	}{
		{name: "contract floor", contract: floor100, wantExit: exitGateFailed, wantEffective: 100},
		{name: "explicit CLI floor stricter than the contract", contract: floor10, args: []string{"--compliance-threshold=100"}, wantExit: exitGateFailed, wantEffective: 100},
		{name: "explicit security view", contract: floor100, args: []string{"--view=security"}, wantExit: 0},
		{name: "contract floor in child processes", contract: floor100, parallel: true, wantExit: exitGateFailed, wantEffective: 100},
		{name: "explicit security view in child processes", contract: floor100, args: []string{"--view=security"}, parallel: true, wantExit: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			servers := map[string]string{"prod": newFakeAPIServer(t, 0, false).URL}
			kubeContexts := []string{"prod"}
			var parallel []string
			var started *atomic.Int32
			if tt.parallel {
				started = useTestBinaryForChildren(t)
				servers["staging"] = newFakeAPIServer(t, 0, false).URL
				kubeContexts = append(kubeContexts, "staging")
				parallel = []string{"--parallel=2", "--retries=0"}
			}
			args := append([]string{"--kube-contexts=" + strings.Join(kubeContexts, ","), "--scan-contract=" + writeScanContract(t, tt.contract)}, append(parallel, tt.args...)...)

			run, dir := runBareFleetE2E(t, servers, args...)

			assert.Equal(t, tt.wantExit, run.exitCode, "error: %v", run.err)
			if tt.parallel {
				assert.EqualValues(t, len(kubeContexts), started.Load(), "each context is scanned by its own child process")
			}
			for _, kubeContext := range kubeContexts {
				assert.Equal(t, fleet.ClusterScanned, clusterNamed(t, run.report, kubeContext).Status, "a breach is still a measurement")

				provenance := contractProvenanceIn(t, dir, kubeContext)
				assert.Regexp(t, `^sha256:[0-9a-f]{64}$`, provenance.EffectiveRunDigest)
				require.NotNil(t, provenance.GateResolution)
				require.NotNil(t, provenance.GateResolution.ComplianceBelow.Contract)
				require.NotNil(t, provenance.Effective)
				if tt.wantEffective == 0 {
					assert.Nil(t, provenance.GateResolution.ComplianceBelow.Effective, "%s: an unenforced gate is not effective", kubeContext)
					assert.Nil(t, provenance.Effective.Failure, "%s: the failure section held only the unenforced gate", kubeContext)
					continue
				}
				require.NotNil(t, provenance.GateResolution.ComplianceBelow.Effective, kubeContext)
				assert.Equal(t, tt.wantEffective, *provenance.GateResolution.ComplianceBelow.Effective, kubeContext)
				require.NotNil(t, provenance.Effective.Failure, kubeContext)
				require.NotNil(t, provenance.Effective.Failure.ComplianceBelow, kubeContext)
				assert.Equal(t, tt.wantEffective, *provenance.Effective.Failure.ComplianceBelow, kubeContext)
			}
			if tt.wantExit == 0 {
				assert.NoError(t, run.err)
				return
			}
			assert.ErrorContains(t, run.err, "compliance-score is below permitted threshold")
		})
	}
}
