package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errContractScanReached = errors.New("contract scan reached")

type contractCaptureKubescape struct {
	mocks.MockIKubescape
	captured *cautils.ScanInfo
	policies []cautils.PolicyIdentifier
}

func (m *contractCaptureKubescape) Context() context.Context {
	return context.Background()
}

func (m *contractCaptureKubescape) ScanContext(_ context.Context, scanInfo *cautils.ScanInfo, policies []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	copied := *scanInfo
	m.captured = &copied
	m.policies = append([]cautils.PolicyIdentifier(nil), policies...)
	return nil, errContractScanReached
}

func writeScanContract(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubescape.yaml")
	document := fmt.Sprintf(`apiVersion: config.kubescape.io/v1alpha1
kind: ScanContract
metadata:
  name: application-test
spec:
  minimumKubescapeVersion: v0.0.1
  defaultContract: ci
  contracts:
    ci:
%s
`, body)
	require.NoError(t, os.WriteFile(path, []byte(document), 0o600))
	return path
}

func executeCapturedScan(t *testing.T, contractBody string, args ...string) (*cautils.ScanInfo, []cautils.PolicyIdentifier, error) {
	t.Helper()
	path := writeScanContract(t, contractBody)
	ks := &contractCaptureKubescape{}
	cmd := GetScanCommand(ks)
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(cmd)
	root.SetArgs(append([]string{"scan"}, append(args, "--scan-contract", path)...))
	err := root.Execute()
	return ks.captured, ks.policies, err
}

func TestScanContractAppliesOrdinarySettings(t *testing.T) {
	scanInfo, policies, err := executeCapturedScan(t, `
      policy:
        frameworks: [nsa]
        controlsVersion: v2.0.307
      scope:
        includeNamespaces: [payments, shared]
      evaluation:
        scanTimeout: 2m
        controlTimeout: 30s
      output:
        formats: [json, sarif]
        omitRawResources: true`, ".")

	require.ErrorIs(t, err, errContractScanReached)
	require.NotNil(t, scanInfo)
	assert.Equal(t, "v2.0.307", scanInfo.ControlsVersion)
	assert.Equal(t, "payments,shared", scanInfo.IncludeNamespaces)
	assert.Equal(t, 2*time.Minute, scanInfo.ScanTimeout)
	assert.Equal(t, 30*time.Second, scanInfo.ControlTimeout)
	assert.Equal(t, "json,sarif", scanInfo.Format)
	assert.True(t, scanInfo.OmitRawResources)
	assert.Equal(t, cautils.ScanTypeRepo, scanInfo.ScanType)
	require.Equal(t, []cautils.PolicyIdentifier{{Identifier: "nsa", Kind: apisv1.KindFramework}}, policies)
}

func TestExplicitCLIOverridesOrdinaryContractSettings(t *testing.T) {
	scanInfo, _, err := executeCapturedScan(t, `
      policy:
        frameworks: [nsa]
        controlsVersion: v2.0.307
      scope:
        includeNamespaces: [contract-ns]
      evaluation:
        scanTimeout: 2m
        controlTimeout: 30s
      output:
        formats: [json]
        omitRawResources: true`,
		".",
		"--controls-version", "v2.0.400",
		"--include-namespaces", "runner-ns",
		"--scan-timeout", "5m",
		"--control-timeout", "1m",
		"--format", "yaml",
		"--omit-raw-resources=false")

	require.ErrorIs(t, err, errContractScanReached)
	require.NotNil(t, scanInfo)
	assert.Equal(t, "v2.0.400", scanInfo.ControlsVersion)
	assert.Equal(t, "runner-ns", scanInfo.IncludeNamespaces)
	assert.Equal(t, 5*time.Minute, scanInfo.ScanTimeout)
	assert.Equal(t, time.Minute, scanInfo.ControlTimeout)
	assert.Equal(t, "yaml", scanInfo.Format)
	assert.False(t, scanInfo.OmitRawResources)
}

func TestExplicitNamespaceModeOverridesTheContractNamespaceMode(t *testing.T) {
	tests := []struct {
		name          string
		contractScope string
		flags         []string
		wantIncluded  string
		wantExcluded  string
	}{
		{
			name:          "runner include replaces contract exclude",
			contractScope: "excludeNamespaces: [contract-excluded]",
			flags:         []string{"--include-namespaces", "runner-included"},
			wantIncluded:  "runner-included",
		},
		{
			name:          "runner exclude replaces contract include",
			contractScope: "includeNamespaces: [contract-included]",
			flags:         []string{"--exclude-namespaces", "runner-excluded"},
			wantExcluded:  "runner-excluded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`
      policy:
        frameworks: [nsa]
      scope:
        %s`, tt.contractScope)
			args := append([]string{"."}, tt.flags...)
			scanInfo, _, err := executeCapturedScan(t, body, args...)

			require.ErrorIs(t, err, errContractScanReached)
			require.NotNil(t, scanInfo)
			assert.Equal(t, tt.wantIncluded, scanInfo.IncludeNamespaces)
			assert.Equal(t, tt.wantExcluded, scanInfo.ExcludedNamespaces)
		})
	}
}

func TestContractAndCLIGateFloorsResolveMonotonically(t *testing.T) {
	tests := []struct {
		name                         string
		failure                      string
		flags                        []string
		wantSeverity                 string
		wantCompliance, wantCoverage float32
		wantDegraded                 bool
	}{
		{
			name: "contract supplies gates when runner has no floor",
			failure: `severityAtLeast: medium
        complianceBelow: 80
        coverageBelow: 90
        degradedPolicyInput: fail`,
			wantSeverity: "medium", wantCompliance: 80, wantCoverage: 90, wantDegraded: true,
		},
		{
			name: "contract tightens every runner floor",
			failure: `severityAtLeast: low
        complianceBelow: 95
        coverageBelow: 98
        degradedPolicyInput: fail`,
			flags:        []string{"--severity-threshold", "high", "--compliance-threshold", "80", "--fail-coverage-below", "90", "--fail-on-degraded-config=false"},
			wantSeverity: "low", wantCompliance: 95, wantCoverage: 98, wantDegraded: true,
		},
		{
			name: "contract cannot weaken any runner floor",
			failure: `severityAtLeast: critical
        complianceBelow: 70
        coverageBelow: 75
        degradedPolicyInput: allow`,
			flags:        []string{"--severity-threshold", "medium", "--compliance-threshold", "85", "--fail-coverage-below", "92", "--fail-on-degraded-config"},
			wantSeverity: "medium", wantCompliance: 85, wantCoverage: 92, wantDegraded: true,
		},
		{
			name: "equal gates remain equal",
			failure: `severityAtLeast: high
        complianceBelow: 80
        coverageBelow: 90
        degradedPolicyInput: allow`,
			flags:        []string{"--severity-threshold", "high", "--compliance-threshold", "80", "--fail-coverage-below", "90", "--fail-on-degraded-config=false"},
			wantSeverity: "high", wantCompliance: 80, wantCoverage: 90, wantDegraded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`
      policy:
        frameworks: [nsa]
      failure:
        %s`, tt.failure)
			args := append([]string{"."}, tt.flags...)
			scanInfo, _, err := executeCapturedScan(t, body, args...)

			require.ErrorIs(t, err, errContractScanReached)
			require.NotNil(t, scanInfo)
			assert.Equal(t, tt.wantSeverity, scanInfo.FailThresholdSeverity)
			assert.Equal(t, tt.wantCompliance, scanInfo.ComplianceThreshold)
			assert.Equal(t, tt.wantCoverage, scanInfo.FailCoverageThreshold)
			assert.Equal(t, tt.wantDegraded, scanInfo.FailOnDegradedConfig)
		})
	}
}

func TestContractPolicyCanMixFrameworksAndControls(t *testing.T) {
	_, policies, err := executeCapturedScan(t, `
      policy:
        frameworks: [nsa, mitre]
        controls: [C-0013]`, ".")

	require.ErrorIs(t, err, errContractScanReached)
	assert.Equal(t, []cautils.PolicyIdentifier{
		{Identifier: "nsa", Kind: apisv1.KindFramework},
		{Identifier: "mitre", Kind: apisv1.KindFramework},
		{Identifier: "C-0013", Kind: apisv1.KindControl},
	}, policies)
}

func TestExplicitPolicySubcommandOverridesContractPolicySelection(t *testing.T) {
	_, policies, err := executeCapturedScan(t, `
      policy:
        frameworks: [mitre]
        controls: [C-0013]`, "framework", "nsa", ".")

	require.ErrorIs(t, err, errContractScanReached)
	assert.Equal(t, []cautils.PolicyIdentifier{{Identifier: "nsa", Kind: apisv1.KindFramework}}, policies)
}

func TestContractControlsVersionRejectsBypassModes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "account", args: []string{"--account", "runner-account"}, want: "--account"},
		{name: "artifact directory", args: []string{"--use-artifacts-from", "artifacts"}, want: "--use-artifacts-from"},
		{name: "local policy", args: []string{"--use-from", "framework.json"}, want: "--use-from"},
		{name: "cached default", args: []string{"--use-default"}, want: "--use-default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"."}, tt.args...)
			scanInfo, _, err := executeCapturedScan(t, `
      policy:
        frameworks: [nsa]
        controlsVersion: v2.0.307`, args...)

			assert.Nil(t, scanInfo)
			require.Error(t, err)
			assert.ErrorContains(t, err, "policy.controlsVersion cannot be used")
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

func TestContractNameRequiresContractFile(t *testing.T) {
	cmd := GetScanCommand(&contractCaptureKubescape{})
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(cmd)
	root.SetArgs([]string{"scan", ".", "--contract", "ci"})

	err := root.Execute()
	require.EqualError(t, err, "--contract requires --scan-contract")
}

func TestScanContractIsRejectedForImageCommand(t *testing.T) {
	path := writeScanContract(t, `
      policy:
        frameworks: [nsa]`)
	cmd := GetScanCommand(&contractCaptureKubescape{})
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(cmd)
	root.SetArgs([]string{"scan", "image", "nginx:latest", "--scan-contract", path})

	err := root.Execute()
	require.EqualError(t, err, "--scan-contract is supported for posture scans, not image scans")
}

func TestContractDrivenAndFlagOnlySettingsAreEquivalent(t *testing.T) {
	contractInfo, _, contractErr := executeCapturedScan(t, `
      scope:
        excludeNamespaces: [kube-system, monitoring]
      evaluation:
        scanTimeout: 3m
        controlTimeout: 20s
      output:
        formats: [json]
        omitRawResources: true
      failure:
        severityAtLeast: high
        complianceBelow: 80
        coverageBelow: 95
        degradedPolicyInput: fail`, "framework", "nsa", ".")
	require.ErrorIs(t, contractErr, errContractScanReached)

	ks := &contractCaptureKubescape{}
	cmd := GetScanCommand(ks)
	root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(cmd)
	root.SetArgs([]string{
		"scan", "framework", "nsa", ".",
		"--exclude-namespaces", "kube-system,monitoring",
		"--scan-timeout", "3m",
		"--control-timeout", "20s",
		"--format", "json",
		"--omit-raw-resources",
		"--severity-threshold", "high",
		"--compliance-threshold", "80",
		"--fail-coverage-below", "95",
		"--fail-on-degraded-config",
	})
	flagErr := root.Execute()
	require.ErrorIs(t, flagErr, errContractScanReached)
	require.NotNil(t, ks.captured)

	assert.Equal(t, ks.captured.ExcludedNamespaces, contractInfo.ExcludedNamespaces)
	assert.Equal(t, ks.captured.ScanTimeout, contractInfo.ScanTimeout)
	assert.Equal(t, ks.captured.ControlTimeout, contractInfo.ControlTimeout)
	assert.Equal(t, ks.captured.Format, contractInfo.Format)
	assert.Equal(t, ks.captured.OmitRawResources, contractInfo.OmitRawResources)
	assert.Equal(t, ks.captured.FailThresholdSeverity, contractInfo.FailThresholdSeverity)
	assert.Equal(t, ks.captured.ComplianceThreshold, contractInfo.ComplianceThreshold)
	assert.Equal(t, ks.captured.FailCoverageThreshold, contractInfo.FailCoverageThreshold)
	assert.Equal(t, ks.captured.FailOnDegradedConfig, contractInfo.FailOnDegradedConfig)
}
