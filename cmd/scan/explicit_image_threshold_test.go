package scan

import (
	"context"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type explicitThresholdPrinter struct{}

func (explicitThresholdPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return nil
}
func (explicitThresholdPrinter) PrintNextSteps()                         {}
func (explicitThresholdPrinter) Score(float32)                           {}
func (explicitThresholdPrinter) SetWriter(context.Context, string) error { return nil }

type explicitThresholdProvider struct {
	severity string
}

func (p explicitThresholdProvider) VulnerabilityMetadata(vulnerability.Reference) (*vulnerability.Metadata, error) {
	return &vulnerability.Metadata{Severity: p.severity}, nil
}
func (explicitThresholdProvider) PackageSearchNames(grypepkg.Package) []string { return nil }
func (explicitThresholdProvider) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}
func (explicitThresholdProvider) Close() error { return nil }

type explicitThresholdKubescape struct {
	mocks.MockIKubescape
	captured *cautils.ScanInfo
}

func (m *explicitThresholdKubescape) Scan(scanInfo *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	captured := *scanInfo
	m.captured = &captured

	matches := match.NewMatches()
	matches.Add(match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-TEST"},
		},
	})

	results := resultshandling.NewResultsHandler(nil, nil, explicitThresholdPrinter{})
	results.SetData(cautils.NewOPASessionObjMock())
	results.ImageScanData = []cautils.ImageScanData{
		{
			Matches:               matches,
			VulnerabilityProvider: explicitThresholdProvider{severity: "Critical"},
		},
	}
	return results, nil
}

func TestExplicitScanCommandsEnforceImageSeverityThreshold(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "framework", args: []string{"framework", "nsa", "--scan-images", "--severity-threshold", "high"}},
		{name: "control", args: []string{"control", "C-0058", "--scan-images", "--severity-threshold", "high"}},
		{name: "workload", args: []string{"workload", "Deployment/nginx", "--scan-images", "--severity-threshold", "high"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &explicitThresholdKubescape{}
			cmd := GetScanCommand(ks)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			require.EqualError(t, err, "image scan result exceeds severity threshold: high")
			require.NotNil(t, ks.captured)
			assert.True(t, ks.captured.ScanImages)
			assert.Equal(t, "high", ks.captured.FailThresholdSeverity)
		})
	}
}

func TestExplicitFrameworkAndControlIgnoreImageDataWithoutScanImages(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "framework", args: []string{"framework", "nsa", "--severity-threshold", "high"}},
		{name: "control", args: []string{"control", "C-0058", "--severity-threshold", "high"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &explicitThresholdKubescape{}
			cmd := GetScanCommand(ks)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs(tt.args)

			require.NoError(t, cmd.Execute())
			require.NotNil(t, ks.captured)
			assert.False(t, ks.captured.ScanImages)
		})
	}
}
