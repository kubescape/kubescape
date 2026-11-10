package scan

import (
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dryRunRecordingPrinter records whether the results stage ran at all.
type dryRunRecordingPrinter struct {
	printed bool
}

func (p *dryRunRecordingPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	p.printed = true
	return nil
}
func (*dryRunRecordingPrinter) PrintNextSteps()                         {}
func (*dryRunRecordingPrinter) Score(float32)                           {}
func (*dryRunRecordingPrinter) SetWriter(context.Context, string) error { return nil }

// dryRunKubescape returns what core.ScanContext returns for a dry run whose
// preflight found no denied resource: a handler around the policies only,
// with no resources collected and no controls evaluated.
type dryRunKubescape struct {
	mocks.MockIKubescape
	printer *dryRunRecordingPrinter
}

func (m *dryRunKubescape) Context() context.Context {
	return context.Background()
}

func (m *dryRunKubescape) ScanContext(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	results := resultshandling.NewResultsHandler(nil, nil, m.printer)
	results.SetData(cautils.NewOPASessionObjMock())
	return results, nil
}

// A passing --dry-run used to fall through into HandleResults and the
// threshold checks, as if the scan had run: it printed and wrote an empty
// posture report ("Kubescape did not scan any resources"), would submit that
// report with --submit, and failed --compliance-threshold against the score
// of an evaluation that never happened.
func TestDryRunSkipsResultsAndThresholds(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "scan", args: []string{"scan", "--dry-run", "--fail-coverage-below", "100"}},
		{name: "framework", args: []string{"scan", "framework", "nsa", "--dry-run", "--compliance-threshold", "100"}},
		{name: "control", args: []string{"scan", "control", "C-0058", "--dry-run", "--compliance-threshold", "100"}},
		{name: "workload", args: []string{"scan", "workload", "Deployment/nginx", "--dry-run", "--compliance-threshold", "100"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &dryRunKubescape{printer: &dryRunRecordingPrinter{}}
			root := &cobra.Command{Use: "kubescape", SilenceErrors: true, SilenceUsage: true}
			root.AddCommand(GetScanCommand(ks))
			root.SetArgs(tt.args)

			require.NoError(t, root.Execute(), "a dry run whose preflight passed must not fail a threshold")
			assert.False(t, ks.printer.printed, "a dry run has no results to print")
		})
	}
}
