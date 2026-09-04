package scan

import (
	"bytes"
	"context"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/mocks"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GitHub #3716: Cobra prints UsageString on RunE errors unless SilenceUsage is set
// after a valid invocation. These tests must not preset cmd.SilenceUsage.

type usageTestPrinter struct{}

func (usageTestPrinter) ActionPrint(context.Context, *cautils.OPASessionObj, []cautils.ImageScanData) error {
	return nil
}
func (usageTestPrinter) PrintNextSteps()                         {}
func (usageTestPrinter) Score(float32)                           {}
func (usageTestPrinter) SetWriter(context.Context, string) error { return nil }

type usageThresholdKubescape struct {
	mocks.MockIKubescape
}

func (m *usageThresholdKubescape) ScanContext(_ context.Context, _ *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	results := resultshandling.NewResultsHandler(nil, nil, usageTestPrinter{})
	data := cautils.NewOPASessionObjMock()
	data.Report.SummaryDetails.ResourcesSeverityCounters = reportsummary.SeverityCounters{LowSeverityCounter: 1}
	results.SetData(data)
	return results, nil
}

func (m *usageThresholdKubescape) ScanImageContext(_ context.Context, _ *metav1.ImageScanInfo, _ *cautils.ScanInfo) (bool, error) {
	return true, nil
}

func newKubescapeRootWithScan(ks meta.IKubescape) (*cobra.Command, *bytes.Buffer) {
	root := &cobra.Command{Use: "kubescape"}
	root.AddCommand(GetScanCommand(ks))
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	return root, &buf
}

func TestScanSeverityThresholdFailureDoesNotPrintUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "security view scan", args: []string{"scan", ".", "--severity-threshold", "low"}},
		{name: "framework", args: []string{"scan", "framework", "nsa", "--severity-threshold", "low"}},
		{name: "control", args: []string{"scan", "control", "C-0058", "--severity-threshold", "low"}},
		{name: "workload", args: []string{"scan", "workload", "Deployment/nginx", "--severity-threshold", "low"}},
		{name: "image", args: []string{"scan", "image", "nginx", "--severity-threshold", "high"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &usageThresholdKubescape{}
			root, buf := newKubescapeRootWithScan(ks)
			root.SetArgs(tt.args)

			err := root.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "severity threshold")
			assert.NotContains(t, buf.String(), "Usage:", "threshold failure must not dump command usage")
		})
	}
}

func TestScanValidationErrorStillPrintsUsage(t *testing.T) {
	ks := &usageThresholdKubescape{}
	root, buf := newKubescapeRootWithScan(ks)
	root.SetArgs([]string{"scan", "--format-version=v3"})

	err := root.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format-version")
	assert.Contains(t, buf.String(), "Usage:")
}

func TestScanFleetValidationStillPrintsUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "security view", args: []string{"scan", "--kube-contexts=ctx-a,ctx-b"}},
		{name: "framework", args: []string{"scan", "framework", "nsa", "--kube-contexts=ctx-a,ctx-b"}},
		{name: "control", args: []string{"scan", "control", "C-0058", "--kube-contexts=ctx-a,ctx-b"}},
		{name: "workload", args: []string{"scan", "workload", "Deployment/nginx", "--kube-contexts=ctx-a,ctx-b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &usageThresholdKubescape{}
			root, buf := newKubescapeRootWithScan(ks)
			root.SetArgs(tt.args)

			err := root.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "--kube-contexts requires --output")
			assert.Contains(t, buf.String(), "Usage:", "invalid fleet CLI input must still print usage")
		})
	}
}
