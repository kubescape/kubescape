package mcpserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The files under testdata/verify_remediation_contract hold what the tool and
// the scan returned before the verdict logic moved into remediationverify, byte
// for byte. They pin the response a client of verify_remediation depends on: its
// every field, its order, its message wording and its indentation, for a clean
// scan, a degraded one and ones with too little coverage to confirm a pass. The
// other tests assert verdicts; these assert that nothing about the wire form has
// moved.

const (
	contractResA = "path=111/api=apps/v1/default/Deployment/a"
	contractResB = "path=222/api=apps/v1/default/Deployment/b"
	contractResC = "path=333/api=v1/default/Pod/c"
)

func contractReport() *reporthandlingv2.PostureReport {
	passed := func(id string) resourcesresults.ResourceAssociatedControl {
		return resourcesresults.ResourceAssociatedControl{ControlID: id, Status: apis.StatusInfo{InnerStatus: apis.StatusPassed}}
	}
	failed := func(id string) resourcesresults.ResourceAssociatedControl {
		return resourcesresults.ResourceAssociatedControl{ControlID: id, Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}}
	}
	return &reporthandlingv2.PostureReport{Results: []resourcesresults.Result{
		{ResourceID: contractResA, AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			passed("C-0017"), failed("C-0001"),
			{ControlID: "C-0044", Status: apis.StatusInfo{InnerStatus: apis.StatusPassed, SubStatus: apis.SubStatusNotEvaluated}},
		}},
		{ResourceID: contractResB, AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: "C-0017", Status: apis.StatusInfo{InnerStatus: apis.StatusPassed, SubStatus: apis.SubStatusException}},
		}},
		{ResourceID: contractResC, AssociatedControls: []resourcesresults.ResourceAssociatedControl{passed("C-0017"), passed("C-0017")}},
	}}
}

// contractItems cover every verdict and every reason a client can get.
func contractItems() []verifyItem {
	return []verifyItem{
		{ResourceID: contractResA, ControlID: "C-0017"},
		{ResourceID: contractResA, ControlID: "c-0017"},
		{ResourceID: contractResA, ControlID: "C-0001"},
		{ResourceID: contractResA, ControlID: "C-0044"},
		{ResourceID: contractResA, ControlID: "C-9999"},
		{ResourceID: contractResB, ControlID: "C-0017"},
		{ResourceID: contractResC, ControlID: "C-0017"},
		{ResourceID: "path=999/api=v1/default/Pod/gone", ControlID: "C-0017"},
		{ResourceID: "", ControlID: "C-0017"},
	}
}

func contractGolden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "verify_remediation_contract", name))
	require.NoError(t, err)
	return string(raw)
}

func TestVerifyRemediationResponseContract(t *testing.T) {
	tests := []struct {
		name     string
		golden   string
		coverage *cautils.ScanCoverage
		degraded bool
	}{
		{"a clean scan", "clean.json", &cautils.ScanCoverage{EvaluatedControls: 2, TotalControls: 2, CoverageScore: 100}, false},
		{"a scan that reports itself degraded", "degraded_by_scan.json", &cautils.ScanCoverage{EvaluatedControls: 2, TotalControls: 2, CoverageScore: 100}, true},
		{"coverage that says degraded", "degraded_by_coverage.json", &cautils.ScanCoverage{Degraded: true, CoverageScore: 50, EvaluatedControls: 1, TotalControls: 2}, false},
		{"a report with no coverage", "insufficient_no_coverage.json", nil, false},
		{"a skipped manifest", "insufficient_skipped_manifest.json", &cautils.ScanCoverage{EvaluatedControls: 2, TotalControls: 2, SkippedManifests: []cautils.SkippedManifest{{Path: "a.yaml", Reason: "parse error"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reportJSON, err := remediationverify.ReportJSON(contractReport(), tt.coverage)
			require.NoError(t, err)

			got, err := verifyRemediationReport(&iacScanOutcome{ReportJSON: reportJSON, Degraded: tt.degraded}, contractItems())

			require.NoError(t, err)
			assert.Equal(t, contractGolden(t, tt.golden), string(got), "the verify_remediation response is not the one it always was")
		})
	}
}

// TestIaCScanReportEnvelopeContract: the scan's report always carried its
// scanCoverage, a clean scan's included, which is how a pass on one is told
// from a pass on a scan that says nothing about itself. Moving the envelope into
// remediationverify must not change that.
func TestIaCScanReportEnvelopeContract(t *testing.T) {
	cleanCoverage := &cautils.ScanCoverage{EvaluatedControls: 2, TotalControls: 2, CoverageScore: 100}

	got, err := remediationverify.ReportJSON(contractReport(), cleanCoverage)

	require.NoError(t, err)
	assert.Equal(t, contractGolden(t, "clean.envelope.json"), string(got))
	assert.Contains(t, string(got), `"scanCoverage":{`, "a clean scan's report carries its coverage")

	withoutCoverage, err := remediationverify.ReportJSON(contractReport(), nil)
	require.NoError(t, err)
	assert.NotContains(t, string(withoutCoverage), "scanCoverage", "no coverage is left out, not written as an empty one")
}
