package fleet

import (
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// controlSpec is a compact description of one control's outcome, so a test can
// say what it means ("C-0016 failed on two resources") instead of assembling a
// reportsummary.ControlSummary literal every time.
type controlSpec struct {
	id          string
	name        string
	status      apis.ScanningStatus
	subStatus   apis.ScanningSubStatus
	failed      int
	scoreFactor float32
	// complianceScore is a pointer because ControlSummary treats an absent
	// score as -1 rather than 0, and some tests need to cover that.
	complianceScore *float32
	// legacyStatusOnly leaves StatusInfo empty and records the verdict only in
	// the deprecated top-level Status field, which is the shape a report
	// written by an older Kubescape arrives in.
	legacyStatusOnly bool
}

// passed, failed, skipped and notEvaluated cover the four outcomes the matrix
// distinguishes. scoreFactor 8 maps to "High" via apis.ControlSeverityToString.
//
// passed is a control the cluster evaluated and satisfied.
func passed(id, name string) controlSpec {
	return controlSpec{id: id, name: name, status: apis.StatusPassed, scoreFactor: 8, complianceScore: score(100)}
}

// failed is a control the cluster evaluated and did not satisfy, on
// failedResources resources.
func failed(id, name string, failedResources int) controlSpec {
	return controlSpec{
		id: id, name: name, status: apis.StatusFailed,
		failed: failedResources, scoreFactor: 8, complianceScore: score(0),
	}
}

// skipped is a control deliberately not applied, which upstream records as
// skipped with an irrelevant sub-status.
func skipped(id, name string) controlSpec {
	return controlSpec{
		id: id, name: name, status: apis.StatusSkipped,
		subStatus: apis.SubStatusIrrelevant, scoreFactor: 8, complianceScore: score(100),
	}
}

// notEvaluated mirrors what OPAProcessor.markControlsSkipped writes when a
// control could not be evaluated: skipped, with a notEvaluated sub-status.
func notEvaluated(id, name string) controlSpec {
	return controlSpec{
		id: id, name: name, status: apis.StatusSkipped,
		subStatus: apis.SubStatusNotEvaluated, scoreFactor: 8,
	}
}

// legacyStatus mirrors a report written before StatusInfo existed: the verdict
// lives only in the deprecated top-level Status field, and ControlSummary's
// GetStatus backfills StatusInfo from it on the first read.
func legacyStatus(id, name string, status apis.ScanningStatus) controlSpec {
	return controlSpec{
		id: id, name: name, status: status,
		scoreFactor: 8, complianceScore: score(0), legacyStatusOnly: true,
	}
}

// score returns a pointer to v, for the fields that distinguish an absent
// measurement from a zero one.
func score(v float32) *float32 {
	return &v
}

// newPostureReport builds the minimum report the fleet aggregation reads: the
// summary details and their control summaries. Nothing here fills in resources
// or results, because the matrix never looks at them.
func newPostureReport(clusterName string, specs ...controlSpec) *reporthandlingv2.PostureReport {
	controls := make(reportsummary.ControlSummaries, len(specs))
	for _, spec := range specs {
		summary := reportsummary.ControlSummary{
			ControlID: spec.id,
			Name:      spec.name,
			StatusInfo: apis.StatusInfo{
				InnerStatus: spec.status,
				SubStatus:   spec.subStatus,
			},
			Status:          spec.status,
			ScoreFactor:     spec.scoreFactor,
			ComplianceScore: spec.complianceScore,
			StatusCounters:  reportsummary.StatusCounters{FailedResources: spec.failed},
		}
		if spec.legacyStatusOnly {
			summary.StatusInfo = apis.StatusInfo{}
		}
		controls[spec.id] = summary
	}

	return &reporthandlingv2.PostureReport{
		ClusterName: clusterName,
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: controls,
		},
	}
}

// scannedCluster is a cluster whose scan completed.
func scannedCluster(name string, specs ...controlSpec) ClusterResult {
	return ClusterResult{
		ClusterID:       name,
		Context:         name,
		Status:          ClusterScanned,
		ComplianceScore: score(100),
		Coverage:        &cautils.ScanCoverage{CoverageScore: 100},
		Duration:        "1m0s",
		Report:          newPostureReport(name, specs...),
	}
}

// unreachableCluster is a cluster the scan could not reach. Report stays nil,
// which is what every consumer has to cope with.
func unreachableCluster(name, reason string) ClusterResult {
	return ClusterResult{
		ClusterID: name,
		Context:   name,
		Status:    ClusterUnreachable,
		Error:     reason,
	}
}

// requireCell fails the test unless the row has a cell for cluster with the
// expected status.
func requireCell(t *testing.T, row FleetControlRow, cluster string, want CellStatus) {
	t.Helper()

	cell, ok := row.ByCluster[cluster]
	require.True(t, ok, "control %s: expected a cell for cluster %q", row.ControlID, cluster)
	assert.Equal(t, want, cell.Status, "control %s on cluster %s", row.ControlID, cluster)
}
