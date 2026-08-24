package resultshandling

import (
	"fmt"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/telemetry"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

func benchmarkSession(resources, controls int) *cautils.OPASessionObj {
	session := &cautils.OPASessionObj{
		Report:       &reporthandlingv2.PostureReport{},
		AllResources: make(map[string]workloadinterface.IMetadata, resources),
	}

	kinds := []string{"Deployment", "Pod", "Service", "ConfigMap", "Role"}
	for i := range resources {
		session.AllResources[fmt.Sprintf("id-%d", i)] = workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "apps/v1",
			"kind":       kinds[i%len(kinds)],
			"metadata":   map[string]any{"name": fmt.Sprintf("resource-%d", i), "namespace": "default"},
		})
	}

	summaries := make(map[string]reportsummary.ControlSummary, controls)
	for i := range controls {
		id := fmt.Sprintf("C-%04d", i)
		summaries[id] = reportsummary.ControlSummary{ControlID: id, ScoreFactor: float32(i%10 + 1)}
	}
	session.Report.SummaryDetails.Controls = summaries

	return session
}

// BenchmarkBuildScanOutcome measures the work HandleResults must skip when no
// collector is configured: it walks every resource and control in the report.
func BenchmarkBuildScanOutcome(b *testing.B) {
	session := benchmarkSession(10000, 130)
	scanInfo := &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster}

	b.ReportAllocs()
	for b.Loop() {
		_ = buildScanOutcome(session, nil, scanInfo)
	}
}

// BenchmarkRecordScanDisabled is the same call site as it behaves on a scan
// without --otel-endpoint, which is every scan by default.
func BenchmarkRecordScanDisabled(b *testing.B) {
	session := benchmarkSession(10000, 130)
	scanInfo := &cautils.ScanInfo{ScanType: cautils.ScanTypeCluster}

	if telemetry.Active() {
		b.Fatal("telemetry must be inactive for this benchmark")
	}

	b.ReportAllocs()
	for b.Loop() {
		if !telemetry.Active() {
			continue
		}
		telemetry.RecordScan(b.Context(), buildScanOutcome(session, nil, scanInfo))
	}
}
