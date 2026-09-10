package printer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/require"
)

// Run each size/format in a fresh process with -benchtime=1x for RSS comparisons.
// KS_PRINTER_SAMPLE_HEAP enables sampling outside normal allocation benchmarks.
// KS_PRINTER_CAPTURE_DIR optionally keeps a representative output for comparison.
func BenchmarkConfigurationOutput(b *testing.B) {
	for _, format := range []string{"fixture", "json", "json-omit", "json-labels-audit", "sarif"} {
		for _, size := range []int{10, 1000, 10000, 50000} {
			b.Run(fmt.Sprintf("%s/%d", format, size), func(b *testing.B) {
				session := configurationOutputFixture(b, size)
				session.OmitRawResources = format == "json-omit"
				if format == "json-labels-audit" {
					session.LabelsToCopy = []string{"app"}
					session.ExceptionAudit = &cautils.ExceptionAudit{Generated: true}
					for i := 0; i < size; i++ {
						session.ExceptionAudit.Items = append(session.ExceptionAudit.Items, cautils.ExceptionAuditItem{
							Name: fmt.Sprintf("exception-%06d", i), Status: "matched", MatchCount: 1,
							MatchedResources: []cautils.ExceptionAuditMatch{{ResourceID: fmt.Sprintf("resource-%06d", i), ControlID: "C-0000"}},
						})
					}
				}
				var f *os.File
				var err error
				if dir := os.Getenv("KS_PRINTER_CAPTURE_DIR"); dir != "" {
					root, openErr := os.OpenRoot(dir)
					require.NoError(b, openErr)
					defer root.Close()
					f, err = root.Create(fmt.Sprintf("%s-%d.json", format, size))
				} else {
					f, err = os.Create(os.DevNull)
				}
				require.NoError(b, err)
				defer f.Close()
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				stop, done := make(chan struct{}), make(chan uint64)
				sampling := os.Getenv("KS_PRINTER_SAMPLE_HEAP") != ""
				if sampling {
					go func() {
						peak := before.HeapAlloc
						ticker := time.NewTicker(time.Millisecond)
						defer ticker.Stop()
						for {
							var m runtime.MemStats
							runtime.ReadMemStats(&m)
							peak = max(peak, m.HeapAlloc)
							select {
							case <-stop:
								done <- peak
								return
							case <-ticker.C:
							}
						}
					}()
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					switch format {
					case "fixture":
					case "sarif":
						err = (&SARIFPrinter{writer: f}).ActionPrint(context.Background(), session, nil)
					default:
						err = (&JsonPrinter{writer: f}).ActionPrint(context.Background(), session, nil)
					}
					if err != nil {
						break
					}
				}
				b.StopTimer()
				if sampling {
					close(stop)
					b.ReportMetric(float64(<-done), "peak-heap-B")
					b.ReportMetric(float64(before.HeapAlloc), "input-heap-B")
				}
				runtime.KeepAlive(session)
				require.NoError(b, err)
			})
		}
	}
}

func configurationOutputFixture(t testing.TB, size int) *cautils.OPASessionObj {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\nspec:\n  hostNetwork: true\n"), 0600))
	session := cautils.NewOPASessionObjMock()
	session.Report.ReportGenerationTime = time.Date(2026, 1, 2, 3, 4, 5, 123, time.UTC)
	session.Report.ClusterName = "benchmark"
	session.Report.ReportID = "benchmark-report"
	session.Report.SummaryDetails.Controls = reportsummary.ControlSummaries{}
	session.ResourceSource = map[string]reporthandling.Source{}
	for c := 0; c < 10; c++ {
		id := fmt.Sprintf("C-%04d", c)
		session.Report.SummaryDetails.Controls[id] = reportsummary.ControlSummary{
			ControlID: id, Name: "Example control", Description: "Example description", Remediation: "Example remediation", ScoreFactor: 8,
		}
	}
	for i := 0; i < size; i++ {
		id := fmt.Sprintf("resource-%06d", i)
		obj := workloadinterface.NewWorkloadObj(map[string]interface{}{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]interface{}{"name": id, "namespace": "default", "labels": map[string]interface{}{"app": "example"}},
			"spec":     map[string]interface{}{"hostNetwork": true, "description": strings.Repeat("x", 4096)},
		})
		session.AllResources[id] = obj
		session.ResourceSource[id] = reporthandling.Source{RelativePath: "pod.yaml", Path: dir}
		result := resourcesresults.Result{ResourceID: id}
		for c := 0; c < 10; c++ {
			result.AssociatedControls = append(result.AssociatedControls, resourcesresults.ResourceAssociatedControl{
				ControlID: fmt.Sprintf("C-%04d", c), Status: apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
					Name: "example-rule", Status: apis.StatusFailed,
					Paths: []armotypes.PosturePaths{{FailedPath: "spec.hostNetwork", ReviewPath: "spec.hostNetwork"}},
				}},
			})
		}
		session.ResourcesResult[id] = result
	}
	return session
}
