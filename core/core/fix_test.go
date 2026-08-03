package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserConfirmed(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{
			input: "yes",
			want:  true,
		},
		{
			input: "y",
			want:  true,
		},
		{
			input: "no",
			want:  false,
		},
		{
			input: "n",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			originalStdin := os.Stdin
			r, w, _ := os.Pipe()
			os.Stdin = r
			defer func() {
				os.Stdin = originalStdin
			}()

			go func() {
				fmt.Fprintln(w, tt.input)
			}()

			got := userConfirmed()

			assert.Equal(t, tt.want, got)
		})
	}
}

// TestUserConfirmed_ClosedStdinReturnsFalse guards against a hang: if stdin is
// closed or non-interactive (e.g. `kubescape fix < /dev/null`), fmt.Scanln
// fails with io.EOF on every call. userConfirmed must treat that as a refusal
// instead of busy-looping forever retrying a read that can never succeed.
func TestUserConfirmed_ClosedStdinReturnsFalse(t *testing.T) {
	originalStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close()) // close the write end so reads see EOF immediately
	os.Stdin = r
	defer func() {
		os.Stdin = originalStdin
	}()

	done := make(chan bool, 1)
	go func() {
		done <- userConfirmed()
	}()

	select {
	case got := <-done:
		assert.False(t, got)
	case <-time.After(5 * time.Second):
		t.Fatal("userConfirmed did not return after stdin EOF; it is hanging/spinning")
	}
}

// --- Fix() orchestration -----------------------------------------------

// buildFixableReport writes a Deployment manifest (privileged: true) plus a
// matching PostureReport JSON into dir, with one failed control whose FixPath
// flips privileged to false. Returns the report file path.
func buildFixableReport(t *testing.T, dir string) string {
	t.Helper()

	manifestName := "deploy.yaml"
	manifestPath := filepath.Join(dir, manifestName)
	require.NoError(t, os.WriteFile(manifestPath, []byte(
		"apiVersion: apps/v1\n"+
			"kind: Deployment\n"+
			"metadata:\n"+
			"  name: demo\n"+
			"spec:\n"+
			"  template:\n"+
			"    spec:\n"+
			"      containers:\n"+
			"      - name: demo\n"+
			"        securityContext:\n"+
			"          privileged: true\n"), 0600))

	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo", "namespace": "default"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{},
			},
		},
	}
	lw := localworkload.NewLocalWorkload(obj)
	lw.SetPath(manifestName + ":0")

	resource := reporthandling.Resource{
		ResourceID: lw.GetID(),
		Object:     lw.GetObject(),
		Source:     &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: dir},
	}

	result := resourcesresults.Result{
		ResourceID: resource.ResourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0057",
				Name:      "Privileged container",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:   "rule-privileged",
						Status: apis.StatusFailed,
						Paths: []armotypes.PosturePaths{
							{FixPath: armotypes.FixPath{Path: "spec.template.spec.containers[0].securityContext.privileged", Value: "false"}},
						},
					},
				},
			},
		},
	}

	report := &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: dir},
			},
		},
		Results:   []resourcesresults.Result{result},
		Resources: []reporthandling.Resource{resource},
	}

	return writeReportFile(t, dir, report)
}

func writeReportFile(t *testing.T, dir string, report *reporthandlingv2.PostureReport) string {
	t.Helper()

	b, err := json.Marshal(report)
	require.NoError(t, err)

	reportPath := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(reportPath, b, 0600))
	return reportPath
}

func manifestContent(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "deploy.yaml"))
	require.NoError(t, err)
	return string(b)
}

func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	originalStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = originalStdin }()

	go func() {
		fmt.Fprintln(w, input)
	}()

	fn()
}

func TestFix_InvalidReportFile(t *testing.T) {
	dir := t.TempDir()
	ks := &Kubescape{Ctx: context.Background()}

	err := ks.Fix(&metav1.FixInfo{ReportFile: filepath.Join(dir, "does-not-exist.json")})

	require.Error(t, err)
}

func TestFix_NoResourcesToFix(t *testing.T) {
	dir := t.TempDir()
	report := &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: dir},
			},
		},
	}
	reportPath := writeReportFile(t, dir, report)

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true})

	assert.NoError(t, err)
}

func TestFix_DryRunDoesNotModifyFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, DryRun: true})

	assert.NoError(t, err)
	assert.Equal(t, before, manifestContent(t, dir), "dry-run must not modify the file on disk")
}

func TestFix_DeclineViaStdinDoesNotModifyFile(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)

	ks := &Kubescape{Ctx: context.Background()}
	withStdin(t, "n", func() {
		err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath})
		assert.NoError(t, err)
	})

	assert.Equal(t, before, manifestContent(t, dir), "declining the confirmation prompt must not modify the file")
}

func TestFix_NoConfirmAppliesChanges(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true})

	assert.NoError(t, err)
	assert.Contains(t, manifestContent(t, dir), "privileged: false",
		"NoConfirm must apply the planned fix to the file on disk")
}

func TestFix_ReturnsErrorWhenApplyFails(t *testing.T) {
	if os.Geteuid() == 0 {
		// A read-only file mode does not stop a process with CAP_DAC_OVERRIDE
		// (e.g. root) from writing to it, so this chmod-based failure
		// injection cannot be enforced when the test runs as root. Be honest
		// about that instead of asserting on an outcome the setup can't
		// actually guarantee.
		t.Skip("chmod-based write failure is not enforced for root")
	}

	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	// Make the target file unwritable so ApplyChanges fails for it.
	require.NoError(t, os.Chmod(filepath.Join(dir, "deploy.yaml"), 0444))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "deploy.yaml"), 0644) })

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true})

	assert.Error(t, err)
}
