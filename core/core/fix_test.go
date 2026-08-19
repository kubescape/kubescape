package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirm(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "yes", input: "yes\n", want: true},
		{name: "y", input: "y\n", want: true},
		{name: "no", input: "no\n", want: false},
		{name: "n", input: "n\n", want: false},
		{name: "retries past blank lines then accepts", input: "\n\n  \ny\n", want: true},
		{name: "EOF before any answer is a decline", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := confirm(strings.NewReader(tt.input))
			assert.Equal(t, tt.want, got)
		})
	}
}

// errReader always fails with a non-EOF error, simulating a persistent I/O
// failure that confirm's error branch doesn't recognize as permanent (unlike
// io.EOF). It exists to pin the maxConfirmRetries backstop without waiting
// on 100 real reads' worth of wall-clock time.
type errReader struct {
	err   error
	calls int
}

func (r *errReader) Read([]byte) (int, error) {
	r.calls++
	return 0, r.err
}

// TestConfirm_ExhaustsRetriesOnPersistentNonEOFError locks in the
// maxConfirmRetries backstop: a read error that never resolves to EOF still
// isn't treated as retryable forever, so no future non-EOF, non-recoverable
// stdin state can reintroduce #2711's unbounded loop.
func TestConfirm_ExhaustsRetriesOnPersistentNonEOFError(t *testing.T) {
	r := &errReader{err: errors.New("simulated persistent read failure")}

	got := confirm(r)

	assert.False(t, got)
	assert.Equal(t, maxConfirmRetries, r.calls,
		"confirm must give up after exactly maxConfirmRetries reads, not loop forever")
}

// TestUserConfirmed_NonInteractiveStdinDeclines guards against #2711: on
// non-interactive stdin (closed, /dev/null, a redirected file, a pipe whose
// reads fail outright, ...) no answer can ever arrive, so userConfirmed must
// decline up front instead of ever entering the retry loop.
func TestUserConfirmed_NonInteractiveStdinDeclines(t *testing.T) {
	prevIsTerminal, prevIsCygwinTerminal := isTerminal, isCygwinTerminal
	t.Cleanup(func() { isTerminal, isCygwinTerminal = prevIsTerminal, prevIsCygwinTerminal })
	isTerminal = func(uintptr) bool { return false }
	isCygwinTerminal = func(uintptr) bool { return false }

	assert.False(t, userConfirmed())
}

// TestUserConfirmed_MinttyStdinPrompts guards against a regression on the
// isTerminal fix itself: on Windows under mintty (Git Bash, MSYS2), stdin is
// a named pipe, so isatty.IsTerminal returns false even at a real
// interactive session — only IsCygwinTerminal reports true there. If
// userConfirmed only checked isTerminal, a real mintty user would be
// silently declined on every `kubescape fix` regardless of what they typed.
func TestUserConfirmed_MinttyStdinPrompts(t *testing.T) {
	prevIsTerminal, prevIsCygwinTerminal := isTerminal, isCygwinTerminal
	t.Cleanup(func() { isTerminal, isCygwinTerminal = prevIsTerminal, prevIsCygwinTerminal })
	isTerminal = func(uintptr) bool { return false }
	isCygwinTerminal = func(uintptr) bool { return true }

	originalStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { os.Stdin = originalStdin })
	os.Stdin = r

	_, err = w.WriteString("y\n")
	require.NoError(t, err)
	require.NoError(t, w.Close())

	assert.True(t, userConfirmed())
}

// TestUserConfirmed_InteractiveReadsStdin checks the (small) wiring in
// userConfirmed itself — that it reads from os.Stdin once isTerminal says
// stdin is interactive — since TestConfirm exercises the retry/parsing logic
// directly and wouldn't catch a wiring mistake here.
func TestUserConfirmed_InteractiveReadsStdin(t *testing.T) {
	prevIsTerminal := isTerminal
	t.Cleanup(func() { isTerminal = prevIsTerminal })
	isTerminal = func(uintptr) bool { return true }

	originalStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { os.Stdin = originalStdin })
	os.Stdin = r

	_, err = w.WriteString("y\n")
	require.NoError(t, err)
	require.NoError(t, w.Close())

	assert.True(t, userConfirmed())
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

// withStdin simulates an interactive user typing input at the confirmation
// prompt: it stubs isTerminal to true (userConfirmed's non-interactive
// short-circuit would otherwise decline before ever reading from the pipe)
// and feeds input through os.Stdin.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()

	prevIsTerminal := isTerminal
	isTerminal = func(uintptr) bool { return true }
	t.Cleanup(func() { isTerminal = prevIsTerminal })

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
