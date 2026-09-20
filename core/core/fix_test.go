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
	"github.com/kubescape/go-logger"
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
	return buildFixableReportAt(t, dir, "deploy.yaml")
}

// buildFixableReportAt is buildFixableReport with the manifest at manifestName,
// a slash-separated path relative to dir, so a test can place it in a nested
// directory.
func buildFixableReportAt(t *testing.T, dir, manifestName string) string {
	t.Helper()

	manifestPath := filepath.Join(dir, filepath.FromSlash(manifestName))
	require.NoError(t, os.MkdirAll(filepath.Dir(manifestPath), 0750))
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

// captureLoggerOutput redirects the package logger to a file for the duration
// of the test and returns a reader for whatever was written to it.
func captureLoggerOutput(t *testing.T) func() string {
	t.Helper()

	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	prev := logger.L().GetWriter()
	logger.L().SetWriter(f)
	t.Cleanup(func() { logger.L().SetWriter(prev) })

	return func() string {
		require.NoError(t, f.Sync())
		b, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		return string(b)
	}
}

// fileContent reads one file of a test's tree.
func fileContent(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

// TestFix_OutputDirWritesFixedCopiesAndLeavesTheOriginals covers #3847. With
// --output-dir a file-based report is fixed into the directory rather than in
// place: the copy keeps the manifest's path relative to the scanned directory,
// nested directories included, and the manifest the scan read is not touched.
//
// NoConfirm is left false on a non-interactive stdin, which declines the
// confirmation prompt. The copy being written anyway pins that this path never
// reaches the prompt: it guards in-place edits, and none are made.
func TestFix_OutputDirWritesFixedCopiesAndLeavesTheOriginals(t *testing.T) {
	prevIsTerminal, prevIsCygwinTerminal := isTerminal, isCygwinTerminal
	t.Cleanup(func() { isTerminal, isCygwinTerminal = prevIsTerminal, prevIsCygwinTerminal })
	isTerminal = func(uintptr) bool { return false }
	isCygwinTerminal = func(uintptr) bool { return false }

	dir := t.TempDir()
	reportPath := buildFixableReportAt(t, dir, "k8s/prod/deploy.yaml")
	original := filepath.Join(dir, "k8s", "prod", "deploy.yaml")
	before := fileContent(t, original)
	outputDir := filepath.Join(t.TempDir(), "fixed")

	readLog := captureLoggerOutput(t)

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: outputDir}))

	fixedCopy := filepath.Join(outputDir, "k8s", "prod", "deploy.yaml")
	require.FileExists(t, fixedCopy, "the copy must mirror the manifest's path under the scanned directory")
	assert.Contains(t, fileContent(t, fixedCopy), "privileged: false", "the copy must carry the fix")
	assert.Equal(t, before, fileContent(t, original), "the scanned manifest must not be modified")
	assert.Contains(t, readLog(), "The original files were not modified",
		"the summary must say the originals are untouched, or the copies read as an in-place fix that also left files behind")
}

// TestFix_OutputDirRefusesANonEmptyDirectory pins the guard the cluster path
// already applies: a stray --output-dir must not scatter manifests over a
// directory that has content, unless --no-confirm says that is intended.
func TestFix_OutputDirRefusesANonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	outputDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outputDir, "unrelated.txt"), []byte("keep me"), 0600))

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: outputDir})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not empty")
	assert.NoFileExists(t, filepath.Join(outputDir, "deploy.yaml"))
	assert.Equal(t, before, manifestContent(t, dir))

	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: outputDir, NoConfirm: true}),
		"--no-confirm must allow writing into a directory that has content")
	assert.Contains(t, fileContent(t, filepath.Join(outputDir, "deploy.yaml")), "privileged: false")
	assert.Equal(t, "keep me", fileContent(t, filepath.Join(outputDir, "unrelated.txt")))
}

// TestFix_OutputDirRefusesTheScannedDirectory: an output directory that is the
// scanned one maps every copy onto its own source, which is an in-place fix
// under another name — the one outcome the flag exists to avoid. It has to be
// refused even with --no-confirm, and for that reason rather than as "not
// empty; pass --no-confirm", advice that would lead straight to the overwrite.
func TestFix_OutputDirRefusesTheScannedDirectory(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)

	ks := &Kubescape{Ctx: context.Background()}
	for _, noConfirm := range []bool{false, true} {
		err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: dir, NoConfirm: noConfirm})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "would overwrite")
		assert.NotContains(t, err.Error(), "--no-confirm")
		assert.Equal(t, before, manifestContent(t, dir), "the scanned manifest must not be modified")
	}
}

// TestFix_OutputDirDryRunWritesNothing: --dry-run promises no changes anywhere,
// and creating the output directory is a change.
func TestFix_OutputDirDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	outputDir := filepath.Join(t.TempDir(), "fixed")

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: outputDir, DryRun: true}))

	assert.NoDirExists(t, outputDir)
	assert.Equal(t, before, manifestContent(t, dir))
}
