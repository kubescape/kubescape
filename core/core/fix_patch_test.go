package core

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubNonInteractiveStdin makes the confirmation prompt decline. A patch export
// that still goes through shows it never reaches the prompt, which guards
// in-place edits and this path makes none.
func stubNonInteractiveStdin(t *testing.T) {
	t.Helper()
	prevIsTerminal, prevIsCygwinTerminal := isTerminal, isCygwinTerminal
	t.Cleanup(func() { isTerminal, isCygwinTerminal = prevIsTerminal, prevIsCygwinTerminal })
	isTerminal = func(uintptr) bool { return false }
	isCygwinTerminal = func(uintptr) bool { return false }
}

// gitApplyIn applies patchPath with git inside dir.
func gitApplyIn(t *testing.T, dir, patchPath string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	cmd := exec.Command("git", "apply", "--whitespace=nowarn", patchPath)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git apply refused the patch: %s", out)
}

// copyFiles copies the named files, paths relative to src, to a new directory,
// so a patch can be applied to a clean copy of the originals.
func copyFiles(t *testing.T, src string, names ...string) string {
	t.Helper()
	dst := t.TempDir()
	for _, name := range names {
		target := filepath.Join(dst, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
		require.NoError(t, os.WriteFile(target, []byte(fileContent(t, filepath.Join(src, filepath.FromSlash(name)))), 0o600))
	}
	return dst
}

func TestFix_OutputPatchExportsAPatchAndLeavesTheOriginals(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReportAt(t, dir, "k8s/prod/deploy.yaml")
	original := filepath.Join(dir, "k8s", "prod", "deploy.yaml")
	before := fileContent(t, original)
	clean := copyFiles(t, dir, "k8s/prod/deploy.yaml")
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.Equal(t, before, fileContent(t, original), "exporting a patch must not modify the manifest")
	patch := fileContent(t, patchPath)
	assert.True(t, strings.HasPrefix(patch, "diff --git a/k8s/prod/deploy.yaml b/k8s/prod/deploy.yaml\n"), patch)
	assert.Contains(t, patch, "-          privileged: true\n+          privileged: false\n")
	assert.NotContains(t, patch, dir, "the patch must carry relative paths, not where the scan ran")

	log := readLog()
	assert.Contains(t, log, "Wrote a patch changing 1 file(s) and 1 resource(s)")
	assert.Contains(t, log, "The original files were not modified")
	assert.Contains(t, log, "git apply")

	gitApplyIn(t, clean, patchPath)
	assert.Contains(t, fileContent(t, filepath.Join(clean, "k8s", "prod", "deploy.yaml")), "privileged: false",
		"applying the patch to a clean copy must give the fixed manifest")
	assert.Equal(t, before, fileContent(t, original), "the original is still untouched after the copy was patched")
}

func TestFix_OutputPatchEqualsTheFixedCopy(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	clean := copyFiles(t, dir, "deploy.yaml")
	outputDir := filepath.Join(t.TempDir(), "fixed")
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputDir: outputDir}))
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	gitApplyIn(t, clean, patchPath)
	fixedOutput := strings.ReplaceAll(fileContent(t, filepath.Join(outputDir, "deploy.yaml")), "\r\n", "\n")
	patchedCopy := strings.ReplaceAll(fileContent(t, filepath.Join(clean, "deploy.yaml")), "\r\n", "\n")
	assert.Equal(t, fixedOutput, patchedCopy,
		"the patch and --output-dir are the same fix")
}

// TestFix_OutputPatchPartialRemediation: one control on the resource has a fix
// and one does not. The patch carries the first, and the second is reported as
// still needing work, so the patch is not read as the whole answer.
func TestFix_OutputPatchPartialRemediation(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)

	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	report.Results[0].AssociatedControls = append(report.Results[0].AssociatedControls, resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0041",
		Name:      "HostNetwork access",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name:   "rule-host-network",
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{{FailedPath: "spec.template.spec.hostNetwork"}},
		}},
	})
	reportPath = writeReportFile(t, dir, &report)
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.Contains(t, fileContent(t, patchPath), "+          privileged: false")
	log := readLog()
	assert.Contains(t, log, "covering 1 of 2 flagged control instances", "a patch that fixes one of two findings must not read as a full fix")
	assert.Contains(t, log, "C-0041", "the control that needs manual work must be listed")
	assert.NotContains(t, log, "auto-fixed", "a patch is a proposal, not an applied fix")
}

// withExtraControls adds failed controls to the one resource of a report built
// by buildFixableReport and writes the report back.
func withExtraControls(t *testing.T, dir, reportPath string, extra ...resourcesresults.ResourceAssociatedControl) string {
	t.Helper()
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	report.Results[0].AssociatedControls = append(report.Results[0].AssociatedControls, extra...)
	return writeReportFile(t, dir, &report)
}

func fixableControl(id, name, path, value string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: id,
		Name:      name,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name:   "rule-" + id,
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{{FixPath: armotypes.FixPath{Path: path, Value: value}}},
		}},
	}
}

func manualControl(id, name, failedPath string) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{
		ControlID: id,
		Name:      name,
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name:   "rule-" + id,
			Status: apis.StatusFailed,
			Paths:  []armotypes.PosturePaths{{FailedPath: failedPath}},
		}},
	}
}

// TestFix_OutputPatchCountsMultipleFindingsOnOneResource: two controls fixed on
// one resource are two flagged control instances but one resource, and the
// summary must say so rather than count the resource twice.
func TestFix_OutputPatchCountsMultipleFindingsOnOneResource(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := withExtraControls(t, dir, buildFixableReport(t, dir),
		fixableControl("C-0013", "Non-root containers", "spec.template.spec.hostNetwork", "false"))
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)

	require.NoError(t, (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	patch := fileContent(t, patchPath)
	assert.Contains(t, patch, "+          privileged: false")
	assert.Contains(t, patch, "hostNetwork: false", "both fixes are in the patch")
	log := readLog()
	assert.Contains(t, log, "changing 1 file(s) and 1 resource(s)")
	assert.Contains(t, log, "covering 2 of 2 flagged control instances")
}

// TestFix_OutputPatchManualOnlyFindingsWriteNoPatch: a report whose findings
// all need manual work yields nothing to export. The run says so, lists the
// controls, and does not claim a patch.
func TestFix_OutputPatchManualOnlyFindingsWriteNoPatch(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	report.Results[0].AssociatedControls = []resourcesresults.ResourceAssociatedControl{
		manualControl("C-0041", "HostNetwork access", "spec.template.spec.hostNetwork"),
		manualControl("C-0044", "Container hostPort", "spec.template.spec.containers[0].ports[0].hostPort"),
	}
	reportPath = writeReportFile(t, dir, &report)
	before := manifestContent(t, dir)
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)

	require.NoError(t, (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.NoFileExists(t, patchPath)
	assert.Equal(t, before, manifestContent(t, dir))
	log := readLog()
	assert.NotContains(t, log, "Wrote a patch", "no patch was made")
	assert.Contains(t, log, "C-0041")
	assert.Contains(t, log, "C-0044", "every control that needs manual work is listed")
}

func TestFix_OutputPatchWritesNothingWhenNoManifestWouldChange(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	manifest := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(strings.Replace(fileContent(t, manifest), "privileged: true", "privileged: false", 1)), 0o600))
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.NoFileExists(t, patchPath, "an empty patch must not be written")
	assert.Contains(t, readLog(), "No manifest would change, so no patch was written")
}

// TestFix_OutputPatchKeepsAnExistingFileWhenNothingWouldChange: an export that
// has nothing to say must not wipe out an earlier patch.
func TestFix_OutputPatchKeepsAnExistingFileWhenNothingWouldChange(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	manifest := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(manifest, []byte(strings.Replace(fileContent(t, manifest), "privileged: true", "privileged: false", 1)), 0o600))
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	require.NoError(t, os.WriteFile(patchPath, []byte("an earlier patch\n"), 0o600))

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath, NoConfirm: true}))

	assert.Equal(t, "an earlier patch\n", fileContent(t, patchPath))
}

func TestFix_OutputPatchWritesNothingWhenThereIsNothingToFix(t *testing.T) {
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
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.NoFileExists(t, patchPath)
}

func TestFix_OutputPatchExistingFile(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	require.NoError(t, os.WriteFile(patchPath, []byte("an earlier patch\n"), 0o600))
	ks := &Kubescape{Ctx: context.Background()}

	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), "--no-confirm")
	assert.Equal(t, "an earlier patch\n", fileContent(t, patchPath), "the earlier patch must survive a refused export")

	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath, NoConfirm: true}))
	assert.Contains(t, fileContent(t, patchPath), "diff --git", "--no-confirm replaces it")
}

// TestFix_OutputPatchRefusesToOverwriteAnInput: the patch path being a scanned
// manifest or the report would destroy what the export exists to protect, and
// --no-confirm must not be able to allow it.
func TestFix_OutputPatchRefusesToOverwriteAnInput(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	manifest := filepath.Join(dir, "deploy.yaml")
	manifestBefore, reportBefore := fileContent(t, manifest), fileContent(t, reportPath)
	ks := &Kubescape{Ctx: context.Background()}

	for name, target := range map[string]string{"the scanned manifest": manifest, "the report": reportPath} {
		t.Run(name, func(t *testing.T) {
			err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: target, NoConfirm: true})

			require.Error(t, err)
			assert.Equal(t, manifestBefore, fileContent(t, manifest))
			assert.Equal(t, reportBefore, fileContent(t, reportPath))
		})
	}
}

func TestFix_OutputPatchInvalidDestinationLeavesNothing(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	parent := t.TempDir()
	ks := &Kubescape{Ctx: context.Background()}

	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: filepath.Join(parent, "missing", "remediation.patch")})

	require.Error(t, err)
	entries, readErr := os.ReadDir(parent)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
	assert.Equal(t, before, manifestContent(t, dir))
}

// TestFix_OutputPatchInvalidDestinationIsRefusedBeforeKustomizeWrites: a report
// with a fixable manifest and a Helm resource, exported with both
// --output-kustomize and --output-patch, must refuse an unusable patch path
// before the Kustomize directory is written, not after.
func TestFix_OutputPatchInvalidDestinationIsRefusedBeforeKustomizeWrites(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	helmReport := readReportFile(t, buildFixableHelmReport(t, dir))
	manifestReport := readReportFile(t, buildFixableReport(t, dir))
	manifestReport.Resources = append(manifestReport.Resources, helmReport.Resources...)
	manifestReport.Results = append(manifestReport.Results, helmReport.Results...)
	reportPath := writeReportFile(t, dir, manifestReport)
	before := manifestContent(t, dir)
	kustDir := filepath.Join(t.TempDir(), "kust-output")
	patchPath := filepath.Join(t.TempDir(), "missing", "remediation.patch")

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{
		ReportFile:       reportPath,
		KustomizeDir:     kustDir,
		OutputPatch:      patchPath,
		NoConfirm:        true,
		HelmValueOptions: cautils.HelmValueOptions{ValueFiles: []string{filepath.Join(dir, "values.yaml")}},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot write the patch")
	assert.NoDirExists(t, kustDir, "the Kustomize output must not be written when the patch path is unusable")
	assert.NoFileExists(t, patchPath)
	assert.Equal(t, before, manifestContent(t, dir))
}

func readReportFile(t *testing.T, path string) *reporthandlingv2.PostureReport {
	t.Helper()
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, path)), &report))
	return &report
}

// TestFix_OutputPatchManifestGoneSinceTheScan: the planner skips a manifest
// that no longer exists and reports its control as unfixed, so there is nothing
// to export. No patch and no temporary file is left, and the control is still
// listed. A manifest that vanishes later, while the patch is built, fails the
// whole export; fixhandler's tests cover that.
func TestFix_OutputPatchManifestGoneSinceTheScan(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	require.NoError(t, os.Remove(filepath.Join(dir, "deploy.yaml")))
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	readLog := captureLoggerOutput(t)
	ks := &Kubescape{Ctx: context.Background()}

	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath}))

	assert.NoFileExists(t, patchPath)
	entries, readErr := os.ReadDir(filepath.Dir(patchPath))
	require.NoError(t, readErr)
	assert.Empty(t, entries, "no temporary file may be left behind")
	assert.Contains(t, readLog(), "C-0057", "the control that could not be fixed must still be listed")
}

func TestFix_OutputPatchCancelledWritesNothing(t *testing.T) {
	stubNonInteractiveStdin(t)
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ks := &Kubescape{Ctx: ctx}

	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath})

	require.Error(t, err)
	assert.NoFileExists(t, patchPath)
	assert.Equal(t, before, manifestContent(t, dir))
}

// TestFix_OutputPatchConflictingOptionsAreRefused: the core API is held to the
// rules the command applies, so a caller that sets both does not get one of
// them quietly ignored, and nothing is written or changed.
func TestFix_OutputPatchConflictingOptionsAreRefused(t *testing.T) {
	stubNonInteractiveStdin(t)

	tests := []struct {
		name    string
		extra   func(*metav1.FixInfo, string)
		wantErr string
	}{
		{"with --dry-run", func(f *metav1.FixInfo, _ string) { f.DryRun = true },
			"--output-patch cannot be combined with --dry-run"},
		{"with --output-dir", func(f *metav1.FixInfo, outputDir string) { f.OutputDir = outputDir },
			"--output-patch cannot be combined with --output-dir"},
		{"with both", func(f *metav1.FixInfo, outputDir string) { f.DryRun, f.OutputDir = true, outputDir },
			"--output-patch cannot be combined with"},
		{"with a blank path", func(f *metav1.FixInfo, _ string) { f.OutputPatch = "  " },
			"--output-patch needs a file path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			reportPath := buildFixableReport(t, dir)
			before := manifestContent(t, dir)
			outputDir := filepath.Join(t.TempDir(), "fixed")
			patchPath := filepath.Join(t.TempDir(), "remediation.patch")
			info := &metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath, NoConfirm: true}
			tt.extra(info, outputDir)

			err := (&Kubescape{Ctx: context.Background()}).Fix(info)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NoFileExists(t, patchPath)
			assert.NoDirExists(t, outputDir)
			assert.Equal(t, before, manifestContent(t, dir), "a refused run must not touch the manifest")
		})
	}
}

func TestFix_OutputPatchRefusalComesBeforeTheReportIsRead(t *testing.T) {
	err := (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{
		ReportFile:  filepath.Join(t.TempDir(), "does-not-exist.json"),
		OutputPatch: filepath.Join(t.TempDir(), "remediation.patch"),
		DryRun:      true,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--output-patch cannot be combined with --dry-run", "the option error, not a missing-report error")
}

func TestFix_OutputPatchRefusesAClusterReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildClusterReport(t, dir)
	patchPath := filepath.Join(t.TempDir(), "remediation.patch")

	ks := &Kubescape{Ctx: context.Background()}
	err := ks.Fix(&metav1.FixInfo{ReportFile: reportPath, OutputPatch: patchPath, NoConfirm: true})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--output-patch")
	assert.Contains(t, err.Error(), "--output-dir")
	assert.NoFileExists(t, patchPath)
}

// TestFix_WithoutOutputPatchIsUnchanged guards the existing flows: with the
// flag unset the manifest is still fixed in place and no patch is made.
func TestFix_WithoutOutputPatchIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)

	ks := &Kubescape{Ctx: context.Background()}
	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true}))

	assert.Contains(t, manifestContent(t, dir), "privileged: false")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 2, "only the manifest and the report are in the directory")
}
