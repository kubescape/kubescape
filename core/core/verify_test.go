package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/remediationverify"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyCaptureLog captures the logger like captureLoggerOutput, at the info
// level these tests read the verification summary at. Another test in the
// package sets the global level and leaves it, so the level is not assumed.
func verifyCaptureLog(t *testing.T) func() string {
	t.Helper()
	previous := logger.L().GetLevel()
	require.NoError(t, logger.L().SetLevel("info"))
	t.Cleanup(func() { _ = logger.L().SetLevel(previous) })
	return captureLoggerOutput(t)
}

// verifyStub replaces the rescan with fn for the test and returns the requests
// it was given, in order. The rescan is a scan; a test of what is made of its
// report should not need one.
func verifyStub(t *testing.T, fn func(verifyRescan) (verifyRescanResult, error)) *[]verifyRescan {
	t.Helper()
	prev := verifyRescanFn
	t.Cleanup(func() { verifyRescanFn = prev })
	var calls []verifyRescan
	verifyRescanFn = func(_ *Kubescape, _ context.Context, req verifyRescan) (verifyRescanResult, error) {
		calls = append(calls, req)
		return fn(req)
	}
	return &calls
}

// verifyNeverRescans fails the test if a rescan is attempted.
func verifyNeverRescans(t *testing.T) *[]verifyRescan {
	t.Helper()
	return verifyStub(t, func(req verifyRescan) (verifyRescanResult, error) {
		t.Errorf("no rescan was expected, got one for %v", req.ControlIDs)
		return verifyRescanResult{}, errors.New("unexpected rescan")
	})
}

// verifyReportJSON is a rescan report in the form the scan writes: the posture
// report with its top-level scanCoverage.
func verifyReportJSON(t *testing.T, results []resourcesresults.Result, coverage *cautils.ScanCoverage) []byte {
	t.Helper()
	envelope := struct {
		*reporthandlingv2.PostureReport
		ScanCoverage *cautils.ScanCoverage `json:"scanCoverage,omitempty"`
	}{PostureReport: &reporthandlingv2.PostureReport{Results: results}, ScanCoverage: coverage}
	raw, err := json.Marshal(&envelope)
	require.NoError(t, err)
	return raw
}

func verifyComplete() *cautils.ScanCoverage {
	return &cautils.ScanCoverage{EvaluatedControls: 1, TotalControls: 1}
}

func verifyControlResult(id string, status apis.ScanningStatus, sub apis.ScanningSubStatus) resourcesresults.ResourceAssociatedControl {
	return resourcesresults.ResourceAssociatedControl{ControlID: id, Status: apis.StatusInfo{InnerStatus: status, SubStatus: sub}}
}

// verifyResourceID is the ID the fix report gave its one resource, which is what
// the rescan has to report the control under for it to be found again.
func verifyResourceID(t *testing.T, reportPath string) string {
	t.Helper()
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	require.NotEmpty(t, report.Results)
	return report.Results[0].ResourceID
}

// verifyRescanWith answers every rescan with the given control status for the
// resource, under a scan of the given coverage.
func verifyRescanWith(t *testing.T, resourceID string, control resourcesresults.ResourceAssociatedControl, coverage *cautils.ScanCoverage) *[]verifyRescan {
	t.Helper()
	return verifyStub(t, func(verifyRescan) (verifyRescanResult, error) {
		return verifyRescanResult{
			ReportJSON: verifyReportJSON(t, []resourcesresults.Result{{ResourceID: resourceID, AssociatedControls: []resourcesresults.ResourceAssociatedControl{control}}}, coverage),
			Degraded:   coverage != nil && coverage.Degraded,
		}, nil
	})
}

func verifyFix(t *testing.T, reportPath string) error {
	t.Helper()
	return (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, Verify: true})
}

func TestFix_VerifyResolved(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	calls := verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
	readLog := verifyCaptureLog(t)

	require.NoError(t, verifyFix(t, reportPath))

	assert.Contains(t, manifestContent(t, dir), "privileged: false", "the fix was applied before it was verified")
	log := readLog()
	assert.Contains(t, log, "Verification: 1 resolved, 0 still failing, 0 unverified")
	assert.Contains(t, log, "controls configuration", "the settings the rescan used are said, not assumed")
	require.Len(t, *calls, 1)
	assert.Equal(t, []string{"C-0057"}, (*calls)[0].ControlIDs)
}

func TestFix_VerifyStillFailing(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusFailed, apis.SubStatusUnknown), verifyComplete())
	readLog := verifyCaptureLog(t)

	err := verifyFix(t, reportPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 still failing, 0 unverified")
	assert.Contains(t, manifestContent(t, dir), "privileged: false", "a failed verification does not undo the fix")
	log := readLog()
	assert.Contains(t, log, "Verification: 0 resolved, 1 still failing, 0 unverified")
	assert.Contains(t, log, "Deployment/demo: C-0057 still_failing (control_failed)", "each unresolved finding is named with its kind, name, control, verdict and reason")
	assert.Contains(t, log, "still reported as failed")
}

// TestFix_VerifyUnverified: every way the rescan cannot confirm a fix is an
// error exit with its own reason, and none reads as a success.
func TestFix_VerifyUnverified(t *testing.T) {
	tests := []struct {
		name       string
		results    func(resourceID string) []resourcesresults.Result
		coverage   *cautils.ScanCoverage
		wantReason string
	}{
		{
			name:       "the resource is missing from the rescan",
			results:    func(string) []resourcesresults.Result { return nil },
			coverage:   verifyComplete(),
			wantReason: remediationverify.ReasonResourceNotFound,
		},
		{
			name: "the resource is there under another id",
			results: func(string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: "path=1/api=apps/v1/default/Deployment/renamed",
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown)}}}
			},
			coverage:   verifyComplete(),
			wantReason: remediationverify.ReasonResourceNotFound,
		},
		{
			name: "the control is missing from the resource",
			results: func(id string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0001", apis.StatusPassed, apis.SubStatusUnknown)}}}
			},
			coverage:   verifyComplete(),
			wantReason: remediationverify.ReasonControlNotFound,
		},
		{
			name: "the control was not evaluated",
			results: func(id string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusNotEvaluated)}}}
			},
			coverage:   verifyComplete(),
			wantReason: remediationverify.ReasonControlNotEvaluated,
		},
		{
			name: "the control passed with an exception",
			results: func(id string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusException)}}}
			},
			coverage:   verifyComplete(),
			wantReason: remediationverify.ReasonControlSubStatus,
		},
		{
			name: "the rescan was degraded",
			results: func(id string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown)}}}
			},
			coverage:   &cautils.ScanCoverage{Degraded: true, SkippedManifests: []cautils.SkippedManifest{{Path: "other.yaml", Reason: "parse error"}}},
			wantReason: remediationverify.ReasonCoverageInsufficient,
		},
		{
			name: "the rescan reports no coverage",
			results: func(id string) []resourcesresults.Result {
				return []resourcesresults.Result{{ResourceID: id,
					AssociatedControls: []resourcesresults.ResourceAssociatedControl{verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown)}}}
			},
			coverage:   nil,
			wantReason: remediationverify.ReasonCoverageInsufficient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			reportPath := buildFixableReport(t, dir)
			resourceID := verifyResourceID(t, reportPath)
			verifyStub(t, func(verifyRescan) (verifyRescanResult, error) {
				return verifyRescanResult{
					ReportJSON: verifyReportJSON(t, tt.results(resourceID), tt.coverage),
					Degraded:   tt.coverage != nil && tt.coverage.Degraded,
				}, nil
			})
			readLog := verifyCaptureLog(t)

			err := verifyFix(t, reportPath)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "0 still failing, 1 unverified")
			log := readLog()
			assert.Contains(t, log, "Verification: 0 resolved, 0 still failing, 1 unverified")
			assert.Contains(t, log, "unverified ("+tt.wantReason+")")
		})
	}
}

func TestFix_VerifyRescanFailureIsAnErrorNotAVerdict(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	verifyStub(t, func(verifyRescan) (verifyRescanResult, error) {
		return verifyRescanResult{}, errors.New("policies unavailable")
	})
	readLog := verifyCaptureLog(t)

	err := verifyFix(t, reportPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "the rescan did not complete")
	assert.Contains(t, err.Error(), "policies unavailable")
	assert.NotContains(t, readLog(), "Verification:", "no verdict is drawn from a scan that did not complete")
	assert.Contains(t, manifestContent(t, dir), "privileged: false")
}

func TestFix_VerifyUnparsableRescanReportIsAnErrorNotAVerdict(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	verifyStub(t, func(verifyRescan) (verifyRescanResult, error) {
		return verifyRescanResult{ReportJSON: []byte(`{"results": "not a list"`)}, nil
	})
	readLog := verifyCaptureLog(t)

	err := verifyFix(t, reportPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
	assert.Contains(t, err.Error(), "failed to parse the fresh posture report")
	assert.NotContains(t, readLog(), "Verification:")
}

func TestFix_VerifySkippedWhenApplyFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based write failure is not enforced for root")
	}
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	require.NoError(t, os.Chmod(filepath.Join(dir, "deploy.yaml"), 0444))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "deploy.yaml"), 0644) })
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	err := verifyFix(t, reportPath)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fix some resources", "the existing failure is what is reported")
	assert.Contains(t, readLog(), "Verification skipped: not every fix was applied")
}

// TestFix_VerifyOnlyTheFixedControls: a control the fixer could not fix is
// manual work and is not rescanned or counted as verified. It stays in the
// listing of what remains.
func TestFix_VerifyOnlyTheFixedControls(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	resourceID := verifyResourceID(t, reportPath)

	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	report.Results[0].AssociatedControls = append(report.Results[0].AssociatedControls, resourcesresults.ResourceAssociatedControl{
		ControlID: "C-0041", Name: "HostNetwork access",
		Status: apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name: "rule-host-network", Status: apis.StatusFailed,
			Paths: []armotypes.PosturePaths{{FailedPath: "spec.template.spec.hostNetwork"}},
		}},
	})
	reportPath = writeReportFile(t, dir, &report)
	calls := verifyRescanWith(t, resourceID, verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
	readLog := verifyCaptureLog(t)

	require.NoError(t, verifyFix(t, reportPath), "every control that was fixed is resolved")

	require.Len(t, *calls, 1)
	assert.Equal(t, []string{"C-0057"}, (*calls)[0].ControlIDs, "the manual control is not rescanned")
	log := readLog()
	assert.Contains(t, log, "Verification: 1 resolved, 0 still failing, 0 unverified", "a manual control is not counted as verified")
	assert.Contains(t, log, "C-0041", "the manual control is still listed as needing work")
}

func TestFix_VerifyNothingFixedDoesNotRescan(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
	report.Results[0].AssociatedControls = []resourcesresults.ResourceAssociatedControl{{
		ControlID: "C-0041", Name: "HostNetwork access",
		Status: apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{{
			Name: "rule-host-network", Status: apis.StatusFailed,
			Paths: []armotypes.PosturePaths{{FailedPath: "spec.template.spec.hostNetwork"}},
		}},
	}}
	reportPath = writeReportFile(t, dir, &report)
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	require.NoError(t, verifyFix(t, reportPath))

	log := readLog()
	assert.Contains(t, log, noFixesToVerify)
	assert.Contains(t, log, "C-0041", "the control that needs manual work is listed")
}

func TestFix_VerifyNoIssuesDoesNotRescan(t *testing.T) {
	dir := t.TempDir()
	reportPath := writeReportFile(t, dir, &reporthandlingv2.PostureReport{
		Metadata: reporthandlingv2.Metadata{
			ScanMetadata: reporthandlingv2.ScanMetadata{ScanningTarget: reporthandlingv2.Directory},
			ContextMetadata: reporthandlingv2.ContextMetadata{
				DirectoryContextMetadata: &reporthandlingv2.DirectoryContextMetadata{BasePath: dir},
			},
		},
	})
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	require.NoError(t, verifyFix(t, reportPath))

	assert.Contains(t, readLog(), noFixesToVerify)
}

func TestFix_VerifyDeclinedFixesAreNotVerified(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	withStdin(t, "n\n", func() {
		err := (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, Interactive: true, Verify: true})
		assert.NoError(t, err)
	})

	assert.Equal(t, before, manifestContent(t, dir), "nothing was applied")
	assert.Contains(t, readLog(), noFixesToVerify)
}

func TestFix_VerifyDecliningTheWholeRunDoesNotRescan(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	// A confirmation that is not answered is a decline.
	require.NoError(t, (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, Verify: true}))

	assert.Contains(t, readLog(), noFixesToVerify)
	assert.NotContains(t, manifestContent(t, dir), "privileged: false")
}

// TestFix_VerifyRescansTheRootsOfTheFix: the rescan has to read the manifests
// through the roots the report's resource IDs were made from, which are the
// scan's and not the fixed files'.
func TestFix_VerifyRescansTheRootsOfTheFix(t *testing.T) {
	t.Run("one scanned directory", func(t *testing.T) {
		dir := t.TempDir()
		reportPath := buildFixableReportAt(t, dir, "k8s/prod/deploy.yaml")
		calls := verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())

		require.NoError(t, verifyFix(t, reportPath))

		require.Len(t, *calls, 1)
		assert.Equal(t, []string{dir}, (*calls)[0].Roots, "the scanned directory, not k8s/prod where the fixed file is")
	})

	t.Run("several scanned directories", func(t *testing.T) {
		dir := t.TempDir()
		reportPath := buildTwoInputReport(t, dir)
		calls := verifyStub(t, func(verifyRescan) (verifyRescanResult, error) {
			return verifyRescanResult{ReportJSON: verifyReportJSON(t, nil, verifyComplete())}, nil
		})

		err := verifyFix(t, reportPath)

		require.Error(t, err, "nothing was found again, so nothing is resolved")
		require.Len(t, *calls, 1)
		assert.ElementsMatch(t, []string{
			filepath.Join(dir, "apps", "web", "k8s"),
			filepath.Join(dir, "infra", "db", "k8s"),
		}, (*calls)[0].Roots, "each input is its own root")
	})
}

func TestFix_VerifyUsesTheControlsConfigurationTheReportRecords(t *testing.T) {
	setup := func(t *testing.T, recorded string) (reportPath string) {
		dir := t.TempDir()
		reportPath = buildFixableReport(t, dir)
		var report reporthandlingv2.PostureReport
		require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
		report.Metadata.ScanMetadata.ControlsInputs = recorded
		return writeReportFile(t, dir, &report)
	}
	resolved := func(t *testing.T, reportPath string) *[]verifyRescan {
		return verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
	}

	t.Run("a recorded file is used and named", func(t *testing.T) {
		inputs := filepath.Join(t.TempDir(), "controls-inputs.json")
		require.NoError(t, os.WriteFile(inputs, []byte(`{}`), 0o600))
		reportPath := setup(t, inputs)
		calls := resolved(t, reportPath)
		readLog := verifyCaptureLog(t)

		require.NoError(t, verifyFix(t, reportPath))

		assert.Equal(t, inputs, (*calls)[0].ControlsInputs)
		assert.Contains(t, readLog(), "the controls configuration the report records")
	})
	t.Run("a recorded file that cannot be read is refused before anything is changed", func(t *testing.T) {
		// A rescan under the default instead could call a finding resolved that
		// the recorded configuration still fails, so the default is not
		// substituted, and nothing is applied that could not then be verified.
		reportPath := setup(t, filepath.Join(t.TempDir(), "gone.json"))
		manifestDir := filepath.Dir(reportPath)
		before := manifestContent(t, manifestDir)
		verifyNeverRescans(t)

		err := verifyFix(t, reportPath)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot verify")
		assert.Contains(t, err.Error(), "cannot be read")
		assert.Contains(t, err.Error(), "--controls-config", "the way forward is named")
		assert.Equal(t, before, manifestContent(t, manifestDir), "the manifest must not be changed by a run that could not be verified")
	})
	t.Run("a report that records none uses the default and says so", func(t *testing.T) {
		reportPath := setup(t, "")
		calls := resolved(t, reportPath)
		readLog := verifyCaptureLog(t)

		require.NoError(t, verifyFix(t, reportPath))

		assert.Empty(t, (*calls)[0].ControlsInputs)
		assert.Contains(t, readLog(), "the report records none")
	})
}

func TestFix_VerifyRefusedCombinations(t *testing.T) {
	verifyNeverRescans(t)

	tests := []struct {
		name    string
		info    func(reportPath, outputDir string) *metav1.FixInfo
		wantErr string
	}{
		{"with --dry-run", func(r, _ string) *metav1.FixInfo {
			return &metav1.FixInfo{ReportFile: r, Verify: true, DryRun: true}
		}, "--verify cannot be combined with --dry-run"},
		{"with --output-dir", func(r, o string) *metav1.FixInfo {
			return &metav1.FixInfo{ReportFile: r, Verify: true, OutputDir: o, NoConfirm: true}
		}, "--verify cannot be combined with --output-dir"},
		// The patch path is the one outputDir names here: it must not be created.
		{"with --output-patch", func(r, o string) *metav1.FixInfo {
			return &metav1.FixInfo{ReportFile: r, Verify: true, OutputPatch: o, NoConfirm: true}
		}, "--verify cannot be combined with --output-patch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			reportPath := buildFixableReport(t, dir)
			before := manifestContent(t, dir)
			outputDir := filepath.Join(t.TempDir(), "fixed")

			err := (&Kubescape{Ctx: context.Background()}).Fix(tt.info(reportPath, outputDir))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.NoDirExists(t, outputDir)
			assert.NoFileExists(t, outputDir, "no patch is written by a refused run")
			assert.Equal(t, before, manifestContent(t, dir), "a refused run changes nothing")
		})
	}

	t.Run("the refusal comes before the report is read", func(t *testing.T) {
		err := (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{
			ReportFile: filepath.Join(t.TempDir(), "does-not-exist.json"), Verify: true, DryRun: true,
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "--verify cannot be combined with --dry-run", "the option error, not a missing-report error")
	})

	t.Run("a cluster report has no manifests to rescan", func(t *testing.T) {
		dir := t.TempDir()
		reportPath := buildClusterReport(t, dir)

		err := (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, Verify: true, NoConfirm: true})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "--verify")
		assert.Contains(t, err.Error(), "cluster")
	})
}

// TestFix_WithoutVerifyDoesNotRescan: with the flag unset the fix is exactly
// what it was, and no scan is made.
func TestFix_WithoutVerifyDoesNotRescan(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	verifyNeverRescans(t)
	readLog := verifyCaptureLog(t)

	require.NoError(t, (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true}))

	assert.Contains(t, manifestContent(t, dir), "privileged: false")
	log := readLog()
	assert.NotContains(t, log, "Verification")
	assert.NotContains(t, log, "Verifying")
}

func TestVerificationItems(t *testing.T) {
	outcomes := []fixhandler.ControlOutcome{
		{ResourceID: "r1", ControlID: "C-1", ResourceKind: "Deployment", ResourceName: "web", Fixed: true},
		{ResourceID: "r1", ControlID: "C-1", ResourceKind: "Deployment", ResourceName: "web", Fixed: true}, // the same finding again
		{ResourceID: "r1", ControlID: "C-2", ResourceKind: "Deployment", ResourceName: "web", Fixed: false, Partial: true},
		{ResourceID: "r2", ControlID: "C-1", ResourceName: "bare", Fixed: true},
		{ResourceID: "r3", ControlID: "C-3", Fixed: true},
		{ResourceID: "r4", ControlID: "C-4", Fixed: false},
		{ResourceID: "r5", ControlID: "C-5", Fixed: true, InMemory: true},
	}

	items, labels := verificationItems(outcomes)

	assert.Equal(t, []remediationverify.Item{{ResourceID: "r1", ControlID: "C-1"}, {ResourceID: "r2", ControlID: "C-1"}, {ResourceID: "r3", ControlID: "C-3"}}, items,
		"each fixed finding once; partial, manual and live-cluster outcomes are left out")
	assert.Equal(t, "Deployment/web", labels[items[0]])
	assert.Equal(t, "bare", labels[items[1]])
	assert.Equal(t, "r3", labels[items[2]], "a resource with no name is named by its id")
}

const verifyE2EBadPod = `apiVersion: v1
kind: Pod
metadata:
  name: bad
  namespace: default
spec:
  containers:
  - name: c
    image: nginx
`

const verifyE2EGoodPod = `apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: default
spec:
  containers:
  - name: c
    image: nginx
    securityContext:
      readOnlyRootFilesystem: true
`

// useLocalPolicies points the rescan at policy files in the repository, so the
// real-scan tests need no network. It also pins the exceptions, which a rescan
// would otherwise take from its defaults. It does not keep the scan off a
// cluster: the rescan does that itself, and these tests rely on it.
func useLocalPolicies(t *testing.T) {
	t.Helper()
	nsa, err := filepath.Abs(filepath.Join("..", "cautils", "getter", "testdata", "NSA.json"))
	require.NoError(t, err)
	exceptions, err := filepath.Abs(filepath.Join("testdata", "empty_exceptions.json"))
	require.NoError(t, err)
	controlsInputs, err := filepath.Abs(filepath.Join("..", "cautils", "getter", "testdata", "controls-inputs.json"))
	require.NoError(t, err)

	prev := verifyScanInfoHook
	t.Cleanup(func() { verifyScanInfoHook = prev })
	verifyScanInfoHook = func(info *cautils.ScanInfo) {
		info.UseFrom = []string{nsa}
		info.UseExceptions = exceptions
		if info.ControlsInputs == "" {
			info.ControlsInputs = controlsInputs
		}
	}
}

// TestFix_VerifyRealScan runs the whole pipeline over manifests on disk: a real
// scan makes the report, the fix applies in place, and the verification is a
// real rescan of the same directory, judged by the shared verifier.
func TestFix_VerifyRealScan(t *testing.T) {
	useLocalPolicies(t)
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	good := filepath.Join(dir, "good.yaml")
	require.NoError(t, os.WriteFile(bad, []byte(verifyE2EBadPod), 0o600))
	require.NoError(t, os.WriteFile(good, []byte(verifyE2EGoodPod), 0o600))

	// The report the user would have saved with `scan --format json`.
	scan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(reportPath, scan.ReportJSON, 0o600))
	readLog := verifyCaptureLog(t)

	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, Verify: true}), readLog())

	assert.Contains(t, fileContent(t, bad), "readOnlyRootFilesystem: true", "the bad pod was fixed in place")
	assert.Equal(t, verifyE2EGoodPod, fileContent(t, good), "the pod with nothing to fix is untouched")
	log := readLog()
	assert.Contains(t, log, "Verification: 1 resolved, 0 still failing, 0 unverified")
	assert.Contains(t, log, "the controls configuration the report records", "the rescan reused the configuration the scan recorded")
}

// TestFix_VerifyRealScanNestedManifest: the fixed file is below the scanned
// directory, and the rescan must still find it under the resource ID the scan
// gave it, which it only does when it reads it through the same root.
func TestFix_VerifyRealScanNestedManifest(t *testing.T) {
	useLocalPolicies(t)
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	nested := filepath.Join(dir, "k8s", "prod")
	require.NoError(t, os.MkdirAll(nested, 0o750))
	bad := filepath.Join(nested, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte(verifyE2EBadPod), 0o600))

	scan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(reportPath, scan.ReportJSON, 0o600))
	readLog := verifyCaptureLog(t)

	require.NoError(t, ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, Verify: true}), readLog())

	assert.Contains(t, fileContent(t, bad), "readOnlyRootFilesystem: true")
	assert.Contains(t, readLog(), "Verification: 1 resolved, 0 still failing, 0 unverified")
}

// TestFix_VerifyRealScanMovedResourceIsNotResolved: a resource that moved to
// another file between the fix and the rescan has another ID, so the rescan does
// not find the finding again. With the real scan, not a canned report, that is
// still unverified, never resolved.
func TestFix_VerifyRealScanMovedResourceIsNotResolved(t *testing.T) {
	useLocalPolicies(t)
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte(verifyE2EBadPod), 0o600))

	scan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(reportPath, scan.ReportJSON, 0o600))

	// Verify a fix that moved the resource to another file: after the fix is
	// applied the rescan reads the same directory, but the resource's id, which
	// depends on its path, is no longer there to be found.
	prev := verifyRescanFn
	t.Cleanup(func() { verifyRescanFn = prev })
	verifyRescanFn = func(ks *Kubescape, ctx context.Context, req verifyRescan) (verifyRescanResult, error) {
		require.NoError(t, os.Rename(bad, filepath.Join(dir, "renamed.yaml")))
		return prev(ks, ctx, req)
	}
	readLog := verifyCaptureLog(t)

	err = ks.Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, Verify: true})

	require.Error(t, err, readLog())
	assert.Contains(t, err.Error(), "0 still failing, 1 unverified")
	assert.Contains(t, readLog(), "unverified (resource_not_found)", "a moved resource is not found, and so not resolved")
}

// pointKubeconfigAt makes the process look connected to a cluster whose API
// server is the given one, and puts the state back afterwards.
func pointKubeconfigAt(t *testing.T, serverURL string) {
	t.Helper()
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- cluster: {server: "`+serverURL+`", insecure-skip-tls-verify: true}
  name: fake
contexts:
- context: {cluster: fake, user: u}
  name: fake
current-context: fake
users:
- name: u
  user: {token: x}
`), 0o600))

	previousConfig, previousConnected := k8sinterface.K8SConfig, k8sinterface.IsConnectedToCluster()
	t.Cleanup(func() {
		// Naming the context resets the loaded config and the connection state, so
		// they are put back after it.
		k8sinterface.SetClusterContextName("")
		k8sinterface.K8SConfig = previousConfig
		k8sinterface.SetConnectedToCluster(previousConnected)
	})
	t.Setenv("KUBECONFIG", kubeconfig)
	// Another test may have left a context name that this kubeconfig does not have.
	k8sinterface.SetClusterContextName("")
	require.NoError(t, k8sinterface.LoadK8sConfig())
	k8sinterface.SetConnectedToCluster(true)
}

// TestRescanForVerificationDoesNotContactTheCluster: a verification rescan reads
// manifests and must not reach for the cluster the kubeconfig names, which, when
// that server is down, costs minutes of connection waits. The fake API server
// counts what reaches it, and the process stays connected the whole time: the
// rescan is told not to use the cluster, it does not make the process unable to.
func TestRescanForVerificationDoesNotContactTheCluster(t *testing.T) {
	useLocalPolicies(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	pointKubeconfigAt(t, server.URL)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(verifyE2EBadPod), 0o600))
	ks := &Kubescape{Ctx: context.Background()}

	// The premise: the same scan, not told to avoid the cluster, does reach the
	// server. Without this the test below would pass for a scan that never could
	// have.
	unrestricted := &cautils.ScanInfo{InputPatterns: []string{dir}, Local: true}
	unrestricted.SetScanType(cautils.ScanTypeControl)
	verifyScanInfoHook(unrestricted)
	_, err := ks.ScanContext(context.Background(), unrestricted, cautils.BuildPolicyIdentifiers([]string{"C-0017"}, apisv1.KindControl))
	require.NoError(t, err)
	if requests.Load() == 0 {
		t.Skip("an unrestricted local scan does not reach the API server on this machine, so there is nothing to show the option prevents")
	}

	requests.Store(0)
	result, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})

	require.NoError(t, err)
	assert.NotEmpty(t, result.ReportJSON)
	assert.Zero(t, requests.Load(), "the rescan must not make a single request to the cluster")
	assert.True(t, k8sinterface.IsConnectedToCluster(), "the process's own connection state is not touched")
}

// TestRescanForVerificationLeavesOtherScansAlone: Kubescape.Fix is library code,
// so a verification may run while other scans do. It must neither be seen by
// them, as a process that is not connected, nor leave the process in a state it
// was not in. Bystanders read the connection state the whole time the rescans
// run; run with -race it also checks the rescans do not share unsynchronized
// state with them.
func TestRescanForVerificationLeavesOtherScansAlone(t *testing.T) {
	useLocalPolicies(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	pointKubeconfigAt(t, server.URL)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(verifyE2EBadPod), 0o600))
	ks := &Kubescape{Ctx: context.Background()}

	var disconnectedSeen atomic.Int32
	stop := make(chan struct{})
	var bystanders sync.WaitGroup
	for i := 0; i < 4; i++ {
		bystanders.Add(1)
		go func() {
			defer bystanders.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if !k8sinterface.IsConnectedToCluster() {
						disconnectedSeen.Add(1)
					}
				}
			}
		}()
	}

	const rescans = 3
	var rescanning sync.WaitGroup
	errs := make([]error, rescans)
	for i := 0; i < rescans; i++ {
		rescanning.Add(1)
		go func() {
			defer rescanning.Done()
			_, errs[i] = ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
		}()
	}
	rescanning.Wait()
	close(stop)
	bystanders.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	assert.Zero(t, disconnectedSeen.Load(), "a bystander must never see the process as not connected")
	assert.True(t, k8sinterface.IsConnectedToCluster(), "the process is as connected as it was")
	assert.Zero(t, requests.Load(), "none of the rescans touched the cluster")
}

// TestFix_VerifyControlsConfigOverride: --controls-config says where the
// configuration the finding was raised under is now. It is used in place of the
// recorded one, and it is the way out when the recorded file is gone.
func TestFix_VerifyControlsConfigOverride(t *testing.T) {
	setup := func(t *testing.T, recorded string) (reportPath, dir string) {
		dir = t.TempDir()
		reportPath = buildFixableReport(t, dir)
		var report reporthandlingv2.PostureReport
		require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
		report.Metadata.ScanMetadata.ControlsInputs = recorded
		return writeReportFile(t, dir, &report), dir
	}
	writeConfig := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(path, []byte(`{}`), 0o600))
		return path
	}
	run := func(t *testing.T, reportPath, override string) error {
		return (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, Verify: true, ControlsConfig: override})
	}

	t.Run("it is used when the report records none", func(t *testing.T) {
		reportPath, _ := setup(t, "")
		override := writeConfig(t)
		calls := verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
		readLog := verifyCaptureLog(t)

		require.NoError(t, run(t, reportPath, override))

		assert.Equal(t, override, (*calls)[0].ControlsInputs)
		assert.Contains(t, readLog(), "given with --controls-config")
	})
	t.Run("it replaces a recorded file, and the output says so", func(t *testing.T) {
		recorded := writeConfig(t)
		reportPath, _ := setup(t, recorded)
		override := writeConfig(t)
		calls := verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
		readLog := verifyCaptureLog(t)

		require.NoError(t, run(t, reportPath, override))

		assert.Equal(t, override, (*calls)[0].ControlsInputs)
		log := readLog()
		assert.Contains(t, log, "in place of the one the report records")
		assert.Contains(t, log, recorded)
	})
	t.Run("it is the way out when the recorded file is gone", func(t *testing.T) {
		reportPath, dir := setup(t, filepath.Join(t.TempDir(), "gone.json"))
		override := writeConfig(t)
		calls := verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())

		require.NoError(t, run(t, reportPath, override))

		assert.Equal(t, override, (*calls)[0].ControlsInputs)
		assert.Contains(t, manifestContent(t, dir), "privileged: false")
	})
	t.Run("a file that cannot be read is refused before anything is changed", func(t *testing.T) {
		reportPath, dir := setup(t, "")
		before := manifestContent(t, dir)
		verifyNeverRescans(t)

		err := run(t, reportPath, filepath.Join(t.TempDir(), "missing.json"))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "--controls-config")
		assert.Contains(t, err.Error(), "cannot be read")
		assert.Equal(t, before, manifestContent(t, dir))
	})
	t.Run("a directory is not a configuration", func(t *testing.T) {
		reportPath, dir := setup(t, "")
		before := manifestContent(t, dir)
		verifyNeverRescans(t)

		err := run(t, reportPath, t.TempDir())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
		assert.Equal(t, before, manifestContent(t, dir))
	})
}

func TestFix_ControlsConfigWithoutVerifyIsRefused(t *testing.T) {
	dir := t.TempDir()
	reportPath := buildFixableReport(t, dir)
	before := manifestContent(t, dir)
	verifyNeverRescans(t)

	err := (&Kubescape{Ctx: context.Background()}).Fix(&metav1.FixInfo{ReportFile: reportPath, NoConfirm: true, ControlsConfig: "config.json"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "--controls-config only applies to --verify")
	assert.Equal(t, before, manifestContent(t, dir), "a flag that would do nothing must not let the fix run quietly")
}

// TestFix_VerifyReportsVersionDrift: a report made by another release was judged
// by policies that may differ from this one's, and the output says so.
func TestFix_VerifyReportsVersionDrift(t *testing.T) {
	prev := versioncheck.BuildNumber
	t.Cleanup(func() { versioncheck.BuildNumber = prev })

	tests := []struct {
		name            string
		recorded, built string
		wantWarning     bool
	}{
		{"another release", "v3.0.0", "v4.0.0", true},
		{"the same release", "v4.0.0", "v4.0.0", false},
		{"the report does not say", "", "v4.0.0", false},
		{"this build does not say", "v3.0.0", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versioncheck.BuildNumber = tt.built
			dir := t.TempDir()
			reportPath := buildFixableReport(t, dir)
			var report reporthandlingv2.PostureReport
			require.NoError(t, json.Unmarshal([]byte(fileContent(t, reportPath)), &report))
			report.Metadata.ScanMetadata.KubescapeVersion = tt.recorded
			reportPath = writeReportFile(t, dir, &report)
			verifyRescanWith(t, verifyResourceID(t, reportPath), verifyControlResult("C-0057", apis.StatusPassed, apis.SubStatusUnknown), verifyComplete())
			readLog := verifyCaptureLog(t)

			require.NoError(t, verifyFix(t, reportPath))

			log := readLog()
			if tt.wantWarning {
				assert.Contains(t, log, "The report was made by Kubescape "+tt.recorded+" and this is "+tt.built)
			} else {
				assert.NotContains(t, log, "The report was made by Kubescape")
			}
		})
	}
}

// verifyExceptionPolicy is one exception, in the form an --exceptions file
// holds it.
func verifyExceptionPolicy(actions []string, attributes map[string]string, policy map[string]string) map[string]any {
	return map[string]any{
		"name":            "test-exception",
		"policyType":      "postureExceptionPolicy",
		"actions":         actions,
		"resources":       []any{map[string]any{"designatorType": "Attributes", "attributes": attributes}},
		"posturePolicies": []any{policy},
	}
}

// TestVerifyExceptionsNeverResolveAFindingThatPersists is the claim that lets
// --verify do without an --exceptions flag: a rescan under exceptions the
// original scan did not have can turn a finding that persists into
// still_failing or unverified, and never into resolved. It is checked with real
// scans of a manifest whose finding is still there, as it would be if a fix did
// not work, under every shape of exception the engine knows.
func TestVerifyExceptionsNeverResolveAFindingThatPersists(t *testing.T) {
	useLocalPolicies(t)
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(verifyE2EBadPod), 0o600))

	scan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal(scan.ReportJSON, &report))
	require.Len(t, report.Results, 1)
	item := remediationverify.Item{ResourceID: report.Results[0].ResourceID, ControlID: "C-0017"}

	const rule = "immutable-container-filesystem"
	pod := map[string]string{"kind": "Pod", "name": "bad", "namespace": "default"}
	control := map[string]string{"controlID": "C-0017"}
	tests := []struct {
		name     string
		policy   map[string]any
		wantOnly string // the one verdict this must give, or "" for any but resolved
	}{
		{"no exception", nil, remediationverify.VerdictStillFailing},
		{"alertOnly on the control", verifyExceptionPolicy([]string{"alertOnly"}, pod, control), remediationverify.VerdictStillFailing},
		{"disable on the control", verifyExceptionPolicy([]string{"disable"}, pod, control), remediationverify.VerdictUnverified},
		{"no action, which suppresses as it always has", verifyExceptionPolicy(nil, pod, control), remediationverify.VerdictUnverified},
		{"disable by kind alone", verifyExceptionPolicy([]string{"disable"}, map[string]string{"kind": "Pod"}, control), remediationverify.VerdictUnverified},
		{"disable by a name pattern", verifyExceptionPolicy([]string{"disable"}, map[string]string{"kind": "Pod", "name": "ba.*"}, control), remediationverify.VerdictUnverified},
		{"disable on the rule alone", verifyExceptionPolicy([]string{"disable"}, pod, map[string]string{"ruleName": rule}), remediationverify.VerdictUnverified},
		{"every control", verifyExceptionPolicy([]string{"disable"}, pod, map[string]string{"controlID": "C-.*"}), remediationverify.VerdictUnverified},
		{"alertOnly and disable together", nil, ""}, // built below
		{"another control", verifyExceptionPolicy([]string{"disable"}, pod, map[string]string{"controlID": "C-0001"}), remediationverify.VerdictStillFailing},
		{"another resource", verifyExceptionPolicy([]string{"disable"}, map[string]string{"kind": "Pod", "name": "other", "namespace": "default"}, control), remediationverify.VerdictStillFailing},
		{"another namespace", verifyExceptionPolicy([]string{"disable"}, map[string]string{"kind": "Pod", "name": "bad", "namespace": "prod"}, control), remediationverify.VerdictStillFailing},
		{"a framework this scan is not for", verifyExceptionPolicy([]string{"disable"}, pod, map[string]string{"frameworkName": "NSA", "controlID": "C-0017"}), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := []any{}
			switch {
			case tt.name == "alertOnly and disable together":
				policies = append(policies, verifyExceptionPolicy([]string{"alertOnly"}, pod, control), verifyExceptionPolicy([]string{"disable"}, pod, control))
			case tt.policy != nil:
				policies = append(policies, tt.policy)
			}
			raw, err := json.Marshal(policies)
			require.NoError(t, err)
			exceptions := filepath.Join(t.TempDir(), "exceptions.json")
			require.NoError(t, os.WriteFile(exceptions, raw, 0o600))
			base := verifyScanInfoHook
			t.Cleanup(func() { verifyScanInfoHook = base })
			verifyScanInfoHook = func(info *cautils.ScanInfo) {
				base(info)
				info.UseExceptions = exceptions
			}

			rescan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
			require.NoError(t, err)
			resp, err := remediationverify.ClassifyReportJSON(rescan.ReportJSON, rescan.Degraded, []remediationverify.Item{item})
			require.NoError(t, err)

			got := resp.Results[0]
			assert.NotEqual(t, remediationverify.VerdictResolved, got.Verdict, "an exception must never resolve a finding that persists (%s)", got.Reason)
			if tt.wantOnly != "" {
				assert.Equal(t, tt.wantOnly, got.Verdict, "reason: %s", got.Reason)
			}
			t.Logf("%-46s -> %s (%s)", tt.name, got.Verdict, got.Reason)
		})
	}
}

// TestVerifyExceptionDoesNotHideAGenuineResolution: an exception attaches to a
// finding, so a manifest that no longer has the finding is resolved whether or
// not an exception names it. Exceptions cost a genuine fix nothing.
func TestVerifyExceptionDoesNotHideAGenuineResolution(t *testing.T) {
	useLocalPolicies(t)
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(verifyE2EBadPod), 0o600))
	scan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	var report reporthandlingv2.PostureReport
	require.NoError(t, json.Unmarshal(scan.ReportJSON, &report))
	item := remediationverify.Item{ResourceID: report.Results[0].ResourceID, ControlID: "C-0017"}

	// The fix, applied as the fixer would: the one container reads only its root.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(verifyE2EBadPod+"    securityContext:\n      readOnlyRootFilesystem: true\n"), 0o600))
	raw, err := json.Marshal([]any{verifyExceptionPolicy([]string{"disable"}, map[string]string{"kind": "Pod", "name": "bad", "namespace": "default"}, map[string]string{"controlID": "C-0017"})})
	require.NoError(t, err)
	exceptions := filepath.Join(t.TempDir(), "exceptions.json")
	require.NoError(t, os.WriteFile(exceptions, raw, 0o600))
	base := verifyScanInfoHook
	t.Cleanup(func() { verifyScanInfoHook = base })
	verifyScanInfoHook = func(info *cautils.ScanInfo) {
		base(info)
		info.UseExceptions = exceptions
	}

	rescan, err := ks.rescanForVerification(context.Background(), verifyRescan{Roots: []string{dir}, ControlIDs: []string{"C-0017"}})
	require.NoError(t, err)
	resp, err := remediationverify.ClassifyReportJSON(rescan.ReportJSON, rescan.Degraded, []remediationverify.Item{item})
	require.NoError(t, err)

	assert.Equal(t, remediationverify.VerdictResolved, resp.Results[0].Verdict, "reason: %s", resp.Results[0].Reason)
}
