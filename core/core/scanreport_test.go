package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/watch"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localScanTemplate is the ScanInfo a caller keeps for a series of scans of the
// manifests under dir. It points at policy files in the repository, so the scans
// need no network, and asks for no cluster and no cloud.
func localScanTemplate(t *testing.T, dir string) *cautils.ScanInfo {
	t.Helper()
	abs := func(parts ...string) string {
		path, err := filepath.Abs(filepath.Join(parts...))
		require.NoError(t, err)
		return path
	}
	info := &cautils.ScanInfo{
		InputPatterns:   []string{dir},
		UseFrom:         []string{abs("..", "cautils", "getter", "testdata", "NSA.json")},
		UseExceptions:   abs("testdata", "empty_exceptions.json"),
		ControlsInputs:  abs("..", "cautils", "getter", "testdata", "controls-inputs.json"),
		Local:           true,
		NoClusterAccess: true,
	}
	info.SetScanType(cautils.ScanTypeControl)
	return info
}

var readOnlyRootFilesystem = cautils.BuildPolicyIdentifiers([]string{"C-0017"}, apisv1.KindControl)

func writeManifest(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
}

// podManifest is a pod that fails C-0017 unless it sets a read-only root filesystem.
func podManifest(name string, readOnly bool) string {
	manifest := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: " + name + "\n  namespace: default\nspec:\n  containers:\n  - name: c\n    image: nginx\n"
	if readOnly {
		manifest += "    securityContext:\n      readOnlyRootFilesystem: true\n"
	}
	return manifest
}

// The report is the document `kubescape scan --format json` writes, with its
// coverage always present.
func TestScanToReportReturnsTheScanReportInMemory(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	ks := &Kubescape{Ctx: context.Background()}

	report, err := ks.ScanToReport(context.Background(), localScanTemplate(t, dir), readOnlyRootFilesystem)

	require.NoError(t, err)
	assert.False(t, report.Degraded)
	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(report.JSON, &document))
	for _, key := range []string{"results", "resources", "summaryDetails", "scanCoverage", "metadata"} {
		assert.Contains(t, document, key)
	}
}

// What a caller does with a series of scans: scan, change a manifest, scan again
// with the same ScanInfo and compare. A finding that the edit fixed is resolved,
// one it introduced is new, and one it did not touch is neither.
func TestScanToReportSeriesCanBeComparedByFindingIdentity(t *testing.T) {
	dir := t.TempDir()
	ks := &Kubescape{Ctx: context.Background()}
	template := localScanTemplate(t, dir)
	scan := func() []byte {
		t.Helper()
		report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		require.NoError(t, err)
		return report.JSON
	}
	compare := func(base, head []byte) *watch.Comparison {
		t.Helper()
		comparison, err := watch.Compare(base, head, diff.Options{Granularity: diff.GranularityControl})
		require.NoError(t, err)
		return comparison
	}

	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	writeManifest(t, dir, "other.yaml", podManifest("other", false))
	first := scan()

	unchanged := compare(first, scan())
	assert.Empty(t, unchanged.ChangeSet.New)
	assert.Empty(t, unchanged.ChangeSet.Resolved)
	assert.Len(t, unchanged.ChangeSet.Unchanged, 2, "both pods still fail C-0017")

	writeManifest(t, dir, "pod.yaml", podManifest("web", true))
	fixed := scan()
	afterFix := compare(first, fixed)
	require.Len(t, afterFix.ChangeSet.Resolved, 1)
	assert.Equal(t, "C-0017", afterFix.ChangeSet.Resolved[0].ControlID)
	assert.Contains(t, afterFix.ChangeSet.Resolved[0].ResourceID, "web")
	assert.Empty(t, afterFix.ChangeSet.New)
	assert.Len(t, afterFix.ChangeSet.Unchanged, 1, "the other pod was not touched")

	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	afterRegression := compare(fixed, scan())
	require.Len(t, afterRegression.ChangeSet.New, 1)
	assert.Contains(t, afterRegression.ChangeSet.New[0].ResourceID, "web")
	assert.Empty(t, afterRegression.ChangeSet.Resolved)
}

// A ScanInfo serves any number of scans because none of them changes it: Init
// would otherwise leave a scan id, resolved policy paths and cleanups in it for
// the next scan to inherit.
func TestScanToReportDoesNotChangeTheScanInfo(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.Format = "json"
	template.Output = filepath.Join(t.TempDir(), "report.json")
	before := *template
	before.UseFrom = slices.Clone(template.UseFrom)
	before.InputPatterns = slices.Clone(template.InputPatterns)
	ks := &Kubescape{Ctx: context.Background()}

	for i := 0; i < 2; i++ {
		_, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		require.NoError(t, err)
	}

	assert.Equal(t, before, *template)
	assert.Empty(t, template.ScanID, "each scan gets an id of its own")
	assert.Nil(t, template.Submit.Get())
	assert.NoFileExists(t, template.Output, "an output file is neither opened nor truncated")
}

func TestScanToReportRefusesWhatCannotBeReturnedAsAReport(t *testing.T) {
	ks := &Kubescape{Ctx: context.Background()}
	dir := t.TempDir()

	t.Run("no scan info", func(t *testing.T) {
		report, err := ks.ScanToReport(context.Background(), nil, readOnlyRootFilesystem)
		require.Error(t, err)
		assert.Nil(t, report)
	})
	t.Run("a dry run", func(t *testing.T) {
		template := localScanTemplate(t, dir)
		template.DryRun = true
		report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		require.ErrorContains(t, err, "dry run")
		assert.Nil(t, report)
	})
	t.Run("an encrypted scan", func(t *testing.T) {
		template := localScanTemplate(t, dir)
		template.EncryptionEnabled = true
		report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		require.ErrorContains(t, err, "encrypted")
		assert.Nil(t, report)
	})
	t.Run("a scan of a cluster", func(t *testing.T) {
		template := &cautils.ScanInfo{Local: true, NoClusterAccess: true}
		template.SetScanType(cautils.ScanTypeControl)
		report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		require.ErrorContains(t, err, "local inputs")
		assert.Nil(t, report)
	})
}

// A scan that fails is an error with no report: a series must not take half a
// scan for a scan.
func TestScanToReportReturnsAScanFailureAsAnError(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.UseFrom = []string{filepath.Join(t.TempDir(), "missing-policy.json")}
	ks := &Kubescape{Ctx: context.Background()}

	report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)

	require.Error(t, err)
	assert.Nil(t, report)
}

// Scans that run at the same time from one ScanInfo share nothing they change.
// Run with -race this also checks that, and the fake API server checks that none
// of them reaches for the cluster the kubeconfig names.
func TestScanToReportConcurrentScansShareAScanInfo(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	pointKubeconfigAt(t, server.URL)
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	ks := &Kubescape{Ctx: context.Background()}

	const scans = 6
	var wg sync.WaitGroup
	reports := make([]*ScanReport, scans)
	errs := make([]error, scans)
	for i := 0; i < scans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i], errs[i] = ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
		}()
	}
	wg.Wait()

	for i := range errs {
		require.NoError(t, errs[i], "scan %d", i)
		require.NotNil(t, reports[i])
		comparison, err := watch.Compare(reports[0].JSON, reports[i].JSON, diff.Options{Granularity: diff.GranularityControl})
		require.NoError(t, err)
		assert.Empty(t, comparison.ChangeSet.New, "scan %d", i)
		assert.Empty(t, comparison.ChangeSet.Resolved, "scan %d", i)
		assert.NotEmpty(t, comparison.ChangeSet.Unchanged, "scan %d", i)
	}
	assert.Zero(t, requests.Load(), "no scan reached for the cluster")
}

// A kubeconfig whose server accepts the connection and never answers is the
// worst a stale kubeconfig can be: a scan that waits for it waits without end.
// A scan told not to use the cluster is not held up.
func TestScanToReportIsNotHeldUpByAnUnresponsiveAPIServer(t *testing.T) {
	var requests atomic.Int32
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	pointKubeconfigAt(t, server.URL)
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	ks := &Kubescape{Ctx: context.Background()}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	started := time.Now()
	report, err := ks.ScanToReport(ctx, localScanTemplate(t, dir), readOnlyRootFilesystem)

	require.NoError(t, err, "the scan finished without waiting for the server")
	assert.NotEmpty(t, report.JSON)
	assert.Less(t, time.Since(started), 30*time.Second)
	assert.Zero(t, requests.Load())
}

// The end of the scan's context is an error that still says what ended it, and no
// report: a caller that stops a scan can tell that apart from one that failed.
func TestScanToReportEndOfContextIsAnErrorThatKeepsItsCause(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	ks := &Kubescape{Ctx: context.Background()}

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report, err := ks.ScanToReport(ctx, localScanTemplate(t, dir), readOnlyRootFilesystem)
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, report)
	})
	t.Run("past its deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		report, err := ks.ScanToReport(ctx, localScanTemplate(t, dir), readOnlyRootFilesystem)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, report)
	})
}

// A report that was asked to leave its resources out has none, and says so to a
// reader that needs them, instead of being compared by guesswork.
func TestScanToReportWithoutRawResourcesCannotBeComparedByIdentity(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.OmitRawResources = true
	ks := &Kubescape{Ctx: context.Background()}

	report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)

	require.NoError(t, err)
	var document struct {
		Resources []json.RawMessage `json:"resources"`
	}
	require.NoError(t, json.Unmarshal(report.JSON, &document))
	assert.Empty(t, document.Resources)
	_, err = watch.Compare(report.JSON, report.JSON, diff.Options{Granularity: diff.GranularityControl})
	assert.ErrorIs(t, err, watch.ErrNoResourceIdentity)
}

// The report is the document `kubescape scan --format json` writes, to what a
// comparison reads of it: the same findings, on the same resources, with the same
// severity. Compared against the report ScanContext's own results serialize to, no
// finding is new, none resolved, and each one that is unchanged carries a severity.
func TestScanToReportMatchesTheScanJSONReport(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	writeManifest(t, dir, "other.yaml", podManifest("other", true))
	template := localScanTemplate(t, dir)
	ks := &Kubescape{Ctx: context.Background()}

	scanned := localScanTemplate(t, dir)
	results, err := ks.ScanContext(context.Background(), scanned, readOnlyRootFilesystem)
	require.NoError(t, err)
	normal, err := results.ToJson()
	require.NoError(t, err)
	report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
	require.NoError(t, err)

	comparison, err := watch.Compare(normal, report.JSON, diff.Options{Granularity: diff.GranularityControl})
	require.NoError(t, err)
	assert.Empty(t, comparison.ChangeSet.New)
	assert.Empty(t, comparison.ChangeSet.Resolved)
	assert.Empty(t, comparison.ChangeSet.Incomparable)
	require.NotEmpty(t, comparison.ChangeSet.Unchanged)
	for _, change := range comparison.ChangeSet.Unchanged {
		assert.NotEmpty(t, change.Severity, "%s on %s", change.ControlID, change.ResourceID)
	}
}

// A series of scans with the one ScanInfo shares the store it carries: the release
// is downloaded for the first of them, and the others are served from it.
func TestScanToReportSeriesDownloadsTheReleaseOnce(t *testing.T) {
	keepScansOffTheCluster(t)
	releases := newRegolibraryReleases(t)
	dir := writePodManifest(t)
	template := &cautils.ScanInfo{
		InputPatterns:       []string{dir},
		ReleasedPolicyStore: getter.NewDownloadReleasedPolicy(),
		Local:               true,
		NoClusterAccess:     true,
		FrameworkScan:       true,
	}
	template.SetScanType(cautils.ScanTypeFramework)
	template.Submit.SetBool(false)
	ks := &Kubescape{Ctx: context.Background()}

	var reports [][]byte
	for i := 0; i < 3; i++ {
		report, err := ks.ScanToReport(context.Background(), template, cautils.BuildPolicyIdentifiers([]string{"nsa"}, apisv1.KindFramework))
		require.NoError(t, err, "scan %d", i)
		reports = append(reports, report.JSON)
	}

	assert.Equal(t, 1, releases.downloads("v2"), "three scans of one ScanInfo downloaded the release once")
	for i := 1; i < len(reports); i++ {
		comparison, err := watch.Compare(reports[0], reports[i], diff.Options{Granularity: diff.GranularityControl})
		require.NoError(t, err)
		assert.Empty(t, comparison.ChangeSet.New, "scan %d", i)
		assert.Empty(t, comparison.ChangeSet.Resolved, "scan %d", i)
	}
}

// An image scan keeps its failure for the results handler and the report holds
// posture results only, so it is refused before anything is scanned: the error is
// ours and not the missing policy file's the scan would have stopped on.
func TestScanToReportRefusesAnImageScanBeforeScanning(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	template := localScanTemplate(t, dir)
	template.ScanImages = true
	template.UseFrom = []string{filepath.Join(t.TempDir(), "missing-policy.json")}
	before := *template
	before.UseFrom = slices.Clone(template.UseFrom)
	before.InputPatterns = slices.Clone(template.InputPatterns)
	ks := &Kubescape{Ctx: context.Background()}

	report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)

	require.ErrorContains(t, err, "image scan")
	assert.NotContains(t, err.Error(), "missing-policy")
	assert.Nil(t, report)
	assert.Equal(t, before, *template)
	assert.Empty(t, template.ScanID, "no scan was started")

	template.ScanImages = false
	_, err = ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)
	require.Error(t, err, "without ScanImages the scan reaches the missing policy file")
	assert.NotContains(t, err.Error(), "image scan")
}

// failedResources lists the resources a report shows C-0017 failing for.
func failedResources(t *testing.T, reportJSON []byte) []string {
	t.Helper()
	var document struct {
		Results []struct {
			ResourceID string `json:"resourceID"`
			Controls   []struct {
				ControlID string `json:"controlID"`
				Status    struct {
					Status string `json:"status"`
				} `json:"status"`
			} `json:"controls"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal(reportJSON, &document))
	var failed []string
	for _, result := range document.Results {
		for _, control := range result.Controls {
			if control.ControlID == "C-0017" && control.Status.Status == "failed" {
				failed = append(failed, result.ResourceID)
			}
		}
	}
	return failed
}

// MinSeverity and MaxSeverity filter what is written when results are handled,
// which a report does not go through, so the report holds the findings whatever
// they are set to, and the caller's ScanInfo keeps its settings. ScanContext does
// not read the filters today, so this pins the outcome and not the copy, which
// ScanToReport clears so that it carries no output setting.
func TestScanToReportIgnoresTheOutputSeverityFilters(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "pod.yaml", podManifest("web", false))
	ks := &Kubescape{Ctx: context.Background()}

	unfiltered, err := ks.ScanToReport(context.Background(), localScanTemplate(t, dir), readOnlyRootFilesystem)
	require.NoError(t, err)
	want := failedResources(t, unfiltered.JSON)
	require.Len(t, want, 1, "the fixture has one failing resource")

	for _, tt := range []struct{ name, min, max string }{
		{"minimum above the finding", "critical", ""},
		{"maximum below the finding", "", "low"},
		{"both, leaving no severity", "critical", "low"},
		{"both, around the finding", "low", "critical"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template := localScanTemplate(t, dir)
			template.MinSeverity, template.MaxSeverity = tt.min, tt.max
			before := *template
			before.UseFrom = slices.Clone(template.UseFrom)
			before.InputPatterns = slices.Clone(template.InputPatterns)

			report, err := ks.ScanToReport(context.Background(), template, readOnlyRootFilesystem)

			require.NoError(t, err)
			assert.Equal(t, want, failedResources(t, report.JSON))
			assert.Equal(t, tt.min, template.MinSeverity)
			assert.Equal(t, tt.max, template.MaxSeverity)
			assert.Equal(t, before, *template, "nothing else of the caller's ScanInfo changed")
		})
	}
}
