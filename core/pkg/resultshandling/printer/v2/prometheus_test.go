package printer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrometheusPrinter(t *testing.T) {
	// For verbose mode false
	verboseMode := false
	promPrinter := NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)

	// For verbose mode true
	verboseMode = true
	promPrinter = NewPrometheusPrinter(verboseMode)
	assert.NotNil(t, promPrinter)
	assert.Equal(t, verboseMode, promPrinter.verboseMode)
}

func TestSetWriter(t *testing.T) {
	outputFile := ""
	promPrinter := &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), outputFile)
	assert.Equal(t, os.Stdout, promPrinter.writer)

	base := filepath.Join(t.TempDir(), "test-prom")
	promPrinter = &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), base)
	// SetWriter leaves the report file open. Windows refuses to delete a file
	// that still has an open handle, so t.TempDir's cleanup fails the test
	// unless the writer is closed too. Captured in a local because promPrinter
	// is reassigned below.
	baseWriter := promPrinter.writer
	defer baseWriter.Close()
	expectedPath := base + printer.PrometheusOutputExt
	f, err := os.Open(expectedPath)
	assert.NoError(t, err)
	defer f.Close()
	assert.Equal(t, expectedPath, promPrinter.writer.Name())

	withExt := filepath.Join(t.TempDir(), "test-prom"+printer.PrometheusOutputExt)
	promPrinter = &PrometheusPrinter{}
	promPrinter.SetWriter(context.Background(), withExt)
	defer promPrinter.writer.Close()
	f2, err := os.Open(withExt)
	assert.NoError(t, err)
	defer f2.Close()
	assert.Equal(t, withExt, promPrinter.writer.Name())
}

func TestScore(t *testing.T) {
	tests := []struct {
		name  string
		score float32
		want  string
	}{
		{
			name:  "Score less than 0",
			score: -20.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 0\n",
		},
		{
			name:  "Score greater than 100",
			score: 120.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 100\n",
		},
		{
			name:  "Score 50",
			score: 50.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 50\n",
		},
		{
			name:  "Fractional score below perfect",
			score: 99.5,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 99\n",
		},
		{
			name:  "Zero Score",
			score: 0.0,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 0\n",
		},
		{
			name:  "Perfect Score",
			score: 100,
			want:  "# HELP kubescape_score Overall compliance score (100 Excellent, 0 All failed)\n# TYPE kubescape_score gauge\nkubescape_score 100\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Score() must write to pp.writer, not stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			promPrinter := NewPrometheusPrinter(false)
			promPrinter.writer = w

			promPrinter.Score(tt.score)

			require.NoError(t, w.Close())
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			require.NoError(t, r.Close())
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestResourceMetricsEmitted(t *testing.T) {
	// Regression test for https://github.com/kubescape/kubescape/issues/2236
	// Fails on master (setResourcesCounters commented out), passes with patch.
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "nginx",
			"namespace": "default",
		},
	}
	wl := workloadinterface.NewWorkloadObj(obj)
	resourceID := wl.GetID()

	failedRule := resourcesresults.ResourceAssociatedRule{}
	failedRule.SetStatus(apis.StatusFailed, nil)

	skippedRule := resourcesresults.ResourceAssociatedRule{}
	skippedRule.SetStatus(apis.StatusSkipped, nil)

	failedCtrl1 := resourcesresults.ResourceAssociatedControl{}
	failedCtrl1.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{failedRule}

	failedCtrl2 := resourcesresults.ResourceAssociatedControl{}
	failedCtrl2.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{failedRule}

	skippedCtrl := resourcesresults.ResourceAssociatedControl{}
	skippedCtrl.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{skippedRule}

	passedRule := resourcesresults.ResourceAssociatedRule{}
	passedRule.SetStatus(apis.StatusPassed, nil)

	passedCtrl := resourcesresults.ResourceAssociatedControl{}
	passedCtrl.ResourceAssociatedRules = []resourcesresults.ResourceAssociatedRule{passedRule}

	result := resourcesresults.Result{}
	result.ResourceID = resourceID
	result.AssociatedControls = []resourcesresults.ResourceAssociatedControl{
		failedCtrl1, failedCtrl2, skippedCtrl, passedCtrl,
	}

	pp := NewPrometheusPrinter(false)
	metrics := pp.generatePrometheusFormat(
		map[string]workloadinterface.IMetadata{resourceID: wl},
		map[string]resourcesresults.Result{resourceID: result},
		&reportsummary.SummaryDetails{},
		cautils.ScanCoverage{},
	)
	output := metrics.String()

	assert.Contains(t, output, "kubescape_resource_count_controls_failed",
		"missing kubescape_resource_count_controls_failed — setResourcesCounters may be commented out")
	assert.Contains(t, output, "kubescape_resource_count_controls_skipped",
		"missing kubescape_resource_count_controls_skipped — setResourcesCounters may be commented out")
	assert.Contains(t, output, "kubescape_resource_count_controls_passed",
		"missing kubescape_resource_count_controls_passed")
}

func TestCoverageScoreMetricEmitted(t *testing.T) {
	coverage := cautils.ScanCoverage{}
	coverage.ComputeCoverageScore(10)
	require.Equal(t, float32(100), coverage.CoverageScore)

	pp := NewPrometheusPrinter(false)
	metrics := pp.generatePrometheusFormat(
		map[string]workloadinterface.IMetadata{},
		map[string]resourcesresults.Result{},
		&reportsummary.SummaryDetails{},
		coverage,
	)
	output := metrics.String()

	assert.Contains(t, output, "# TYPE kubescape_cluster_coverage_score gauge")
	assert.Contains(t, output, "kubescape_cluster_coverage_score{} 100")

	// a degraded scan must emit the discounted score
	degraded := cautils.ScanCoverage{
		NotEvaluatedControls: []cautils.NotEvaluatedControl{{ControlID: "C-0001"}},
	}
	degraded.ComputeCoverageScore(10)
	metrics = pp.generatePrometheusFormat(
		map[string]workloadinterface.IMetadata{},
		map[string]resourcesresults.Result{},
		&reportsummary.SummaryDetails{},
		degraded,
	)
	assert.Contains(t, metrics.String(), "kubescape_cluster_coverage_score{} 90")
}

func TestImagePrometheusFormat_OmitsPostureMetrics(t *testing.T) {
	// Regression test for #2782: an image scan must not emit posture-scan
	// metric families (compliance score, coverage) at zero — those fields
	// are never populated for image scans, so emitting them previously
	// pushed out a misleading all-zero compliance score alongside the
	// real CVE metrics.
	imageData := []cautils.ImageScanData{
		{
			Image:    "test-image:latest",
			Platform: "linux/arm64",
			Matches: match.NewMatches(match.Match{
				Package: grypepkg.Package{ID: "pkg-1", Name: "openssl", Version: "3.0.0"},
				Vulnerability: vulnerability.Vulnerability{
					Metadata: &vulnerability.Metadata{ID: "CVE-2026-0001", Severity: "High"},
					Fix:      vulnerability.Fix{Versions: []string{"3.0.1"}, State: "Fixed"},
				},
			}),
		},
	}

	pp := NewPrometheusPrinter(false)
	metrics := pp.generateImagePrometheusFormat(imageData)
	output := metrics.String()

	// Image metrics must be present.
	assert.Contains(t, output, "kubescape_image_count_cve")
	assert.Contains(t, output, `image="test-image:latest",platform="linux/arm64",severity="High"`)
	assert.NotContains(t, output, `image="test-image:latest [linux/arm64]"`)

	// Posture metric families must be completely absent, not just zeroed.
	assert.NotContains(t, output, "kubescape_cluster_complianceScore")
	assert.NotContains(t, output, "kubescape_cluster_count_resources")
	assert.NotContains(t, output, "kubescape_cluster_count_control")
	assert.NotContains(t, output, "kubescape_cluster_coverage_score")

	imageData[0].Platform = ""
	legacyOutput := pp.generateImagePrometheusFormat(imageData).String()
	assert.Contains(t, legacyOutput, `image="test-image:latest",severity="High"`)
	assert.NotContains(t, legacyOutput, `platform=`)
}

func TestPostureScanFormat_StillEmitsPostureMetrics(t *testing.T) {
	// Sanity check the flag doesn't accidentally suppress posture metrics
	// for real posture scans.
	pp := NewPrometheusPrinter(false)
	metrics := pp.generatePrometheusFormat(
		map[string]workloadinterface.IMetadata{},
		map[string]resourcesresults.Result{},
		&reportsummary.SummaryDetails{},
		cautils.ScanCoverage{},
	)
	output := metrics.String()

	assert.Contains(t, output, "kubescape_cluster_complianceScore")
	assert.Contains(t, output, "kubescape_cluster_coverage_score")
}

func TestPrometheusActionPrint_CombinedScanEmitsBothPostureAndImageMetrics(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	imageData := []cautils.ImageScanData{
		{
			Image:    "test-image:latest",
			Platform: "linux/amd64",
			Matches: match.NewMatches(match.Match{
				Package: grypepkg.Package{ID: "pkg-1", Name: "openssl", Version: "3.0.0"},
				Vulnerability: vulnerability.Vulnerability{
					Metadata: &vulnerability.Metadata{ID: "CVE-2026-0001", Severity: "High"},
					Fix:      vulnerability.Fix{Versions: []string{"3.0.1"}, State: "Fixed"},
				},
			}),
		},
	}

	r, w, err := os.Pipe()
	require.NoError(t, err)

	promPrinter := NewPrometheusPrinter(false)
	promPrinter.writer = w

	err = promPrinter.ActionPrint(context.Background(), session, imageData)
	require.NoError(t, err)

	require.NoError(t, w.Close())
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	output := string(got)

	// Posture metrics must be present.
	assert.Contains(t, output, "kubescape_cluster_complianceScore")
	assert.Contains(t, output, "kubescape_cluster_coverage_score")

	// Container image vulnerability metrics must also be present in combined scans.
	assert.Contains(t, output, "kubescape_image_count_cve")
	assert.Contains(t, output, "kubescape_image_count_cve_fixable")
	assert.Contains(t, output, `image="test-image:latest",platform="linux/amd64",severity="High"`)
}

func TestPrometheusActionPrint_MissingDataReturnsError(t *testing.T) {
	promPrinter := NewPrometheusPrinter(false)
	err := promPrinter.ActionPrint(context.Background(), nil, nil)
	assert.Error(t, err)
}

func TestSetResourcesCountersFromCatalog_DeterministicOrder(t *testing.T) {
	// results is a map, so without an explicit sort the emitted resource
	// metrics follow a randomised iteration order and two runs over the same
	// scan data can produce different report files.
	resources := map[string]workloadinterface.IMetadata{}
	results := map[string]resourcesresults.Result{}
	idToName := map[string]string{}
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("resource-%02d", i)
		wl := workloadinterface.NewWorkloadObj(map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]any{"name": name, "namespace": "default"},
		})
		id := wl.GetID()
		resources[id] = wl
		results[id] = resourcesresults.Result{ResourceID: id}
		idToName[id] = name
	}
	require.Len(t, results, 32)

	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	want := make([]string, 0, len(ids))
	for _, id := range ids {
		want = append(want, idToName[id])
	}

	catalog := cautils.NewMapResourceCatalog(resources)
	for i := 0; i < 50; i++ {
		m := &Metrics{}
		m.setResourcesCountersFromCatalog(catalog, results, &reportsummary.SummaryDetails{})
		got := make([]string, 0, len(m.listResources))
		for _, r := range m.listResources {
			got = append(got, r.name)
		}
		require.Equal(t, want, got, "resource metrics must follow sorted resource ID order")
	}
}

func TestSetImageVulnerabilities_DeterministicSeverityOrder(t *testing.T) {
	severities := []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
	matches := make([]match.Match, 0, len(severities))
	for i, sev := range severities {
		matches = append(matches, match.Match{
			Package: grypepkg.Package{ID: grypepkg.ID(fmt.Sprintf("pkg-%d", i)), Name: "openssl", Version: "1.0.0"},
			Vulnerability: vulnerability.Vulnerability{
				Metadata: &vulnerability.Metadata{ID: fmt.Sprintf("CVE-%d", i), Severity: sev},
			},
		})
	}
	imageData := []cautils.ImageScanData{{
		Image:    "test-image:latest",
		Platform: "linux/amd64",
		Matches:  match.NewMatches(matches...),
	}}

	want := append([]string(nil), severities...)
	sort.Strings(want)

	for i := 0; i < 50; i++ {
		m := &Metrics{}
		m.setImageVulnerabilities(imageData)
		got := make([]string, 0, len(m.listImages))
		for _, img := range m.listImages {
			got = append(got, img.severity)
		}
		require.Equal(t, want, got, "image severities must be emitted in sorted order")
	}
}

// TestSetComplianceScores_DeterministicControlOrder guards against non-deterministic
// Prometheus control metrics. Because summaryDetails.ListControls() traverses an internal
// Go map whose iteration order is randomised, setComplianceScores must sort controls
// by controlID so that identical scan inputs always produce identically ordered metric lines.
func TestSetComplianceScores_DeterministicControlOrder(t *testing.T) {
	controls := reportsummary.ControlSummaries{}
	want := make([]string, 0, 32)
	score := float32(80.0)
	for i := 0; i < 32; i++ {
		controlID := fmt.Sprintf("C-%04d", i)
		controls[controlID] = reportsummary.ControlSummary{
			ControlID:       controlID,
			Name:            fmt.Sprintf("Control %04d", i),
			ScoreFactor:     apis.SeverityHigh,
			ComplianceScore: &score,
		}
		want = append(want, controlID)
	}
	sort.Strings(want)

	summaryDetails := &reportsummary.SummaryDetails{
		Controls: controls,
	}

	for i := 0; i < 50; i++ {
		m := &Metrics{}
		m.setComplianceScores(summaryDetails)
		got := make([]string, 0, len(m.listControls))
		for _, c := range m.listControls {
			got = append(got, c.controlID)
		}
		require.Equal(t, want, got, "control metrics must follow sorted control ID order")
	}
}

// TestSetComplianceScores_DeterministicFrameworkOrder verifies that framework compliance
// metrics are emitted in a deterministic, alphabetically sorted order by framework name.
func TestSetComplianceScores_DeterministicFrameworkOrder(t *testing.T) {
	frameworkNames := []string{"NSA", "MITRE", "CIS", "ArmoBest"}
	frameworks := make([]reportsummary.FrameworkSummary, 0, len(frameworkNames))
	for _, name := range frameworkNames {
		frameworks = append(frameworks, reportsummary.FrameworkSummary{
			Name:            name,
			ComplianceScore: 75.0,
		})
	}

	want := append([]string(nil), frameworkNames...)
	sort.Strings(want)

	summaryDetails := &reportsummary.SummaryDetails{
		Frameworks: frameworks,
	}

	for i := 0; i < 50; i++ {
		m := &Metrics{}
		m.setComplianceScores(summaryDetails)
		got := make([]string, 0, len(m.listFrameworks))
		for _, f := range m.listFrameworks {
			got = append(got, f.frameworkName)
		}
		require.Equal(t, want, got, "framework metrics must follow sorted framework name order")
	}
}

// TestSetImageVulnerabilities_DeterministicMultiImageOrder verifies that container image
// vulnerability metrics across multiple images and platforms are emitted deterministically
// in canonical (image, platform, severity) sorted order.
func TestSetImageVulnerabilities_DeterministicMultiImageOrder(t *testing.T) {
	severities := []string{"Critical", "High"}
	mkMatches := func() []match.Match {
		matches := make([]match.Match, 0, len(severities))
		for i, sev := range severities {
			matches = append(matches, match.Match{
				Package: grypepkg.Package{ID: grypepkg.ID(fmt.Sprintf("pkg-%d", i)), Name: "pkg", Version: "1.0.0"},
				Vulnerability: vulnerability.Vulnerability{
					Metadata: &vulnerability.Metadata{ID: fmt.Sprintf("CVE-%d", i), Severity: sev},
				},
			})
		}
		return matches
	}

	// Supply images in non-sorted order: z-image first, then a-image with different platforms.
	imageData := []cautils.ImageScanData{
		{Image: "z-image:v1", Platform: "linux/amd64", Matches: match.NewMatches(mkMatches()...)},
		{Image: "a-image:v1", Platform: "linux/arm64", Matches: match.NewMatches(mkMatches()...)},
		{Image: "a-image:v1", Platform: "linux/amd64", Matches: match.NewMatches(mkMatches()...)},
	}

	type imgKey struct {
		image    string
		platform string
		severity string
	}
	want := []imgKey{
		{image: "a-image:v1", platform: "linux/amd64", severity: "Critical"},
		{image: "a-image:v1", platform: "linux/amd64", severity: "High"},
		{image: "a-image:v1", platform: "linux/arm64", severity: "Critical"},
		{image: "a-image:v1", platform: "linux/arm64", severity: "High"},
		{image: "z-image:v1", platform: "linux/amd64", severity: "Critical"},
		{image: "z-image:v1", platform: "linux/amd64", severity: "High"},
	}

	for i := 0; i < 50; i++ {
		m := &Metrics{}
		m.setImageVulnerabilities(imageData)
		got := make([]imgKey, 0, len(m.listImages))
		for _, img := range m.listImages {
			got = append(got, imgKey{
				image:    img.image,
				platform: img.platform,
				severity: img.severity,
			})
		}
		require.Equal(t, want, got, "multi-image metrics must follow canonical (image, platform, severity) sorted order")
	}
}
