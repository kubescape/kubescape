package printer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/imageprinter"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mdControlID1  = "C-0057"
	mdControlID2  = "C-0058"
	mdResourceID1 = "apps/v1/Deployment/default/nginx"
	mdResourceID2 = "apps/v1/Deployment/cache/redis"
)

func mdSessionFixture() *cautils.OPASessionObj {
	lw1 := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "nginx", "namespace": "default"},
		"spec":       map[string]interface{}{},
	})
	lw2 := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "redis", "namespace": "cache"},
		"spec":       map[string]interface{}{},
	})

	session := cautils.NewOPASessionObjMock()
	session.AllResources[mdResourceID1] = lw1
	session.AllResources[mdResourceID2] = lw2

	session.ResourcesResult[mdResourceID1] = resourcesresults.Result{
		ResourceID: mdResourceID1,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: mdControlID1, Name: "Privileged container", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
			{ControlID: mdControlID2, Name: "Run as root", Status: apis.StatusInfo{InnerStatus: apis.StatusPassed}},
		},
	}
	session.ResourcesResult[mdResourceID2] = resourcesresults.Result{
		ResourceID: mdResourceID2,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: mdControlID1, Name: "Privileged container", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}

	failedStatus := &apis.StatusInfo{InnerStatus: apis.StatusFailed}
	passedStatus := &apis.StatusInfo{InnerStatus: apis.StatusPassed}

	ctrl1 := &reportsummary.ControlSummary{
		ControlID:   mdControlID1,
		Name:        "Privileged container",
		ScoreFactor: 9.0,
		Remediation: "Remove privilegedContainer: true from your pod spec",
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	ctrl1.Append(failedStatus, mdResourceID1, mdResourceID2)

	ctrl2 := &reportsummary.ControlSummary{
		ControlID:   mdControlID2,
		Name:        "Run as root",
		ScoreFactor: 5.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}
	ctrl2.Append(passedStatus, mdResourceID1)

	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 42,
			Controls: reportsummary.ControlSummaries{
				mdControlID1: *ctrl1,
				mdControlID2: *ctrl2,
			},
		},
	}

	return session
}

func mdRunActionPrint(t *testing.T, session *cautils.OPASessionObj) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "kubescape-md-*.md")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	mp := NewMarkdownPrinter()
	mp.writer = tmp
	err = mp.ActionPrint(context.TODO(), session, nil)
	require.NoError(t, err)
	mp.CloseWriter()

	content, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return string(content)
}

func mdImageMatch(id, severity, packageName, version string, fixState vulnerability.FixState, fixVersions ...string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: id, Namespace: "nvd"},
			Metadata:  &vulnerability.Metadata{ID: id, Severity: severity},
			Fix: vulnerability.Fix{
				Versions: fixVersions,
				State:    fixState,
			},
		},
		Package: grypepkg.Package{
			ID:      grypepkg.ID(packageName + "@" + version),
			Name:    packageName,
			Version: version,
		},
	}
}

func mdRunImageActionPrint(t *testing.T, imageScanData []cautils.ImageScanData) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "kubescape-image-md-*.md")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmp.Name()) })

	mp := NewMarkdownPrinter()
	mp.writer = tmp
	err = mp.ActionPrint(context.TODO(), nil, imageScanData)
	require.NoError(t, err)
	mp.CloseWriter()

	content, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	return string(content)
}

func TestNewMarkdownPrinter(t *testing.T) {
	mp := NewMarkdownPrinter()
	assert.NotNil(t, mp)
}

func TestMarkdownPrinter_SetWriter_DefaultFile(t *testing.T) {
	tmpDir := t.TempDir()

	mp := NewMarkdownPrinter()
	mp.SetWriter(context.TODO(), filepath.Join(tmpDir, "report"))
	require.NotNil(t, mp.writer)
	name := mp.writer.Name()
	assert.True(t, strings.HasSuffix(name, ".md"), "expected .md extension, got %s", name)
	mp.CloseWriter()
}

func TestMarkdownPrinter_SetWriter_AppendExtension(t *testing.T) {
	tmp, err := os.CreateTemp("", "md-test-report")
	require.NoError(t, err)
	tmp.Close()
	os.Remove(tmp.Name())

	mp := NewMarkdownPrinter()
	mp.SetWriter(context.TODO(), tmp.Name())
	require.NotNil(t, mp.writer)
	assert.True(t, strings.HasSuffix(mp.writer.Name(), ".md"))
	mp.CloseWriter()
	os.Remove(mp.writer.Name())
}

func TestMarkdownPrinter_SetWriter_ExistingMdExtension(t *testing.T) {
	tmp, err := os.CreateTemp("", "md-test-*.md")
	require.NoError(t, err)
	base := tmp.Name()
	tmp.Close()
	os.Remove(base)

	mp := NewMarkdownPrinter()
	mp.SetWriter(context.TODO(), base)
	require.NotNil(t, mp.writer)
	assert.True(t, strings.HasSuffix(mp.writer.Name(), ".md"))
	assert.False(t, strings.HasSuffix(mp.writer.Name(), ".md.md"), "extension must not be doubled")
	mp.CloseWriter()
	os.Remove(mp.writer.Name())
}

func TestMarkdownPrinter_Score(t *testing.T) {
	mp := NewMarkdownPrinter()
	assert.NotPanics(t, func() { mp.Score(72) })
}

func TestMarkdownPrinter_PrintNextSteps(t *testing.T) {
	mp := NewMarkdownPrinter()
	assert.NotPanics(t, func() { mp.PrintNextSteps() })
}

func TestMarkdownPrinter_SetWriter_ReturnsExplicitSetupError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	target := filepath.Join(blocker, "report.md")
	mp := NewMarkdownPrinter()
	err := mp.SetWriter(context.TODO(), target)

	require.Error(t, err)
	assert.Nil(t, mp.writer)
	assert.NoFileExists(t, target)
}

func TestMarkdownPrinter_ActionPrint_NilSession(t *testing.T) {
	mp := NewMarkdownPrinter()
	mp.writer = os.Stdout
	err := mp.ActionPrint(context.TODO(), nil, nil)
	assert.NoError(t, err)
}

func TestMarkdownPrinter_ActionPrint_NilReport(t *testing.T) {
	mp := NewMarkdownPrinter()
	mp.writer = os.Stdout
	session := cautils.NewOPASessionObjMock()
	session.Report = nil
	err := mp.ActionPrint(context.TODO(), session, nil)
	assert.NoError(t, err, "nil Report must not panic")
}

func TestMarkdownPrinter_ActionPrint_Header(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.True(t, strings.HasPrefix(out, "# Kubescape Security Report"), "must start with h1 heading")
	assert.Contains(t, out, "**Compliance Score:** 42%", "compliance score must appear with percentage")
}

func TestMarkdownPrinter_ActionPrint_SummaryTablePresent(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.Contains(t, out, "## Summary")
	assert.Contains(t, out, "| Severity | Control | ID | Status | Failed | Passed |")
	assert.Contains(t, out, "|---|---|---|---|---|---|")
	assert.Contains(t, out, "Privileged container")
	assert.Contains(t, out, mdControlID1)
	assert.Contains(t, out, "Run as root")
	assert.Contains(t, out, mdControlID2)
}

func TestMarkdownPrinter_ActionPrint_StatusEmojis(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.Contains(t, out, "❌ Failed", "failed status emoji missing")
	assert.Contains(t, out, "✅ Passed", "passed status emoji missing")
}

func TestMarkdownPrinter_ActionPrint_SeverityOrder(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	criticalPos := strings.Index(out, "Critical")
	mediumPos := strings.Index(out, "Medium")
	assert.Greater(t, mediumPos, criticalPos, "Critical must appear before Medium in the table")
}

func TestMarkdownPrinter_ActionPrint_FailedSection(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.Contains(t, out, "## Failed Controls")
	assert.Contains(t, out, "### Privileged container")
	assert.Contains(t, out, "Remove privilegedContainer: true from your pod spec", "remediation text missing")
	assert.Contains(t, out, "[View documentation]", "control URL link missing")
	assert.Contains(t, out, "hub.armosec.io/docs/c-0057", "control URL must include lowercase ID")
}

func TestMarkdownPrinter_ActionPrint_ResourceTable(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.Contains(t, out, "| Resource | Kind | Namespace |")
	assert.Contains(t, out, "|---|---|---|")
	assert.Contains(t, out, "| nginx |")
	assert.Contains(t, out, "| redis |")
	assert.Contains(t, out, "| default |", "namespace column missing for nginx")
	assert.Contains(t, out, "| cache |", "namespace column missing for redis")
}

func TestMarkdownPrinter_ActionPrint_PassedControlNoSection(t *testing.T) {
	out := mdRunActionPrint(t, mdSessionFixture())

	assert.NotContains(t, out, "### Run as root", "passed controls must not appear in Failed Controls section")
}

func TestMarkdownPrinter_ActionPrint_AllPassedNoFailedSection(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 100,
			Controls: reportsummary.ControlSummaries{
				mdControlID2: reportsummary.ControlSummary{
					ControlID:  mdControlID2,
					Name:       "Run as root",
					StatusInfo: apis.StatusInfo{InnerStatus: apis.StatusPassed},
				},
			},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "## Summary")
	assert.NotContains(t, out, "## Failed Controls", "no Failed Controls section when everything passes")
}

func TestMarkdownPrinter_ActionPrint_EmptyControls(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 0,
			Controls:        reportsummary.ControlSummaries{},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "# Kubescape Security Report")
	assert.Contains(t, out, "**Compliance Score:** 0%")
	assert.Contains(t, out, "## Summary")
}

func TestMarkdownPrinter_ActionPrint_NegativeScoreRendersNA(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: -1,
			Controls:        reportsummary.ControlSummaries{},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "# Kubescape Security Report")
	assert.Contains(t, out, "**Compliance Score:** N/A")
	assert.NotContains(t, out, "**Compliance Score:** -1")
}

func TestMarkdownPrinter_ActionPrint_PerfectScoreRenders100Percent(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 100,
			Controls:        reportsummary.ControlSummaries{},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "# Kubescape Security Report")
	assert.Contains(t, out, "**Compliance Score:** 100%")
}

func TestMarkdownPrinter_ActionPrint_FractionalScoreRendersPercentage(t *testing.T) {
	session := cautils.NewOPASessionObjMock()
	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 99.5,
			Controls:        reportsummary.ControlSummaries{},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "# Kubescape Security Report")
	assert.Contains(t, out, "**Compliance Score:** 99%")
}

func TestMdSortedControls(t *testing.T) {
	controls := reportsummary.ControlSummaries{
		"C-0001": reportsummary.ControlSummary{ControlID: "C-0001", Name: "Beta", ScoreFactor: 5.0},
		"C-0002": reportsummary.ControlSummary{ControlID: "C-0002", Name: "Alpha", ScoreFactor: 9.0},
		"C-0003": reportsummary.ControlSummary{ControlID: "C-0003", Name: "Gamma", ScoreFactor: 5.0},
	}

	sorted := mdSortedControls(controls)

	require.Len(t, sorted, 3)
	assert.Equal(t, "C-0002", sorted[0].GetID(), "critical must be first")
	assert.Equal(t, "C-0001", sorted[1].GetID(), "medium Beta before Gamma alphabetically")
	assert.Equal(t, "C-0003", sorted[2].GetID(), "medium Gamma last")
}

func TestMdSortedControls_Empty(t *testing.T) {
	sorted := mdSortedControls(reportsummary.ControlSummaries{})
	assert.Empty(t, sorted)
}

func TestMdSortedControls_SameScore(t *testing.T) {
	controls := reportsummary.ControlSummaries{
		"C-Z": reportsummary.ControlSummary{ControlID: "C-Z", Name: "Zeta", ScoreFactor: 5.0},
		"C-A": reportsummary.ControlSummary{ControlID: "C-A", Name: "Alpha", ScoreFactor: 5.0},
		"C-M": reportsummary.ControlSummary{ControlID: "C-M", Name: "Mu", ScoreFactor: 5.0},
	}

	sorted := mdSortedControls(controls)

	require.Len(t, sorted, 3)
	assert.Equal(t, "Alpha", sorted[0].GetName())
	assert.Equal(t, "Mu", sorted[1].GetName())
	assert.Equal(t, "Zeta", sorted[2].GetName())
}

func TestMdStatusLabel(t *testing.T) {
	cases := []struct {
		status apis.IStatus
		want   string
	}{
		{&apis.StatusInfo{InnerStatus: apis.StatusFailed}, "❌ Failed"},
		{&apis.StatusInfo{InnerStatus: apis.StatusPassed}, "✅ Passed"},
		{&apis.StatusInfo{InnerStatus: apis.StatusSkipped}, "⏭ Skipped"},
		{&apis.StatusInfo{InnerStatus: apis.StatusUnknown}, string(apis.StatusUnknown)},
		{nil, "Unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, mdStatusLabel(tc.status))
		})
	}
}

func TestMdEscapeCell(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"with|pipe", "with\\|pipe"},
		{"multi|pipe|in|cell", "multi\\|pipe\\|in\\|cell"},
		{"", ""},
		{"no special chars", "no special chars"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, mdEscapeCell(tc.input))
		})
	}
}

func TestMarkdownPrinter_ActionPrint_ResourceNameWithPipe(t *testing.T) {
	lw := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "my|deployment", "namespace": "default"},
		"spec":       map[string]interface{}{},
	})

	session := cautils.NewOPASessionObjMock()
	session.AllResources[mdResourceID1] = lw

	ctrl := &reportsummary.ControlSummary{
		ControlID:   mdControlID1,
		Name:        "Privileged container",
		ScoreFactor: 9.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	ctrl.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, mdResourceID1)

	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{
				mdControlID1: *ctrl,
			},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "my\\|deployment", "pipe in resource name must be escaped")
}

func TestMarkdownPrinter_ActionPrint_ImageScanReport(t *testing.T) {
	imageScanData := mdImageScanDataFixture()

	out := mdRunImageActionPrint(t, imageScanData)

	assert.True(t, strings.HasPrefix(out, "# Kubescape Image Scan Report"))
	assert.Contains(t, out, "**Images:** 2")
	assert.Contains(t, out, "**Vulnerability DB Built:** 2026-08-25T10:30:00Z")
	assert.Contains(t, out, "## Images")
	assert.Contains(t, out, "`registry.example.com/app:v1 [linux/amd64]`")
	assert.Contains(t, out, "`registry.example.com/app:v1 [linux/arm64]`")

	assert.Contains(t, out, "## Vulnerability Summary")
	assert.Contains(t, out, "| Critical | 1 | 1 |")
	assert.Contains(t, out, "| High | 1 | 0 |")
	assert.Contains(t, out, "| Medium | 1 | 0 |")
	assert.Contains(t, out, "| **Total** | **3** | **1** |")

	assert.Contains(t, out, "## Affected Packages")
	assert.Contains(t, out, "| openssl | 1.0.0 |")
	assert.Contains(t, out, "| glibc | 2.39 |")
	assert.Contains(t, out, "| busybox | 1.36.0 |")

	assert.Contains(t, out, "## Vulnerabilities")
	assert.Contains(t, out, "| Critical | CVE-2026-0001 | openssl | 1.0.0 | 1.0.1, 1.0.2 | `registry.example.com/app:v1 [linux/amd64]` |")
	assert.Contains(t, out, "| High | CVE-2026-0003 | glibc | 2.39 | wont-fix | `registry.example.com/app:v1 [linux/arm64]` |")
	assert.Contains(t, out, "| Medium | CVE-2026-0002 | busybox | 1.36.0 |  | `registry.example.com/app:v1 [linux/amd64]` |")
}

func TestMarkdownPrinter_ActionPrint_ImageScanGolden(t *testing.T) {
	out := mdRunImageActionPrint(t, mdImageScanDataFixture())
	want, err := os.ReadFile(filepath.Join("testdata", "markdown_image_scan.md"))
	require.NoError(t, err)
	assert.Equal(t, string(want), out)
}

func mdImageScanDataFixture() []cautils.ImageScanData {
	dbBuilt := time.Date(2026, 8, 25, 10, 30, 0, 0, time.UTC)
	return []cautils.ImageScanData{
		{
			Image:       "registry.example.com/app:v1",
			Platform:    "linux/amd64",
			VulnDBBuilt: &dbBuilt,
			Matches: match.NewMatches(
				mdImageMatch("CVE-2026-0001", "Critical", "openssl", "1.0.0", vulnerability.FixStateFixed, "1.0.1", "1.0.2"),
				mdImageMatch("CVE-2026-0002", "Medium", "busybox", "1.36.0", vulnerability.FixStateNotFixed),
			),
		},
		{
			Image:    "registry.example.com/app:v1",
			Platform: "linux/arm64",
			Matches: match.NewMatches(
				mdImageMatch("CVE-2026-0003", "High", "glibc", "2.39", vulnerability.FixStateWontFix),
			),
		},
	}
}

func TestMarkdownPrinter_ActionPrint_ImageScanNoVulnerabilities(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		{
			Image:   "registry.example.com/clean:v1",
			Matches: match.NewMatches(),
		},
	}

	out := mdRunImageActionPrint(t, imageScanData)

	assert.Contains(t, out, "# Kubescape Image Scan Report")
	assert.Contains(t, out, "**Image:** `registry.example.com/clean:v1`")
	assert.Contains(t, out, "| `registry.example.com/clean:v1` |")
	assert.Contains(t, out, "| **Total** | **0** | **0** |")
	assert.Contains(t, out, "No affected packages were found.")
	assert.Contains(t, out, "No vulnerabilities were found.")
}

func TestMarkdownPrinter_ActionPrint_ImageScanEscapesTableCells(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		{
			Image:    "registry.example.com/app|with-pipe:v1",
			Platform: "linux/amd64",
			Matches: match.NewMatches(
				mdImageMatch("CVE-2026-PIPE", "High", "pkg|name", "1|2", vulnerability.FixStateFixed, "3|4"),
			),
		},
	}

	out := mdRunImageActionPrint(t, imageScanData)

	assert.Contains(t, out, "`registry.example.com/app\\|with-pipe:v1 [linux/amd64]`")
	assert.Contains(t, out, "| High | CVE-2026-PIPE | pkg\\|name | 1\\|2 | 3\\|4 | `registry.example.com/app\\|with-pipe:v1 [linux/amd64]` |")
}

func TestMdWriteImageSeveritySummarySortsBySeverity(t *testing.T) {
	var out strings.Builder
	err := mdWriteImageSeveritySummary(&out, map[string]*imageprinter.SeveritySummary{
		"Low":      {NumberOfCVEs: 1},
		"Critical": {NumberOfCVEs: 2, NumberOfFixableCVEs: 1},
		"Medium":   {NumberOfCVEs: 3},
		"High":     {NumberOfCVEs: 4},
	})
	require.NoError(t, err)

	text := out.String()
	assert.Less(t, strings.Index(text, "Critical"), strings.Index(text, "High"))
	assert.Less(t, strings.Index(text, "High"), strings.Index(text, "Medium"))
	assert.Less(t, strings.Index(text, "Medium"), strings.Index(text, "Low"))
	assert.Contains(t, text, "| **Total** | **10** | **1** |")
}

func TestMdSortedImagePackages(t *testing.T) {
	packages := map[string]*imageprinter.PackageScore{
		"b": {Name: "b", Version: "1", Score: 2},
		"a": {Name: "a", Version: "2", Score: 5},
		"c": {Name: "a", Version: "1", Score: 5},
	}

	got := mdSortedImagePackages(packages)

	require.Len(t, got, 3)
	assert.Equal(t, "a", got[0].Name)
	assert.Equal(t, "1", got[0].Version)
	assert.Equal(t, "a", got[1].Name)
	assert.Equal(t, "2", got[1].Version)
	assert.Equal(t, "b", got[2].Name)
}

func TestMdSortedImageCVEs(t *testing.T) {
	cves := []imageprinter.CVE{
		{ID: "CVE-Z", Severity: "Low", Package: "pkg", Image: "image"},
		{ID: "CVE-B", Severity: "Critical", Package: "pkg", Image: "image"},
		{ID: "CVE-A", Severity: "Critical", Package: "pkg", Image: "image"},
		{ID: "CVE-M", Severity: "High", Package: "pkg", Image: "image"},
	}

	got := mdSortedImageCVEs(cves)

	require.Len(t, got, 4)
	assert.Equal(t, "CVE-A", got[0].ID)
	assert.Equal(t, "CVE-B", got[1].ID)
	assert.Equal(t, "CVE-M", got[2].ID)
	assert.Equal(t, "CVE-Z", got[3].ID)
}

func TestMdUnknownSeverityCount(t *testing.T) {
	got := mdUnknownSeverityCount(map[string]int{
		"Critical":   1,
		"High":       2,
		"Negligible": 3,
		"Unknown":    4,
	})

	assert.Equal(t, 7, got)
}

func TestMdFixedIn(t *testing.T) {
	cases := []struct {
		name string
		cve  imageprinter.CVE
		want string
	}{
		{
			name: "fixed with versions",
			cve:  imageprinter.CVE{FixedState: "fixed", FixVersions: []string{"1.0.1", "1.0.2"}},
			want: "1.0.1, 1.0.2",
		},
		{
			name: "fixed without versions",
			cve:  imageprinter.CVE{FixedState: "fixed"},
			want: "fixed",
		},
		{
			name: "wont fix",
			cve:  imageprinter.CVE{FixedState: "wont-fix"},
			want: "wont-fix",
		},
		{
			name: "not fixed",
			cve:  imageprinter.CVE{FixedState: "not-fixed"},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mdFixedIn(tc.cve))
		})
	}
}
