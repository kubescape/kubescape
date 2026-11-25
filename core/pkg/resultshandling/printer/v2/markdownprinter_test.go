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

// mdWithExploitData adds CISA KEV and EPSS data to a match built by mdImageMatch.
func mdWithExploitData(m match.Match, kev bool, epss, percentile float64) match.Match {
	if kev {
		m.Vulnerability.Metadata.KnownExploited = []vulnerability.KnownExploited{{CVE: m.Vulnerability.ID}}
	}
	m.Vulnerability.Metadata.EPSS = []vulnerability.EPSS{{CVE: m.Vulnerability.ID, EPSS: epss, Percentile: percentile}}
	return m
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

func TestMarkdownPrinter_ActionPrint_NilReportImageScanFallback(t *testing.T) {
	tmp, err := os.CreateTemp("", "md-nil-report-*.md")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tmp.Close())
		assert.NoError(t, os.Remove(tmp.Name()))
	}()

	mp := NewMarkdownPrinter()
	mp.writer = tmp
	session := &cautils.OPASessionObj{Report: nil}
	require.NoError(t, mp.ActionPrint(context.TODO(), session, mdImageScanDataFixture()))

	raw, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	assert.Contains(t, string(raw), "# Kubescape Image Scan Report")
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

func TestMarkdownPrinter_ActionPrint_MultilineRemediationStaysQuoted(t *testing.T) {
	session := mdSessionFixture()
	ctrl := session.Report.SummaryDetails.Controls[mdControlID1]
	ctrl.Remediation = "Run the following command\n\n \n```\nchmod 600 /var/lib/kubelet/config.yaml\n\n```"
	session.Report.SummaryDetails.Controls[mdControlID1] = ctrl

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "> **Remediation:** Run the following command\n>\n>\n> ```\n> chmod 600 /var/lib/kubelet/config.yaml\n>\n> ```\n\n[View documentation]")
}

func TestMarkdownPrinter_ActionPrint_BlankRemediationOmitted(t *testing.T) {
	session := mdSessionFixture()
	ctrl := session.Report.SummaryDetails.Controls[mdControlID1]
	ctrl.Remediation = " \n\t"
	session.Report.SummaryDetails.Controls[mdControlID1] = ctrl

	assert.NotContains(t, mdRunActionPrint(t, session), "**Remediation:**")
}

func TestMdBlockquote(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"single line", "fix it", "> fix it"},
		{"paragraphs", "first\n\nsecond", "> first\n>\n> second"},
		{"crlf", "first\r\nsecond\r\n", "> first\n> second"},
		{"whitespace-only line", "first\n\t \nsecond", "> first\n>\n> second"},
		{"hard line break", "First step  \nSecond step", "> First step  \n> Second step"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mdBlockquote(tc.input))
		})
	}
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

func TestMarkdownPrinter_ActionPrint_FractionalNegativeScoreRendersNA(t *testing.T) {
	for _, score := range []float32{-0.5, -0.25, -0.1} {
		session := cautils.NewOPASessionObjMock()
		session.Report = &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				ComplianceScore: score,
				Controls:        reportsummary.ControlSummaries{},
			},
		}

		out := mdRunActionPrint(t, session)

		assert.Contains(t, out, "# Kubescape Security Report")
		assert.Contains(t, out, "**Compliance Score:** N/A")
		assert.NotContains(t, out, "**Compliance Score:** 0%")
	}
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
		{"with\x00null", "withnull"},
		{"with\x1bescape", "withescape"},
		{"with\x07bell", "withbell"},
		{"with\x7fdel", "withdel"},
		{"with\ttab", "with\ttab"},
		{"with\u0080pad", "withpad"},
		{"with\u0085nel", "withnel"},
		{"with\u009bcsi", "withcsi"},
		{"with\u009fapc", "withapc"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, mdEscapeCell(tc.input))
		})
	}
}

func TestMdSanitizeText(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"normal text", "hello world", "hello world"},
		{"collapses newlines and carriage returns", "line1\r\nline2\nline3\rline4", "line1 line2 line3 line4"},
		{"trims surrounding whitespace", "   spaced text   \n", "spaced text"},
		{"strips C0 control characters but preserves tab", "col1\t\x00val\x07\x1b", "col1\tval"},
		{"strips C1 control characters (0x80-0x9f)", "foo\u0080bar\u0085baz\u009bqux\u009f", "foobarbazqux"},
		{"preserves printable non-ASCII characters", "latin: \u00a0 café — \u4e16\u754c", "latin: \u00a0 café — \u4e16\u754c"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeText(tc.input))
		})
	}
}

func TestMdEscapeCodeCell(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"with|pipe", "with\\|pipe"},
		{"image`with`backticks", "image'with'backticks"},
		{"image|with|pipe`and`ticks\r\n", "image\\|with\\|pipe'and'ticks"},
		{"\x1b[31mimage`tag`\x00", "[31mimage'tag'"},
		{"image\u0085with\u009bC1`and`pipe|", "imagewithC1'and'pipe\\|"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, mdEscapeCodeCell(tc.input))
		})
	}
}

func TestMdEscapeInline(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"image:v1", "image:v1"},
		{"image`tag", "image'tag"},
		{"C-0099|local", "C-0099|local"},
		{"img`with`backtick\nand\r\nnewlines", "img'with'backtick and newlines"},
		{"\x00bad`inline\x1b", "bad'inline"},
		{"\u0080bad`inline\u009b", "bad'inline"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, mdEscapeInline(tc.input))
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
	assert.Contains(t, out, "| Severity | Vulnerability | KEV | EPSS | Package | Version | Fixed In | Image |")
	assert.Contains(t, out, "| Critical | CVE-2026-0001 |  | < 0.1% (12th) | openssl | 1.0.0 | 1.0.1, 1.0.2 | `registry.example.com/app:v1 [linux/amd64]` |")
	assert.Contains(t, out, "| High | CVE-2026-0003 |  | N/A | glibc | 2.39 | wont-fix | `registry.example.com/app:v1 [linux/arm64]` |")
	assert.Contains(t, out, "| Medium | CVE-2026-0002 | yes | 63.9% (99th) | busybox | 1.36.0 |  | `registry.example.com/app:v1 [linux/amd64]` |")

	kev := strings.Index(out, "| Medium | CVE-2026-0002 |")
	critical := strings.Index(out, "| Critical | CVE-2026-0001 |")
	high := strings.Index(out, "| High | CVE-2026-0003 |")
	assert.True(t, kev < critical && critical < high, "KEV findings must be listed first, then by severity")
}

func TestMarkdownPrinter_ActionPrint_ImageScanGolden(t *testing.T) {
	out := mdRunImageActionPrint(t, mdImageScanDataFixture())
	want, err := os.ReadFile(filepath.Join("testdata", "markdown_image_scan.md"))
	require.NoError(t, err)
	wantStr := strings.ReplaceAll(string(want), "\r\n", "\n")
	assert.Equal(t, wantStr, out)
}

func mdImageScanDataFixture() []cautils.ImageScanData {
	dbBuilt := time.Date(2026, 8, 25, 10, 30, 0, 0, time.UTC)
	return []cautils.ImageScanData{
		{
			Image:       "registry.example.com/app:v1",
			Platform:    "linux/amd64",
			VulnDBBuilt: &dbBuilt,
			Matches: match.NewMatches(
				mdWithExploitData(mdImageMatch("CVE-2026-0001", "Critical", "openssl", "1.0.0", vulnerability.FixStateFixed, "1.0.1", "1.0.2"), false, 0.0004, 0.12),
				mdWithExploitData(mdImageMatch("CVE-2026-0002", "Medium", "busybox", "1.36.0", vulnerability.FixStateNotFixed), true, 0.63894, 0.99215),
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
	assert.Contains(t, out, "| High | CVE-2026-PIPE |  | N/A | pkg\\|name | 1\\|2 | 3\\|4 | `registry.example.com/app\\|with-pipe:v1 [linux/amd64]` |")
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

func TestMarkdownPrinter_ActionPrint_CombinedPostureAndImageScan(t *testing.T) {
	ctx := context.Background()
	tmp, err := os.CreateTemp("", "kubescape-md-combined-*.md")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmp.Name()) })

	mp := NewMarkdownPrinter()
	mp.writer = tmp

	session := mdSessionFixture()
	imageScanData := []cautils.ImageScanData{
		{
			Image: "registry.example.com/combined:v1",
		},
	}

	err = mp.ActionPrint(ctx, session, imageScanData)
	require.NoError(t, err)
	require.NoError(t, mp.CloseWriter())

	content, err := os.ReadFile(tmp.Name())
	require.NoError(t, err)
	text := string(content)

	assert.Contains(t, text, "# Kubescape Security Report", "must contain posture report heading")
	assert.Contains(t, text, "# Kubescape Image Scan Report", "must contain image scan report heading")
	assert.Contains(t, text, "`registry.example.com/combined:v1`", "must contain scanned image name")
}

func TestMarkdownPrinter_ActionPrint_CoverageSectionPresent(t *testing.T) {
	session := mdSessionFixture()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     85.0,
		EvaluatedControls: 17,
		TotalControls:     20,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID:   "C-0099",
				MissingGVRs: []string{"apps/v1/daemonsets"},
			},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "## Scan Coverage")
	assert.Contains(t, out, "**Coverage Score:** 85% ⚠️ Degraded")
	assert.Contains(t, out, "Evaluated 17 of 20 controls")
	assert.Contains(t, out, "| Control ID | Name | Reason |")
	assert.Contains(t, out, "| C-0099 | C-0099 | missing: apps/v1/daemonsets |")
}

func TestMarkdownPrinter_ActionPrint_CoverageSectionOmittedWhenPerfect(t *testing.T) {
	session := mdSessionFixture()
	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     100.0,
		EvaluatedControls: 20,
		TotalControls:     20,
		Degraded:          false,
	}

	out := mdRunActionPrint(t, session)

	assert.NotContains(t, out, "## Scan Coverage")
}

func TestMarkdownPrinter_ActionPrint_CoverageSkippedControlsWithReasons(t *testing.T) {
	session := mdSessionFixture()
	skippedStatus := &apis.StatusInfo{
		InnerStatus: apis.StatusSkipped,
		SubStatus:   apis.SubStatusIrrelevant,
		InnerInfo:   "no matching resources in cluster",
	}
	ctrlSkipped := &reportsummary.ControlSummary{
		ControlID:   "C-0070",
		Name:        "Host IPC",
		ScoreFactor: 6.0,
		StatusInfo:  *skippedStatus,
	}
	ctrlSkipped.Append(skippedStatus, mdResourceID1)
	session.Report.SummaryDetails.Controls["C-0070"] = *ctrlSkipped

	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     90.0,
		EvaluatedControls: 9,
		TotalControls:     10,
		Degraded:          true,
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "## Scan Coverage")
	assert.Contains(t, out, "C-0070")
	assert.Contains(t, out, "Host IPC")
	assert.Contains(t, out, "irrelevant: no matching resources in cluster")
}

func TestMdSortedControls_DeterministicTieBreakByID(t *testing.T) {
	controls := reportsummary.ControlSummaries{
		"C-0099": {
			ControlID:   "C-0099",
			Name:        "Duplicate Name",
			ScoreFactor: 9.0,
		},
		"C-0010": {
			ControlID:   "C-0010",
			Name:        "Duplicate Name",
			ScoreFactor: 9.0,
		},
		"C-0050": {
			ControlID:   "C-0050",
			Name:        "Duplicate Name",
			ScoreFactor: 9.0,
		},
		"C-0001": {
			ControlID:   "C-0001",
			Name:        "Another Duplicate",
			ScoreFactor: 9.0,
		},
		// Same ID, Name, Severity, but different map keys
		"z-custom-key": {
			ControlID:   "C-9999",
			Name:        "Identical Everything",
			ScoreFactor: 5.0,
			Remediation: "z-key-remediation",
		},
		"a-custom-key": {
			ControlID:   "C-9999",
			Name:        "Identical Everything",
			ScoreFactor: 5.0,
			Remediation: "a-key-remediation",
		},
	}

	for i := 0; i < 20; i++ {
		sorted := mdSortedControls(controls)
		require.Len(t, sorted, 6)
		// "Another Duplicate" comes first alphabetically
		assert.Equal(t, "C-0001", sorted[0].GetID())
		// The three "Duplicate Name" controls break tie by ID ascending
		assert.Equal(t, "C-0010", sorted[1].GetID())
		assert.Equal(t, "C-0050", sorted[2].GetID())
		assert.Equal(t, "C-0099", sorted[3].GetID())
		// "Identical Everything" (score 5) breaks tie by map key: "a-custom-key" before "z-custom-key"
		assert.Equal(t, "a-key-remediation", sorted[4].GetRemediation())
		assert.Equal(t, "z-key-remediation", sorted[5].GetRemediation())
	}
}

func TestMdEscapeCell_NeutralizesLineBreaks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain string without special characters",
			input: "clean-value",
			want:  "clean-value",
		},
		{
			name:  "escapes pipe character",
			input: "foo|bar",
			want:  "foo\\|bar",
		},
		{
			name:  "neutralizes CRLF into space",
			input: "line1\r\nline2",
			want:  "line1 line2",
		},
		{
			name:  "neutralizes LF into space",
			input: "line1\nline2",
			want:  "line1 line2",
		},
		{
			name:  "neutralizes CR into space",
			input: "line1\rline2",
			want:  "line1 line2",
		},
		{
			name:  "neutralizes combination of pipes and newlines with surrounding whitespace",
			input: "  prefix|middle\r\n## Heading\n[link](https://evil.com)  ",
			want:  "prefix\\|middle ## Heading [link](https://evil.com)",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, mdEscapeCell(tt.input))
		})
	}
}

func TestMarkdownPrinter_ActionPrint_NeutralizesNewlinesInTableCells(t *testing.T) {
	session := mdSessionFixture()

	// Inject a resource name containing a newline and markdown heading injection
	injectedResourceID := "apps/v1/Deployment/default/injected"
	injectedWorkload := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment\n| evil | evil |",
		"metadata": map[string]interface{}{
			"name":      "nginx\n\n## Injected Heading\n[Malicious](https://example.com)",
			"namespace": "default\r\ninjected-ns",
		},
		"spec": map[string]interface{}{},
	})
	session.AllResources[injectedResourceID] = injectedWorkload
	session.ResourcesResult[injectedResourceID] = resourcesresults.Result{
		ResourceID: injectedResourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: mdControlID1, Name: "Privileged container", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}
	failedStatus := &apis.StatusInfo{InnerStatus: apis.StatusFailed}
	ctrl := session.Report.SummaryDetails.Controls[mdControlID1]
	ctrl.Append(failedStatus, injectedResourceID)
	session.Report.SummaryDetails.Controls[mdControlID1] = ctrl

	out := mdRunActionPrint(t, session)

	// Verify that table cells do not break out into newlines
	assert.NotContains(t, out, "\n## Injected Heading\n", "newline injection must not produce a freestanding heading")
	assert.Contains(t, out, "nginx  ## Injected Heading [Malicious](https://example.com)", "newlines within resource name must be collapsed into spaces")
	assert.Contains(t, out, "Deployment \\| evil \\| evil \\|", "pipe characters and newlines within kind must be safely escaped")
	assert.Contains(t, out, "default injected-ns", "CRLF in namespace must be collapsed into space")
}

func TestMarkdownPrinter_ActionPrint_NeutralizesNewlinesInControlIDs(t *testing.T) {
	session := mdSessionFixture()

	injectedControlID := "C-0099\r\n| evil |"
	ctrl := reportsummary.ControlSummary{
		ControlID:   injectedControlID,
		Name:        "Injected Control Name",
		ScoreFactor: 1.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}
	session.Report.SummaryDetails.Controls[injectedControlID] = ctrl

	session.ScanCoverage = cautils.ScanCoverage{
		CoverageScore:     80,
		TotalControls:     10,
		EvaluatedControls: 8,
		Degraded:          true,
		NotEvaluatedControls: []cautils.NotEvaluatedControl{
			{
				ControlID: "C-0088\r\n| leaked",
			},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.NotContains(t, out, "C-0099\r\n")
	assert.NotContains(t, out, "C-0088\r\n")
	assert.Contains(t, out, "C-0099 \\| evil \\|")
	assert.Contains(t, out, "C-0088 \\| leaked")
}

func TestMarkdownPrinter_ActionPrint_ImageScanBacktickAndControlSanitization(t *testing.T) {
	imageScanData := []cautils.ImageScanData{
		{
			Image:    "registry.example.com/app`evil`\x1b[31m|pipe:v1",
			Platform: "linux/amd64",
			Matches: match.NewMatches(
				mdImageMatch("CVE-2026-TICK", "High", "pkg`name", "1.0", vulnerability.FixStateFixed, "2.0"),
			),
		},
	}

	out := mdRunImageActionPrint(t, imageScanData)

	// Image targets table: backticks neutralized to single quotes and control characters stripped
	assert.Contains(t, out, "`registry.example.com/app'evil'[31m\\|pipe:v1 [linux/amd64]`")
	assert.NotContains(t, out, "`registry.example.com/app`evil`")
	assert.NotContains(t, out, "\x1b")

	// Vulnerabilities table: scoped to the vulnerabilities section so the Images table cannot satisfy it
	vulnIdx := strings.Index(out, "## Vulnerabilities")
	require.True(t, vulnIdx != -1, "expected ## Vulnerabilities section")
	vulnSection := out[vulnIdx:]
	assert.Contains(t, vulnSection, "| `registry.example.com/app'evil'[31m\\|pipe:v1 [linux/amd64]` |")
	assert.NotContains(t, vulnSection, "`evil`")
	assert.NotContains(t, vulnSection, "\x1b")
}

func TestMarkdownPrinter_ActionPrint_NeutralizesNewlinesInFailedControlHeading(t *testing.T) {
	session := mdSessionFixture()

	injectedControlID := "C-0099`hack`"
	ctrl := reportsummary.ControlSummary{
		ControlID:   injectedControlID,
		Name:        "Dangerous Control\n## Rogue Section",
		ScoreFactor: 9.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	failedStatus := &apis.StatusInfo{InnerStatus: apis.StatusFailed}
	ctrl.Append(failedStatus, mdResourceID1)
	session.Report.SummaryDetails.Controls[injectedControlID] = ctrl

	out := mdRunActionPrint(t, session)

	assert.NotContains(t, out, "\n## Rogue Section\n", "newline in control name must not produce a rogue heading")
	assert.Contains(t, out, "### Dangerous Control ## Rogue Section — Critical (`C-0099'hack'`)")
}

func TestMarkdownPrinter_ActionPrint_FailedControlHeadingPreservesPipeInControlID(t *testing.T) {
	session := mdSessionFixture()

	controlID := "C-0099|local"
	ctrl := reportsummary.ControlSummary{
		ControlID:   controlID,
		Name:        "Custom Control",
		ScoreFactor: 9.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	failedStatus := &apis.StatusInfo{InnerStatus: apis.StatusFailed}
	ctrl.Append(failedStatus, mdResourceID1)
	session.Report.SummaryDetails.Controls[controlID] = ctrl

	out := mdRunActionPrint(t, session)

	// Heading code span outside table must preserve pipe without literal backslash escaping
	assert.Contains(t, out, "### Custom Control — Critical (`C-0099|local`)")
	assert.NotContains(t, out, "### Custom Control — Critical (`C-0099\\|local`)")

	// Summary table cell must still escape pipe to preserve table structure
	assert.Contains(t, out, "| Critical | Custom Control | C-0099\\|local |")
}

func TestMarkdownActionPrint_NilWriterReturnsError(t *testing.T) {
	mp := NewMarkdownPrinter()
	session := mdSessionFixture()

	require.NotPanics(t, func() {
		err := mp.ActionPrint(context.Background(), session, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "output writer is nil")
	})

	require.NotPanics(t, func() {
		err := mp.ActionPrint(context.Background(), nil, []cautils.ImageScanData{{Image: "nginx:1.23"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "output writer is nil")
	})
}

func TestMdWriteSummaryTable_NilResourcesListDoesNotPanic(t *testing.T) {
	ctrl := reportsummary.ControlSummary{
		ControlID:   "C-0001",
		Name:        "Test Control",
		ScoreFactor: 5.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusPassed},
	}
	var buf strings.Builder
	require.NotPanics(t, func() {
		err := mdWriteSummaryTable(&buf, []reportsummary.ControlSummary{ctrl})
		require.NoError(t, err)
	})
	assert.Contains(t, buf.String(), "| Medium | Test Control | C-0001 | ✅ Passed | 0 | 0 |")
}

func TestMdWriteFailedSection_NilSafety(t *testing.T) {
	t.Run("nil status does not panic", func(t *testing.T) {
		ctrl := reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Test Control",
			ScoreFactor: 5.0,
		}
		var buf strings.Builder
		require.NotPanics(t, func() {
			err := mdWriteFailedSection(context.Background(), &buf, []reportsummary.ControlSummary{ctrl}, nil)
			require.NoError(t, err)
		})
		assert.Empty(t, buf.String())
	})

	t.Run("nil resources list with failed status does not panic", func(t *testing.T) {
		ctrl := reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Failed Control",
			ScoreFactor: 9.0,
			StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		}
		var buf strings.Builder
		require.NotPanics(t, func() {
			err := mdWriteFailedSection(context.Background(), &buf, []reportsummary.ControlSummary{ctrl}, nil)
			require.NoError(t, err)
		})
		assert.Contains(t, buf.String(), "Failed Controls")
		assert.Contains(t, buf.String(), "### Failed Control — Critical (`C-0001`)")
	})

	t.Run("nil session does not panic when resolving failed resources", func(t *testing.T) {
		ctrl := reportsummary.ControlSummary{
			ControlID:   "C-0001",
			Name:        "Failed Control",
			ScoreFactor: 9.0,
			StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
		}
		ctrl.Append(&apis.StatusInfo{InnerStatus: apis.StatusFailed}, "res-missing")
		var buf strings.Builder
		require.NotPanics(t, func() {
			err := mdWriteFailedSection(context.Background(), &buf, []reportsummary.ControlSummary{ctrl}, nil)
			require.NoError(t, err)
		})
		assert.Contains(t, buf.String(), "| res-missing | — | — |")
	})
}

func TestMarkdown_NilReceiverSafety(t *testing.T) {
	var mp *MarkdownPrinter

	assert.NotPanics(t, func() {
		err := mp.ActionPrint(context.Background(), nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "printer is nil")
	})

	assert.NotPanics(t, func() {
		err := mp.CloseWriter()
		assert.NoError(t, err)
	})

	assert.NotPanics(t, func() {
		err := mp.SetWriter(context.Background(), "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "printer is nil")
	})

	assert.NotPanics(t, func() {
		mp.Score(100)
		mp.PrintNextSteps()
	})
}

func TestMarkdownPrinter_ActionPrint_ClusterScopedAndNamespacedResources(t *testing.T) {
	clusterRoleID := "rbac.authorization.k8s.io/v1/ClusterRole//cluster-admin"
	deploymentID := "apps/v1/Deployment/default/nginx"

	clusterRole := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "cluster-admin"},
		"spec":       map[string]interface{}{},
	})
	deployment := localworkload.NewLocalWorkload(map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "nginx", "namespace": "default"},
		"spec":       map[string]interface{}{},
	})

	session := cautils.NewOPASessionObjMock()
	session.AllResources[clusterRoleID] = clusterRole
	session.AllResources[deploymentID] = deployment

	ctrl := &reportsummary.ControlSummary{
		ControlID:   "C-0012",
		Name:        "Cluster admin binding",
		ScoreFactor: 10.0,
		StatusInfo:  apis.StatusInfo{InnerStatus: apis.StatusFailed},
	}
	failedStatus := &apis.StatusInfo{InnerStatus: apis.StatusFailed}
	ctrl.Append(failedStatus, clusterRoleID, deploymentID)

	session.ResourcesResult[clusterRoleID] = resourcesresults.Result{
		ResourceID: clusterRoleID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: "C-0012", Name: "Cluster admin binding", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}
	session.ResourcesResult[deploymentID] = resourcesresults.Result{
		ResourceID: deploymentID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{ControlID: "C-0012", Name: "Cluster admin binding", Status: apis.StatusInfo{InnerStatus: apis.StatusFailed}},
		},
	}

	session.Report = &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			ComplianceScore: 50,
			Controls: reportsummary.ControlSummaries{
				"C-0012": *ctrl,
			},
		},
	}

	out := mdRunActionPrint(t, session)

	assert.Contains(t, out, "| Resource | Kind | Namespace |")
	assert.Contains(t, out, "| cluster-admin | ClusterRole | \\<cluster-scoped\\> |")
	assert.Contains(t, out, "| nginx | Deployment | default |")
}
